import type { RowDataPacket } from 'mysql2/promise';
import { canonicalJson, hmacSha256, sha256 } from '../core/canonical.js';
import type { Pool } from '../db/pool.js';
import { toMysqlDatetime, withTx } from '../db/pool.js';

export type AuditEventType =
  | 'session.opened'
  | 'session.closed'
  | 'agent.auth_failed'
  | 'tool.call.intercepted'
  | 'policy.decision'
  | 'approval.requested'
  | 'approval.vote'
  | 'approval.resolved'
  | 'approval.consumed'
  | 'tool.call.forwarded'
  | 'tool.call.result'
  | 'tool.call.cancelled'
  | 'tools.list.filtered'
  | 'request.rejected';

export interface AuditEvent {
  readonly type: AuditEventType;
  readonly correlationId?: string;
  readonly agentId?: string;
  readonly serverId?: string;
  readonly tool?: string;
  readonly resource?: string;
  readonly rpcId?: string | number;
  /** Raw arguments: only an HMAC is persisted (linkable across rows, not reversible). */
  readonly args?: unknown;
  readonly decision?: string;
  readonly reasonCode?: string;
  readonly metadata?: Record<string, unknown>;
}

/** The exact structure covered by entry_hash. Shared with the verifier. */
export interface AuditRecord {
  v: 1;
  seq: number;
  occurredAt: string;
  type: string;
  correlationId: string | null;
  agentId: string | null;
  serverId: string | null;
  tool: string | null;
  resource: string | null;
  rpcId: string | null;
  argsHmac: string | null;
  decision: string | null;
  reasonCode: string | null;
  metadata: Record<string, unknown>;
}

export const chainHash = (prev: Buffer, r: AuditRecord): Buffer => sha256(Buffer.concat([prev, Buffer.from(canonicalJson(r))]));

const MAX_METADATA_BYTES = 32 * 1024;

interface HeadRow extends RowDataPacket { last_seq: number | string; last_hash: Buffer }

/**
 * Append-only, hash-chained audit log. Each append runs in a short transaction that locks the
 * singleton chain head, so sequence numbers are gap-free and any deleted/reordered/edited row
 * breaks the chain. Throughput is bounded by that lock (~thousands/s on commodity MySQL),
 * which is ample for a tool-call firewall; shard the chain per server if you need more.
 */
export class AuditLog {
  constructor(private readonly db: Pool, private readonly argsKey: Buffer) {
    if (argsKey.length < 32) throw new Error('audit HMAC key must be at least 32 bytes');
  }

  argsHmac(args: unknown): Buffer {
    return hmacSha256(this.argsKey, canonicalJson(args ?? {}));
  }

  async append(e: AuditEvent): Promise<{ seq: number; hash: Buffer }> {
    const occurredAt = new Date();
    let metadata = JSON.parse(JSON.stringify(e.metadata ?? {})) as Record<string, unknown>;
    if (Buffer.byteLength(canonicalJson(metadata)) > MAX_METADATA_BYTES) metadata = { truncated: true };
    const argsHmac = e.args === undefined ? null : this.argsHmac(e.args);

    return withTx(this.db, async (conn) => {
      const [[head]] = await conn.query<HeadRow[]>('SELECT last_seq, last_hash FROM fw_audit_head WHERE id = 1 FOR UPDATE');
      if (!head) throw new Error('fw_audit_head missing — run migrations');
      const seq = Number(head.last_seq) + 1;
      const record: AuditRecord = {
        v: 1,
        seq,
        occurredAt: occurredAt.toISOString(),
        type: e.type,
        correlationId: e.correlationId ?? null,
        agentId: e.agentId ?? null,
        serverId: e.serverId ?? null,
        tool: e.tool ?? null,
        resource: e.resource ?? null,
        rpcId: e.rpcId === undefined ? null : String(e.rpcId),
        argsHmac: argsHmac?.toString('hex') ?? null,
        decision: e.decision ?? null,
        reasonCode: e.reasonCode ?? null,
        metadata,
      };
      const hash = chainHash(head.last_hash, record);
      await conn.execute(
        `INSERT INTO fw_audit_log
           (seq, occurred_at, event_type, correlation_id, agent_id, server_id, tool, resource, rpc_id,
            args_hmac, decision, reason_code, metadata, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          seq, toMysqlDatetime(occurredAt), record.type, record.correlationId, record.agentId, record.serverId,
          record.tool, record.resource, record.rpcId, argsHmac, record.decision, record.reasonCode,
          canonicalJson(metadata), head.last_hash, hash,
        ],
      );
      await conn.execute('UPDATE fw_audit_head SET last_seq = ?, last_hash = ? WHERE id = 1', [seq, hash]);
      return { seq, hash };
    });
  }
}
