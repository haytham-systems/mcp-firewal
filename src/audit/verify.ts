import type { RowDataPacket } from 'mysql2/promise';
import type { Pool } from '../db/pool.js';
import { chainHash, type AuditRecord } from './audit-log.js';

export interface ChainReport {
  ok: boolean;
  rowsChecked: number;
  firstBadSeq: number | null;
  problem: string | null;
}

interface Row extends RowDataPacket {
  seq: number | string; occurred_at: Date; event_type: string; correlation_id: string | null; agent_id: string | null;
  server_id: string | null; tool: string | null; resource: string | null; rpc_id: string | null; args_hmac: Buffer | null;
  decision: string | null; reason_code: string | null; metadata: Record<string, unknown>; prev_hash: Buffer; entry_hash: Buffer;
}

/**
 * Walks the chain from genesis. Detects edited rows (hash mismatch), deleted/inserted rows
 * (seq gap or prev_hash mismatch) and truncation of the tail (head pointer mismatch).
 * Anchor `fw_audit_head.last_hash` externally (e.g. hourly to WORM storage) so that a DBA who
 * rewrites the whole chain is also detectable.
 */
export async function verifyAuditChain(db: Pool, batch = 5_000): Promise<ChainReport> {
  let prev: Buffer = Buffer.alloc(32);
  let expectedSeq = 1;
  let checked = 0;
  for (;;) {
    const [rows] = await db.query<Row[]>('SELECT * FROM fw_audit_log WHERE seq >= ? ORDER BY seq LIMIT ?', [expectedSeq, batch]);
    if (rows.length === 0) break;
    for (const r of rows) {
      const seq = Number(r.seq);
      const fail = (problem: string): ChainReport => ({ ok: false, rowsChecked: checked, firstBadSeq: seq, problem });
      if (seq !== expectedSeq) return fail(`sequence gap: expected ${expectedSeq}`);
      if (!r.prev_hash.equals(prev)) return fail('prev_hash does not link to previous row');
      const record: AuditRecord = {
        v: 1, seq, occurredAt: r.occurred_at.toISOString(), type: r.event_type, correlationId: r.correlation_id,
        agentId: r.agent_id, serverId: r.server_id, tool: r.tool, resource: r.resource, rpcId: r.rpc_id,
        argsHmac: r.args_hmac?.toString('hex') ?? null, decision: r.decision, reasonCode: r.reason_code, metadata: r.metadata,
      };
      if (!chainHash(prev, record).equals(r.entry_hash)) return fail('row content does not match its hash (edited)');
      prev = r.entry_hash;
      expectedSeq++;
      checked++;
    }
  }
  const [[head]] = await db.query<RowDataPacket[]>('SELECT last_seq, last_hash FROM fw_audit_head WHERE id = 1');
  if (!head || Number(head['last_seq']) !== checked || !(head['last_hash'] as Buffer).equals(prev)) {
    return { ok: false, rowsChecked: checked, firstBadSeq: checked + 1, problem: 'chain head does not match last row (tail truncated?)' };
  }
  return { ok: true, rowsChecked: checked, firstBadSeq: null, problem: null };
}
