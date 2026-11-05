import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { decodeProtectedHeader, type JWK } from 'jose';
import type { ResultSetHeader, RowDataPacket } from 'mysql2/promise';
import type { AuditLog } from '../audit/audit-log.js';
import { b64url } from '../core/canonical.js';
import { FirewallError } from '../core/errors.js';
import type { Logger } from '../core/logger.js';
import { isDupKey, toMysqlDatetime, withTx, type Pool } from '../db/pool.js';
import type { Risk } from '../policy/types.js';
import { challengeHash, verifyDecision, type ChallengeSigner } from './crypto.js';

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'consumed';

export interface ApprovalRequest {
  agentId: string;
  serverId: string;
  tool: string;
  resource: string;
  risk: Risk;
  args: Record<string, unknown>;
  argsSha256: Buffer;
  policyId: number;
  requiredApprovals: number;
  approverGroup: string | null;
  correlationId: string;
}

export interface ApprovalView {
  id: string;
  status: ApprovalStatus;
  agentId: string;
  serverId: string;
  tool: string;
  resource: string;
  risk: Risk;
  arguments: unknown;
  argsSha256: string;
  challenge: string;
  requiredApprovals: number;
  approverGroup: string | null;
  approvals: { approverId: string; decision: 'approve' | 'deny'; signedAt: string }[];
  createdAt: string;
  expiresAt: string;
}

interface ApprovalRow extends RowDataPacket {
  id: string; status: ApprovalStatus; agent_id: string; server_id: string; tool: string; resource: string; risk: Risk;
  args_sha256: Buffer; arguments: unknown; challenge: string; policy_id: number; required_approvals: number;
  approver_group: string | null; correlation_id: string; created_at: Date; expires_at: Date;
}

export interface ApprovalConfig { ttlSeconds: number; pollIntervalMs: number }

/**
 * Approval state machine (all transitions are conditional UPDATEs, so concurrent firewall
 * instances and approvers cannot race each other into an inconsistent state):
 *
 *   pending ──(N approve votes)──▶ approved ──(exact call re-presented)──▶ consumed
 *      │  └────(any deny vote)───▶ denied
 *      └──────(expires_at passes)─▶ expired
 */
export class ApprovalService {
  constructor(
    private readonly db: Pool,
    private readonly signer: ChallengeSigner,
    private readonly audit: AuditLog,
    private readonly log: Logger,
    private readonly cfg: ApprovalConfig,
  ) {}

  /** An open (pending or approved, unexpired) approval for this exact call, if any. */
  async findOpen(agentId: string, serverId: string, tool: string, argsSha256: Buffer): Promise<{ id: string; status: 'pending' | 'approved' } | null> {
    const [rows] = await this.db.execute<RowDataPacket[]>(
      `SELECT id, status FROM fw_approvals
        WHERE agent_id = ? AND server_id = ? AND tool = ? AND args_sha256 = ?
          AND status IN ('pending','approved') AND expires_at > UTC_TIMESTAMP(3)
        ORDER BY FIELD(status, 'approved', 'pending'), created_at DESC LIMIT 1`,
      [agentId, serverId, tool, argsSha256],
    );
    const r = rows[0];
    return r ? { id: String(r['id']), status: r['status'] as 'pending' | 'approved' } : null;
  }

  async create(req: ApprovalRequest): Promise<{ id: string; expiresAt: Date }> {
    const id = randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.cfg.ttlSeconds * 1000);
    const challenge = await this.signer.mint({
      approvalId: id, agent: req.agentId, server: req.serverId, tool: req.tool, resource: req.resource,
      risk: req.risk, argsSha256: req.argsSha256, ttlSeconds: this.cfg.ttlSeconds,
    });
    await this.db.execute(
      `INSERT INTO fw_approvals
         (id, status, agent_id, server_id, tool, resource, risk, args_sha256, arguments, challenge, policy_id,
          required_approvals, approver_group, correlation_id, created_at, expires_at)
       VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id, req.agentId, req.serverId, req.tool, req.resource, req.risk, req.argsSha256, JSON.stringify(req.args), challenge,
        req.policyId, req.requiredApprovals, req.approverGroup, req.correlationId, toMysqlDatetime(now), toMysqlDatetime(expiresAt),
      ],
    );
    return { id, expiresAt };
  }

  /** Polls until the approval leaves 'pending', the timeout elapses, or `signal` aborts. */
  async waitForDecision(id: string, timeoutMs: number, signal: AbortSignal): Promise<ApprovalStatus> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      await this.expireStale();
      const [rows] = await this.db.execute<RowDataPacket[]>('SELECT status FROM fw_approvals WHERE id = ?', [id]);
      const status = rows[0]?.['status'] as ApprovalStatus | undefined;
      if (!status) throw new FirewallError('APPROVAL_EXPIRED', 'approval vanished', 410);
      if (status !== 'pending' || Date.now() >= deadline) return status;
      try {
        await sleep(Math.min(this.cfg.pollIntervalMs, Math.max(0, deadline - Date.now())), undefined, { signal });
      } catch {
        return 'pending'; // aborted (client cancelled or session closed)
      }
    }
  }

  /**
   * Atomically spends an approved approval for the exact call being released. Re-verifies the
   * HMAC challenge so a tampered DB row cannot redirect an approval to different arguments.
   */
  async consume(id: string, call: { agentId: string; serverId: string; tool: string; argsSha256: Buffer }): Promise<void> {
    const [rows] = await this.db.execute<ApprovalRow[]>('SELECT * FROM fw_approvals WHERE id = ?', [id]);
    const row = rows[0];
    if (!row) throw new FirewallError('APPROVAL_EXPIRED', 'approval not found', 404);
    const claims = await this.signer.verify(row.challenge).catch(() => null);
    const bound =
      claims !== null && claims.sub === id && claims.agent === call.agentId && claims.server === call.serverId &&
      claims.tool === call.tool && claims.args_sha256 === b64url(call.argsSha256) && row.args_sha256.equals(call.argsSha256);
    if (!bound) throw new FirewallError('APPROVAL_BINDING_MISMATCH', 'approval is not bound to this exact call');

    const [res] = await this.db.execute<ResultSetHeader>(
      `UPDATE fw_approvals SET status = 'consumed', consumed_at = UTC_TIMESTAMP(3)
        WHERE id = ? AND status = 'approved' AND expires_at > UTC_TIMESTAMP(3)`,
      [id],
    );
    if (res.affectedRows !== 1) throw new FirewallError('APPROVAL_EXPIRED', 'approval is not in an approvable state (expired or already used)', 410);
  }

  /**
   * Records one approver's signed vote. The JWS itself is the credential: it must be signed by an
   * active approver's registered key, reference this approval id and the SHA-256 of its exact
   * challenge, and be fresh. One vote per approver (PK); any deny vote ends the approval.
   */
  async submitDecision(id: string, jws: string): Promise<{ status: ApprovalStatus; approverId: string }> {
    let kid: unknown;
    try { kid = decodeProtectedHeader(jws).kid; } catch { kid = undefined; }
    if (typeof kid !== 'string' || kid.length > 64) throw new FirewallError('INVALID_REQUEST', 'decision must carry a kid', 400);

    const [approvers] = await this.db.execute<RowDataPacket[]>(
      `SELECT id, public_jwk FROM fw_approvers WHERE kid = ? AND status = 'active'`, [kid],
    );
    const approver = approvers[0];
    if (!approver) throw new FirewallError('AGENT_UNAUTHENTICATED', 'unknown or disabled approver key', 401);
    const approverId = String(approver['id']);

    let claims;
    try {
      claims = await verifyDecision(jws, approver['public_jwk'] as JWK);
    } catch (err) {
      throw new FirewallError('AGENT_UNAUTHENTICATED', 'decision signature invalid or stale', 401, { cause: err });
    }
    if (claims.aid !== id) throw new FirewallError('APPROVAL_BINDING_MISMATCH', 'decision is for a different approval', 409);

    await this.expireStale();
    const outcome = await withTx(this.db, async (conn) => {
      const [rows] = await conn.execute<ApprovalRow[]>('SELECT * FROM fw_approvals WHERE id = ? FOR UPDATE', [id]);
      const row = rows[0];
      if (!row) throw new FirewallError('INVALID_REQUEST', 'approval not found', 404);
      if (row.status !== 'pending') throw new FirewallError('APPROVAL_EXPIRED', `approval is ${row.status}`, 410);
      if (claims.chal !== challengeHash(row.challenge)) {
        throw new FirewallError('APPROVAL_BINDING_MISMATCH', 'signature does not cover this challenge', 409);
      }
      await this.signer.verify(row.challenge).catch((err: unknown) => {
        throw new FirewallError('APPROVAL_BINDING_MISMATCH', 'stored challenge failed integrity check', 409, { cause: err });
      });

      if (row.approver_group) {
        const [m] = await conn.execute<RowDataPacket[]>(
          'SELECT 1 FROM fw_approver_groups WHERE group_id = ? AND approver_id = ?', [row.approver_group, approverId],
        );
        if (m.length === 0) throw new FirewallError('POLICY_DENY', `approver is not in group '${row.approver_group}'`, 403);
      }

      try {
        await conn.execute(
          `INSERT INTO fw_approval_signatures (approval_id, approver_id, decision, signature, signed_at)
           VALUES (?, ?, ?, ?, UTC_TIMESTAMP(3))`,
          [id, approverId, claims.decision, jws],
        );
      } catch (err) {
        if (isDupKey(err)) throw new FirewallError('INVALID_REQUEST', 'approver has already voted on this approval', 409);
        throw err;
      }

      let status: ApprovalStatus = 'pending';
      if (claims.decision === 'deny') status = 'denied';
      else {
        const [[c]] = await conn.execute<RowDataPacket[]>(
          `SELECT COUNT(*) AS n FROM fw_approval_signatures WHERE approval_id = ? AND decision = 'approve'`, [id],
        );
        if (Number(c?.['n']) >= row.required_approvals) status = 'approved';
      }
      if (status !== 'pending') {
        await conn.execute(`UPDATE fw_approvals SET status = ?, decided_at = UTC_TIMESTAMP(3) WHERE id = ?`, [status, id]);
      }
      return { status, row };
    });

    const base = {
      correlationId: outcome.row.correlation_id, agentId: outcome.row.agent_id, serverId: outcome.row.server_id,
      tool: outcome.row.tool, resource: outcome.row.resource,
    };
    await this.audit.append({ ...base, type: 'approval.vote', decision: claims.decision, metadata: { approvalId: id, approverId, kid } });
    if (outcome.status !== 'pending') {
      await this.audit.append({ ...base, type: 'approval.resolved', decision: outcome.status, metadata: { approvalId: id } });
    }
    this.log.info('approval vote recorded', { approvalId: id, approverId, decision: claims.decision, status: outcome.status });
    return { status: outcome.status, approverId };
  }

  async get(id: string): Promise<ApprovalView | null> {
    await this.expireStale();
    const [rows] = await this.db.execute<ApprovalRow[]>('SELECT * FROM fw_approvals WHERE id = ?', [id]);
    const row = rows[0];
    return row ? this.view(row) : null;
  }

  async list(status: ApprovalStatus | 'all' = 'pending', limit = 50): Promise<ApprovalView[]> {
    await this.expireStale();
    const [rows] = status === 'all'
      ? await this.db.query<ApprovalRow[]>('SELECT * FROM fw_approvals ORDER BY created_at DESC LIMIT ?', [limit])
      : await this.db.query<ApprovalRow[]>('SELECT * FROM fw_approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?', [status, limit]);
    return Promise.all(rows.map((r) => this.view(r)));
  }

  /** pending → expired. Cheap (indexed) and idempotent; called opportunistically. */
  async expireStale(): Promise<void> {
    await this.db.execute(
      `UPDATE fw_approvals SET status = 'expired', decided_at = UTC_TIMESTAMP(3)
        WHERE status IN ('pending','approved') AND expires_at <= UTC_TIMESTAMP(3)`,
    );
  }

  private async view(row: ApprovalRow): Promise<ApprovalView> {
    const [sigs] = await this.db.execute<RowDataPacket[]>(
      'SELECT approver_id, decision, signed_at FROM fw_approval_signatures WHERE approval_id = ? ORDER BY signed_at', [row.id],
    );
    return {
      id: row.id, status: row.status, agentId: row.agent_id, serverId: row.server_id, tool: row.tool, resource: row.resource,
      risk: row.risk, arguments: row.arguments, argsSha256: b64url(row.args_sha256), challenge: row.challenge,
      requiredApprovals: row.required_approvals, approverGroup: row.approver_group,
      approvals: sigs.map((s) => ({ approverId: String(s['approver_id']), decision: s['decision'] as 'approve' | 'deny', signedAt: (s['signed_at'] as Date).toISOString() })),
      createdAt: row.created_at.toISOString(), expiresAt: row.expires_at.toISOString(),
    };
  }
}
