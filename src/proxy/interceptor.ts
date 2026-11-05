import { randomUUID } from 'node:crypto';
import type { AuditEvent, AuditLog } from '../audit/audit-log.js';
import { b64url } from '../core/canonical.js';
import { isFirewallError, type ReasonCode } from '../core/errors.js';
import {
  errorResponse, isRequest, isResponse, JSONRPC_INVALID_PARAMS, ToolCallParamsSchema, toolErrorResult,
  type JSONRPCMessage, type RpcId,
} from '../core/jsonrpc.js';
import type { Logger } from '../core/logger.js';
import type { ApprovalService } from '../hitl/approval-service.js';
import { argsDigest } from '../hitl/crypto.js';
import { evaluate, isToolVisible } from '../policy/engine.js';
import type { PolicyRepository } from '../policy/repository.js';
import type { AgentIdentity } from './agents.js';

export interface InterceptorDeps {
  readonly serverId: string;
  readonly policies: PolicyRepository;
  readonly approvals: ApprovalService;
  readonly audit: AuditLog;
  readonly log: Logger;
  /** How long a tools/call is held open waiting for a human before returning APPROVAL_PENDING. */
  readonly holdTimeoutMs: number;
  /** Public URL humans use to review approvals (included in the agent-facing message). */
  readonly approvalUrl: string;
  readonly filterToolsList: boolean;
}

/** What the session should do with a client→server message. */
export type ClientVerdict =
  | { kind: 'forward'; message: JSONRPCMessage }
  | { kind: 'respond'; message: JSONRPCMessage }
  | { kind: 'hold'; release: Promise<ClientVerdict | null> }  // null = drop silently (cancelled)
  | { kind: 'drop' };

interface InflightCall { correlationId: string; tool: string; resource: string; startedAt: number; args: Record<string, unknown> }

const key = (id: RpcId) => `${typeof id}:${String(id)}`;

/**
 * Per-session policy enforcement point. Stateless with respect to transport: it only sees
 * JSON-RPC messages and returns verdicts, so the same logic guards stdio and HTTP sessions.
 */
export class SessionInterceptor {
  private readonly inflight = new Map<string, InflightCall>();
  private readonly listRequests = new Set<string>();
  private readonly holds = new Map<string, AbortController>();

  constructor(private readonly deps: InterceptorDeps, readonly agent: AgentIdentity, readonly sessionId: string) {}

  private base(correlationId?: string): Pick<AuditEvent, 'agentId' | 'serverId' | 'correlationId'> {
    return { agentId: this.agent.id, serverId: this.deps.serverId, ...(correlationId ? { correlationId } : {}) };
  }

  // ── client → upstream ─────────────────────────────────────────────────────

  async onClientMessage(msg: JSONRPCMessage): Promise<ClientVerdict> {
    if (isRequest(msg)) {
      if (msg.method === 'tools/call') return this.onToolCall(msg.id, msg.params);
      if (msg.method === 'tools/list' && this.deps.filterToolsList) this.listRequests.add(key(msg.id));
      return { kind: 'forward', message: msg };
    }
    if ('method' in msg && msg.method === 'notifications/cancelled') {
      const requestId = (msg.params as { requestId?: RpcId } | undefined)?.requestId;
      const hold = requestId === undefined ? undefined : this.holds.get(key(requestId));
      if (hold) {
        hold.abort();
        return { kind: 'drop' }; // the upstream never saw the held request
      }
    }
    return { kind: 'forward', message: msg };
  }

  private async onToolCall(id: RpcId, rawParams: unknown): Promise<ClientVerdict> {
    const correlationId = randomUUID();
    const parsed = ToolCallParamsSchema.safeParse(rawParams);
    if (!parsed.success) {
      await this.auditSafe({ ...this.base(correlationId), type: 'request.rejected', rpcId: id, reasonCode: 'INVALID_REQUEST', metadata: { issues: parsed.error.issues.map((i) => i.message) } });
      return { kind: 'respond', message: errorResponse(id, JSONRPC_INVALID_PARAMS, 'Invalid tools/call params') };
    }
    const { name: tool, arguments: args } = parsed.data;

    // Fail closed: if we cannot write the audit trail, the call does not happen.
    try {
      await this.deps.audit.append({ ...this.base(correlationId), type: 'tool.call.intercepted', tool, rpcId: id, args, metadata: { sessionId: this.sessionId } });
    } catch (err) {
      this.deps.log.error('audit unavailable; refusing tool call', { err, correlationId });
      return { kind: 'respond', message: this.blocked(id, 'AUDIT_UNAVAILABLE', 'audit log unavailable', correlationId) };
    }

    let decision;
    try {
      const snap = await this.deps.policies.snapshot();
      decision = evaluate(snap.policies, snap.classes, { agentId: this.agent.id, serverId: this.deps.serverId, tool, args });
    } catch (err) {
      this.deps.log.error('policy evaluation failed; denying', { err, correlationId });
      return { kind: 'respond', message: this.blocked(id, 'FIREWALL_ERROR', 'policy engine unavailable', correlationId) };
    }

    const resource = 'resource' in decision ? decision.resource : undefined;
    await this.auditSafe({
      ...this.base(correlationId), type: 'policy.decision', tool, resource, rpcId: id, args, decision: decision.effect,
      reasonCode: decision.effect === 'deny' ? decision.code : undefined,
      metadata: { risk: decision.risk ?? null, matchedPolicyIds: decision.matchedPolicyIds, ...(decision.effect === 'deny' ? { reason: decision.reason } : {}) },
    });

    if (decision.effect === 'deny') {
      this.deps.log.warn('tool call denied', { agent: this.agent.id, tool, code: decision.code, resource, correlationId });
      return { kind: 'respond', message: this.blocked(id, decision.code, decision.reason, correlationId) };
    }

    if (decision.effect === 'allow') return this.forwardCall(id, tool, decision.resource, args, correlationId, rawParams);

    // ── require_approval ───────────────────────────────────────────────────
    const argsSha = argsDigest(args);
    const call = { agentId: this.agent.id, serverId: this.deps.serverId, tool, argsSha256: argsSha };
    let approvalId: string;
    try {
      const open = await this.deps.approvals.findOpen(call.agentId, call.serverId, tool, argsSha);
      if (open?.status === 'approved') {
        // Retry of an already-approved call: spend the approval and release immediately.
        await this.deps.approvals.consume(open.id, call);
        await this.auditSafe({ ...this.base(correlationId), type: 'approval.consumed', tool, resource: decision.resource, rpcId: id, metadata: { approvalId: open.id } });
        return this.forwardCall(id, tool, decision.resource, args, correlationId, rawParams);
      }
      if (open) {
        approvalId = open.id; // same call already awaiting humans: join it instead of spamming approvers
      } else {
        const created = await this.deps.approvals.create({
          ...call, resource: decision.resource, risk: decision.risk, args, policyId: decision.policyId,
          requiredApprovals: decision.requiredApprovals, approverGroup: decision.approverGroup, correlationId,
        });
        approvalId = created.id;
        await this.deps.audit.append({
          ...this.base(correlationId), type: 'approval.requested', tool, resource: decision.resource, rpcId: id, args,
          decision: 'pending', metadata: { approvalId, requiredApprovals: decision.requiredApprovals, approverGroup: decision.approverGroup, expiresAt: created.expiresAt.toISOString(), argsSha256: b64url(argsSha) },
        });
        this.deps.log.warn('HUMAN APPROVAL REQUIRED', { approvalId, agent: this.agent.id, tool, resource: decision.resource, review: `${this.deps.approvalUrl}/${approvalId}` });
      }
    } catch (err) {
      const code: ReasonCode = isFirewallError(err) ? err.code : 'FIREWALL_ERROR';
      this.deps.log.error('approval flow failed; denying', { err, correlationId });
      return { kind: 'respond', message: this.blocked(id, code, 'approval flow failed', correlationId) };
    }

    const abort = new AbortController();
    this.holds.set(key(id), abort);
    const release = (async (): Promise<ClientVerdict | null> => {
      try {
        const status = await this.deps.approvals.waitForDecision(approvalId, this.deps.holdTimeoutMs, abort.signal);
        if (abort.signal.aborted) {
          await this.auditSafe({ ...this.base(correlationId), type: 'tool.call.cancelled', tool, rpcId: id, metadata: { approvalId } });
          return null;
        }
        if (status === 'approved') {
          await this.deps.approvals.consume(approvalId, call);
          await this.deps.audit.append({ ...this.base(correlationId), type: 'approval.consumed', tool, resource: decision.resource, rpcId: id, metadata: { approvalId } });
          return this.forwardCall(id, tool, decision.resource, args, correlationId, rawParams);
        }
        if (status === 'pending') {
          return {
            kind: 'respond',
            message: toolErrorResult(id,
              `Blocked by MCP Firewall: human approval required for ${tool} on ${decision.resource}. ` +
              `Approval ${approvalId} is pending (${decision.requiredApprovals} signature(s) needed). ` +
              'Ask the user to approve it, then retry this exact call with identical arguments.',
              { code: 'APPROVAL_PENDING', approvalId, correlationId, reviewUrl: `${this.deps.approvalUrl}/${approvalId}` }),
          };
        }
        const code: ReasonCode = status === 'denied' ? 'APPROVAL_DENIED' : 'APPROVAL_EXPIRED';
        return { kind: 'respond', message: this.blocked(id, code, `approval ${status}`, correlationId, { approvalId }) };
      } catch (err) {
        const code: ReasonCode = isFirewallError(err) ? err.code : 'FIREWALL_ERROR';
        this.deps.log.error('approval release failed; denying', { err, approvalId, correlationId });
        return { kind: 'respond', message: this.blocked(id, code, 'approval could not be applied', correlationId, { approvalId }) };
      } finally {
        this.holds.delete(key(id));
      }
    })();
    return { kind: 'hold', release };
  }

  private async forwardCall(id: RpcId, tool: string, resource: string, args: Record<string, unknown>, correlationId: string, rawParams: unknown): Promise<ClientVerdict> {
    try {
      await this.deps.audit.append({ ...this.base(correlationId), type: 'tool.call.forwarded', tool, resource, rpcId: id, args, decision: 'allow', metadata: {} });
    } catch (err) {
      this.deps.log.error('audit unavailable; refusing to forward', { err, correlationId });
      return { kind: 'respond', message: this.blocked(id, 'AUDIT_UNAVAILABLE', 'audit log unavailable', correlationId) };
    }
    this.inflight.set(key(id), { correlationId, tool, resource, startedAt: Date.now(), args });
    // Forward the ORIGINAL params object: the firewall never rewrites what the agent sent.
    return { kind: 'forward', message: { jsonrpc: '2.0', id, method: 'tools/call', params: rawParams } as JSONRPCMessage };
  }

  // ── upstream → client ─────────────────────────────────────────────────────

  async onUpstreamMessage(msg: JSONRPCMessage): Promise<JSONRPCMessage> {
    if (!isResponse(msg)) return msg;
    const k = key(msg.id);

    const call = this.inflight.get(k);
    if (call) {
      this.inflight.delete(k);
      const isError = 'error' in msg || (msg as { result?: { isError?: boolean } }).result?.isError === true;
      await this.auditSafe({
        ...this.base(call.correlationId), type: 'tool.call.result', tool: call.tool, resource: call.resource, rpcId: msg.id,
        args: call.args, decision: isError ? 'error' : 'ok', metadata: { latencyMs: Date.now() - call.startedAt, protocolError: 'error' in msg },
      });
      return msg;
    }

    if (this.listRequests.delete(k) && 'result' in msg) {
      const tools = (msg.result as { tools?: { name?: unknown }[] }).tools;
      if (!Array.isArray(tools)) return msg;
      const snap = await this.deps.policies.snapshot();
      const visible = tools.filter((t) => typeof t.name === 'string' && isToolVisible(snap.policies, snap.classes, this.agent.id, this.deps.serverId, t.name));
      const hidden = tools.length - visible.length;
      if (hidden > 0) {
        await this.auditSafe({ ...this.base(), type: 'tools.list.filtered', decision: 'filtered', metadata: { total: tools.length, hidden, visible: visible.map((t) => t.name) } });
      }
      return { ...msg, result: { ...msg.result, tools: visible } } as JSONRPCMessage;
    }
    return msg;
  }

  /** Abort every held call (session closing). */
  abortAll(): void {
    for (const h of this.holds.values()) h.abort();
  }

  // ── helpers ───────────────────────────────────────────────────────────────

  private blocked(id: RpcId, code: ReasonCode, reason: string, correlationId: string, extra: Record<string, unknown> = {}): JSONRPCMessage {
    // The agent gets the code + a correlation id; full detail lives in the audit log.
    return toolErrorResult(id, `Blocked by MCP Firewall (${code}): ${reason}. Reference ${correlationId}.`, { code, correlationId, ...extra });
  }

  private async auditSafe(e: AuditEvent): Promise<void> {
    try {
      await this.deps.audit.append(e);
    } catch (err) {
      this.deps.log.error('audit append failed (non-gating event)', { err, type: e.type });
    }
  }
}

