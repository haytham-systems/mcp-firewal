import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { AuditLog } from '../audit/audit-log.js';
import { errorResponse, isRequest, isResponse, JSONRPC_INTERNAL_ERROR, type JSONRPCMessage, type RpcId } from '../core/jsonrpc.js';
import type { Logger } from '../core/logger.js';
import type { ClientVerdict, SessionInterceptor } from './interceptor.js';

/**
 * Bridges a downstream (agent-facing, server-side) transport and an upstream (MCP-server-facing,
 * client-side) transport through a SessionInterceptor. Works with ANY pair of MCP SDK transports:
 * stdio↔stdio, HTTP↔stdio, HTTP↔HTTP.
 *
 * Ordering: messages in each direction are processed through a serial queue, so the upstream sees
 * client messages in the order sent (e.g. `initialize` before `notifications/initialized`).
 * Calls held for human approval leave the queue immediately and are released asynchronously,
 * so one pending approval never blocks the rest of the session.
 */
export class FirewallSession {
  private clientQueue: Promise<void> = Promise.resolve();
  private upstreamQueue: Promise<void> = Promise.resolve();
  private initializeId: RpcId | null = null;
  private closed = false;
  private markDone!: () => void;
  /** Resolves once the session has fully closed (either side). */
  readonly done = new Promise<void>((resolve) => { this.markDone = resolve; });

  constructor(
    private readonly downstream: Transport,
    private readonly upstream: Transport,
    private readonly interceptor: SessionInterceptor,
    private readonly audit: AuditLog,
    private readonly log: Logger,
  ) {}

  async start(): Promise<void> {
    this.upstream.onmessage = (m) => { this.upstreamQueue = this.upstreamQueue.then(() => this.fromUpstream(m)); };
    this.downstream.onmessage = (m) => { this.clientQueue = this.clientQueue.then(() => this.fromClient(m)); };
    this.upstream.onclose = () => void this.close('upstream closed');
    this.downstream.onclose = () => void this.close('downstream closed');
    this.upstream.onerror = (err) => this.log.error('upstream transport error', { err, session: this.interceptor.sessionId });
    this.downstream.onerror = (err) => this.log.error('downstream transport error', { err, session: this.interceptor.sessionId });

    await this.upstream.start();
    await this.downstream.start();
    await this.audit.append({
      type: 'session.opened', agentId: this.interceptor.agent.id, decision: 'open',
      metadata: { sessionId: this.interceptor.sessionId },
    }).catch((err: unknown) => this.log.error('audit append failed', { err }));
  }

  private async fromClient(msg: JSONRPCMessage): Promise<void> {
    if (isRequest(msg) && msg.method === 'initialize') this.initializeId = msg.id;
    let verdict: ClientVerdict;
    try {
      verdict = await this.interceptor.onClientMessage(msg);
    } catch (err) {
      this.log.error('interceptor failed; failing closed', { err });
      if (isRequest(msg)) await this.sendDown(errorResponse(msg.id, JSONRPC_INTERNAL_ERROR, 'MCP Firewall internal error'));
      return;
    }
    await this.apply(verdict);
  }

  private async apply(v: ClientVerdict): Promise<void> {
    switch (v.kind) {
      case 'forward':
        await this.sendUp(v.message);
        return;
      case 'respond':
        await this.sendDown(v.message);
        return;
      case 'drop':
        return;
      case 'hold':
        // Do NOT await inside the queue: other traffic keeps flowing while humans decide.
        void v.release.then((next) => (next ? this.apply(next) : undefined)).catch((err: unknown) => this.log.error('held call release failed', { err }));
        return;
    }
  }

  private async fromUpstream(msg: JSONRPCMessage): Promise<void> {
    let out = msg;
    try {
      out = await this.interceptor.onUpstreamMessage(msg);
    } catch (err) {
      this.log.error('upstream interception failed; passing through unmodified', { err });
    }
    // Raw proxying bypasses the SDK Client, so propagate the negotiated version ourselves
    // (required by the Streamable HTTP client transport for subsequent requests).
    if (this.initializeId !== null && isResponse(out) && out.id === this.initializeId && 'result' in out) {
      const version = (out.result as { protocolVersion?: unknown }).protocolVersion;
      if (typeof version === 'string') this.upstream.setProtocolVersion?.(version);
      this.initializeId = null;
    }
    await this.sendDown(out);
  }

  private async sendUp(m: JSONRPCMessage): Promise<void> {
    if (this.closed) return;
    await this.upstream.send(m).catch((err: unknown) => this.log.error('send upstream failed', { err }));
  }

  private async sendDown(m: JSONRPCMessage): Promise<void> {
    if (this.closed) return;
    const relatedRequestId = isResponse(m) ? m.id : undefined;
    await this.downstream.send(m, relatedRequestId === undefined ? undefined : { relatedRequestId })
      .catch((err: unknown) => this.log.error('send downstream failed', { err }));
  }

  async close(reason: string): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.interceptor.abortAll();
    await Promise.allSettled([this.upstream.close(), this.downstream.close()]);
    await this.audit.append({
      type: 'session.closed', agentId: this.interceptor.agent.id, decision: 'closed',
      metadata: { sessionId: this.interceptor.sessionId, reason },
    }).catch(() => undefined);
    this.log.info('session closed', { session: this.interceptor.sessionId, reason });
    this.markDone();
  }
}
