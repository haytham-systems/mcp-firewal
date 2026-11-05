import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { AuditLog } from './audit/audit-log.js';
import type { FirewallConfig, FirewallSecrets } from './config.js';
import { isFirewallError } from './core/errors.js';
import { createLogger, type Logger } from './core/logger.js';
import { createPool, type Pool } from './db/pool.js';
import { createApprovalApi } from './hitl/approval-api.js';
import { ApprovalService } from './hitl/approval-service.js';
import { ChallengeSigner } from './hitl/crypto.js';
import { PolicyRepository } from './policy/repository.js';
import { AgentDirectory, type AgentIdentity } from './proxy/agents.js';
import { SessionInterceptor, type InterceptorDeps } from './proxy/interceptor.js';
import { FirewallSession } from './proxy/session.js';
import { bearer, HttpError, readJsonBody, sendJson } from './transports/http-util.js';

/**
 * Composition root. One Firewall instance guards one upstream MCP server (`config.serverId`).
 * Run one instance per upstream server; they can share the MySQL database.
 */
export class Firewall {
  readonly db: Pool;
  readonly audit: AuditLog;
  readonly approvals: ApprovalService;
  readonly policies: PolicyRepository;
  readonly agents: AgentDirectory;
  private approvalServer: Server | null = null;
  private httpServer: Server | null = null;
  private readonly sessions = new Map<string, { session: FirewallSession; agent: AgentIdentity; transport: StreamableHTTPServerTransport }>();
  private approvalBaseUrl = '';

  constructor(readonly config: FirewallConfig, secrets: FirewallSecrets, readonly log: Logger = createLogger()) {
    this.db = createPool(secrets.databaseUrl);
    this.audit = new AuditLog(this.db, secrets.auditKey);
    this.policies = new PolicyRepository(this.db, log, config.policyCacheTtlMs);
    this.agents = new AgentDirectory(this.db);
    this.approvals = new ApprovalService(this.db, new ChallengeSigner(secrets.hmacSecret), this.audit, log, {
      ttlSeconds: config.approvals.ttlSeconds,
      pollIntervalMs: config.approvals.pollIntervalMs,
    });
    this.adminToken = secrets.adminToken;
  }

  private readonly adminToken: string;

  /** Starts the approval API. Returns its base URL. */
  async startApprovalApi(): Promise<string> {
    const { host, port, publicUrl, serve } = this.config.approvals;
    if (!serve) {
      this.approvalBaseUrl = publicUrl ?? `http://${host}:${port}`;
      return this.approvalBaseUrl;
    }
    this.approvalServer = createApprovalApi(this.approvals, this.adminToken, this.log);
    await new Promise<void>((resolve, reject) => {
      this.approvalServer!.once('error', reject).listen(port, host, () => resolve());
    });
    const actual = (this.approvalServer.address() as AddressInfo).port;
    this.approvalBaseUrl = publicUrl ?? `http://${host}:${actual}`;
    this.log.info('approval API listening', { url: this.approvalBaseUrl });
    return this.approvalBaseUrl;
  }

  private interceptorDeps(): InterceptorDeps {
    return {
      serverId: this.config.serverId,
      policies: this.policies,
      approvals: this.approvals,
      audit: this.audit,
      log: this.log,
      holdTimeoutMs: this.config.approvals.holdTimeoutMs,
      approvalUrl: `${this.approvalBaseUrl}/v1/approvals`,
      filterToolsList: this.config.filterToolsList,
    };
  }

  private createUpstream(): Transport {
    const up = this.config.upstream;
    if (up.type === 'stdio') {
      return new StdioClientTransport({
        command: up.command, args: up.args, stderr: 'inherit',
        ...(up.cwd ? { cwd: up.cwd } : {}), ...(up.env ? { env: up.env } : {}),
      });
    }
    return new StreamableHTTPClientTransport(new URL(up.url), { requestInit: { headers: up.headers ?? {} } });
  }

  /**
   * stdio downstream: the agent launches the firewall as its "MCP server" command and passes its
   * credential in MCP_FW_AGENT_KEY. Resolves when the agent disconnects.
   */
  async runStdio(agentKey: string | undefined): Promise<void> {
    let agent: AgentIdentity;
    try {
      agent = await this.agents.authenticate(agentKey);
    } catch (err) {
      await this.audit.append({ type: 'agent.auth_failed', decision: 'deny', reasonCode: isFirewallError(err) ? err.code : 'FIREWALL_ERROR', metadata: { transport: 'stdio' } }).catch(() => undefined);
      throw err;
    }
    const sessionId = randomUUID();
    const downstream = new StdioServerTransport();
    const session = new FirewallSession(downstream, this.createUpstream(), new SessionInterceptor(this.interceptorDeps(), agent, sessionId), this.audit, this.log);
    const stdinClosed = new Promise<void>((resolve) => {
      process.stdin.once('end', resolve);
      process.stdin.once('close', resolve);
    });
    await session.start();
    this.log.info('stdio session started', { agent: agent.id, sessionId, server: this.config.serverId });
    await Promise.race([stdinClosed, session.done]);
    await session.close('stdin closed');
  }

  /**
   * Streamable HTTP downstream with per-agent bearer auth. A session is bound to the agent that
   * initialized it; every later request on that session must present the same agent's key.
   */
  async startHttp(): Promise<string> {
    const ds = this.config.downstream;
    if (ds.type !== 'http') throw new Error('downstream is not http');

    this.httpServer = createServer((req, res) => {
      void (async () => {
        try {
          const url = new URL(req.url ?? '/', 'http://local');
          if (url.pathname === '/healthz' && req.method === 'GET') return sendJson(res, 200, { ok: true });
          if (url.pathname !== ds.path) throw new HttpError(404, 'not found');

          const agent = await this.authenticateHttp(req);
          const sessionId = req.headers['mcp-session-id'];
          const body = req.method === 'POST' ? await readJsonBody(req) : undefined;

          if (typeof sessionId === 'string') {
            const s = this.sessions.get(sessionId);
            if (!s) throw new HttpError(404, 'unknown session');
            if (s.agent.id !== agent.id) {
              await this.audit.append({ type: 'agent.auth_failed', agentId: agent.id, decision: 'deny', reasonCode: 'AGENT_UNAUTHENTICATED', metadata: { reason: 'session belongs to another agent' } }).catch(() => undefined);
              throw new HttpError(403, 'session belongs to a different agent');
            }
            await s.transport.handleRequest(req, res, body);
            return;
          }

          if (req.method !== 'POST' || !isInitialize(body)) throw new HttpError(400, 'expected initialize request without mcp-session-id');
          if (this.sessions.size >= ds.maxSessions) throw new HttpError(503, 'session limit reached');

          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            enableDnsRebindingProtection: true,
            allowedHosts: ds.allowedHosts ?? [`${ds.host}:${(this.httpServer!.address() as AddressInfo).port}`, `localhost:${(this.httpServer!.address() as AddressInfo).port}`],
            onsessioninitialized: (id) => {
              this.sessions.set(id, { session, agent, transport });
              this.log.info('http session started', { agent: agent.id, sessionId: id });
            },
            onsessionclosed: (id) => {
              const s = this.sessions.get(id);
              this.sessions.delete(id);
              void s?.session.close('client terminated session');
            },
          });
          const session = new FirewallSession(transport, this.createUpstream(), new SessionInterceptor(this.interceptorDeps(), agent, randomUUID()), this.audit, this.log);
          await session.start();
          await transport.handleRequest(req, res, body);
        } catch (err) {
          if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
          if (isFirewallError(err)) return sendJson(res, err.httpStatus, { error: err.code, message: err.message });
          this.log.error('http downstream error', { err });
          return sendJson(res, 500, { error: 'internal error' });
        }
      })();
    });

    await new Promise<void>((resolve, reject) => this.httpServer!.once('error', reject).listen(ds.port, ds.host, () => resolve()));
    const port = (this.httpServer.address() as AddressInfo).port;
    const url = `http://${ds.host}:${port}${ds.path}`;
    this.log.info('MCP firewall (http) listening', { url, upstream: this.config.upstream.type, server: this.config.serverId });
    return url;
  }

  private async authenticateHttp(req: IncomingMessage): Promise<AgentIdentity> {
    try {
      return await this.agents.authenticate(bearer(req));
    } catch (err) {
      await this.audit.append({ type: 'agent.auth_failed', decision: 'deny', reasonCode: isFirewallError(err) ? err.code : 'FIREWALL_ERROR', metadata: { transport: 'http', ip: req.socket.remoteAddress ?? null } }).catch(() => undefined);
      throw err;
    }
  }

  async close(): Promise<void> {
    await Promise.allSettled([...this.sessions.values()].map((s) => s.session.close('firewall shutdown')));
    this.sessions.clear();
    await Promise.allSettled([
      new Promise<void>((r) => (this.httpServer ? this.httpServer.close(() => r()) : r())),
      new Promise<void>((r) => (this.approvalServer ? this.approvalServer.close(() => r()) : r())),
    ]);
    this.httpServer?.closeAllConnections();
    this.approvalServer?.closeAllConnections();
    await this.db.end();
  }
}

function isInitialize(body: unknown): boolean {
  const first = Array.isArray(body) ? body[0] : body;
  return typeof first === 'object' && first !== null && (first as { method?: unknown }).method === 'initialize';
}
