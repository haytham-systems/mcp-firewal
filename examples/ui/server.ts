import { readFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { z } from 'zod';

const root = resolve('examples/ui');
const host = process.env['MCP_FW_UI_HOST'] ?? '127.0.0.1';
const port = Number(process.env['MCP_FW_UI_PORT'] ?? 4173);
const approvalUrl = (process.env['MCP_FW_APPROVAL_URL'] ?? 'http://127.0.0.1:7801').replace(/\/+$/, '');
const firewallUrl = (process.env['MCP_FW_UI_FIREWALL_URL'] ?? 'http://127.0.0.1:7800').replace(/\/+$/, '');
const adminToken = process.env['MCP_FW_ADMIN_TOKEN'];

if (!adminToken) throw new Error('MCP_FW_ADMIN_TOKEN is required to run the local approval dashboard');
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('MCP_FW_UI_PORT must be a valid TCP port');

const DemoCallSchema = z.discriminatedUnion('tool', [
  z.object({
    agent: z.enum(['ops', 'research']),
    tool: z.literal('db.drop_table'),
    args: z.object({ database: z.enum(['prod', 'staging']), table: z.string().min(1).max(64) }).strict(),
  }).strict(),
  z.object({
    agent: z.enum(['ops', 'research']),
    tool: z.literal('github.get_file'),
    args: z.object({ owner: z.string().min(1).max(64), repo: z.string().min(1).max(64), path: z.string().min(1).max(256) }).strict(),
  }).strict(),
  z.object({
    agent: z.enum(['ops', 'research']),
    tool: z.literal('github.create_issue'),
    args: z.object({ owner: z.string().min(1).max(64), repo: z.string().min(1).max(64), title: z.string().min(1).max(256) }).strict(),
  }).strict(),
  z.object({
    agent: z.enum(['ops', 'research']),
    tool: z.literal('github.update_org_settings'),
    args: z.object({ org: z.string().min(1).max(64), setting: z.string().min(1).max(64), value: z.string().min(1).max(128) }).strict(),
  }).strict(),
  z.object({
    agent: z.enum(['ops', 'research']),
    tool: z.literal('payments.send_money'),
    args: z.object({ to: z.string().min(1).max(64), amount_cents: z.number().int().positive(), currency: z.string().length(3) }).strict(),
  }).strict(),
]);

const ApprovalIdSchema = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
const VoteSchema = z.strictObject({ signature: z.string().min(20).max(4096) });
const statusNames = new Set(['pending', 'approved', 'denied', 'expired', 'consumed', 'all']);
const staticFiles: Record<string, { file: string; type: string }> = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/styles.css': { file: 'styles.css', type: 'text/css; charset=utf-8' },
};

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk.toString();
    if (raw.length > 16_384) throw new Error('request body too large');
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new Error('request body must be valid JSON');
  }
}

async function getApi(path: string): Promise<Response> {
  return fetch(`${approvalUrl}${path}`, { headers: { authorization: `Bearer ${adminToken}` } });
}

async function health(url: string): Promise<boolean> {
  try {
    const response = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1500) });
    return response.ok;
  } catch {
    return false;
  }
}

async function demoCall(input: unknown): Promise<unknown> {
  const parsed = DemoCallSchema.safeParse(input);
  if (!parsed.success) throw new Error('Choose a supported demo tool and valid arguments');

  const credsPath = resolve('examples/keys/credentials.json');
  let credentials: unknown;
  try {
    credentials = JSON.parse(await readFile(credsPath, 'utf8')) as unknown;
  } catch {
    throw new Error('Demo credentials are missing. Run npm run demo:seed against a disposable local database first.');
  }
  const credentialsSchema = z.object({
    agents: z.object({ ops: z.string().min(1), research: z.string().min(1) }),
  });
  const validCredentials = credentialsSchema.safeParse(credentials);
  if (!validCredentials.success) throw new Error('Demo credentials are invalid; rerun npm run demo:seed on the local demo database.');

  const { agent, tool, args } = parsed.data;
  const client = new Client({ name: 'mcp-firewall-local-dashboard', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`${firewallUrl}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${validCredentials.data.agents[agent]}` } },
  });
  let connected = false;
  try {
    await client.connect(transport);
    connected = true;
    const result = await client.callTool({ name: tool, arguments: args }, undefined, { timeout: 90_000 });
    return {
      agent,
      tool,
      isError: result.isError ?? false,
      content: result.content,
      firewall: result.structuredContent,
    };
  } finally {
    if (connected) await client.close();
  }
}

const server = createServer((req, res) => {
  void (async () => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (req.method === 'GET' && url.pathname === '/api/status') {
        const [firewall, approvals] = await Promise.all([health(firewallUrl), health(approvalUrl)]);
        return json(res, 200, { firewall, approvals });
      }

      if (req.method === 'GET' && url.pathname === '/api/approvals') {
        const status = url.searchParams.get('status') ?? 'pending';
        if (!statusNames.has(status)) return json(res, 400, { error: 'invalid approval status' });
        const response = await getApi(`/v1/approvals?status=${encodeURIComponent(status)}`);
        return res.writeHead(response.status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(await response.text());
      }

      const approvalMatch = /^\/api\/approvals\/([^/]+)$/.exec(url.pathname);
      if (req.method === 'GET' && approvalMatch) {
        const id = ApprovalIdSchema.safeParse(approvalMatch[1]);
        if (!id.success) return json(res, 400, { error: 'invalid approval id' });
        const response = await getApi(`/v1/approvals/${id.data}`);
        return res.writeHead(response.status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(await response.text());
      }

      const voteMatch = /^\/api\/approvals\/([^/]+)\/decisions$/.exec(url.pathname);
      if (req.method === 'POST' && voteMatch) {
        const id = ApprovalIdSchema.safeParse(voteMatch[1]);
        const vote = VoteSchema.safeParse(await readBody(req));
        if (!id.success || !vote.success) return json(res, 400, { error: 'invalid approval id or signed vote' });
        const response = await fetch(`${approvalUrl}/v1/approvals/${id.data}/decisions`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(vote.data),
        });
        return res.writeHead(response.status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(await response.text());
      }

      if (req.method === 'POST' && url.pathname === '/api/demo/call') {
        try {
          return json(res, 200, await demoCall(await readBody(req)));
        } catch (error) {
          return json(res, 400, { error: error instanceof Error ? error.message : String(error) });
        }
      }

      if (req.method === 'GET' && staticFiles[url.pathname]) {
        const asset = staticFiles[url.pathname]!;
        res.writeHead(200, { 'content-type': asset.type, 'cache-control': 'no-cache' });
        return res.end(await readFile(resolve(root, asset.file)));
      }
      return json(res, 404, { error: 'not found' });
    } catch (error) {
      return json(res, 502, { error: error instanceof Error ? error.message : String(error) });
    }
  })();
});

server.listen(port, host, () => {
  process.stdout.write(`MCP Firewall dashboard: http://${host}:${port}\n`);
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => server.close(() => process.exit(0)));
}
