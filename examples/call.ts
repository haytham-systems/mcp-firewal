/**
 * Make ONE tool call through a running HTTP firewall as a seeded agent.
 *
 *   npm run demo:call -- <tool> '<json args>' [ops|research]
 *   npm run demo:call -- db.drop_table '{"database":"prod","table":"users"}'
 */
import { readFile } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { DemoCredentials } from './seed.js';

const [tool, rawArgs = '{}', who = 'ops'] = process.argv.slice(2);
if (!tool) throw new Error("usage: call.ts <tool> '<json args>' [ops|research]");
const creds = JSON.parse(await readFile(new URL('./keys/credentials.json', import.meta.url), 'utf8')) as DemoCredentials;
const key = creds.agents[who as keyof DemoCredentials['agents']];
if (!key) throw new Error(`unknown agent '${who}'`);

const client = new Client({ name: `cli-${who}`, version: '1.0.0' });
await client.connect(new StreamableHTTPClientTransport(new URL(process.env['MCP_FW_URL'] ?? 'http://127.0.0.1:7800/mcp'), {
  requestInit: { headers: { authorization: `Bearer ${key}` } },
}));
const result = await client.callTool({ name: tool, arguments: JSON.parse(rawArgs) as Record<string, unknown> }, undefined, { timeout: 600_000 });
console.log(JSON.stringify({ isError: result.isError ?? false, content: result.content, firewall: (result.structuredContent as { firewall?: unknown } | undefined)?.firewall }, null, 2));
await client.close();
