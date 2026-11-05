/**
 * A stand-in for a real upstream MCP server ("acme-ops"): GitHub, database and payments tools.
 * It has NO security of its own — that is the firewall's job. Every call it actually executes is
 * printed to stderr with a ⚡ so you can see exactly what got through.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const server = new McpServer({ name: 'acme-ops', version: '1.0.0' });
const executed = (tool: string, args: unknown) => process.stderr.write(`⚡ upstream EXECUTED ${tool} ${JSON.stringify(args)}\n`);
const ok = (data: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data) }] });

server.registerTool('github.get_file', {
  description: 'Read a file from a GitHub repository',
  inputSchema: { owner: z.string(), repo: z.string(), path: z.string() },
}, async (a) => { executed('github.get_file', a); return ok({ path: a.path, content: `# ${a.repo}\nhello from ${a.owner}/${a.repo}` }); });

server.registerTool('github.create_issue', {
  description: 'Open an issue',
  inputSchema: { owner: z.string(), repo: z.string(), title: z.string() },
}, async (a) => { executed('github.create_issue', a); return ok({ issue: 42, title: a.title }); });

server.registerTool('github.delete_repo', {
  description: 'Permanently delete a repository',
  inputSchema: { owner: z.string(), repo: z.string() },
}, async (a) => { executed('github.delete_repo', a); return ok({ deleted: `${a.owner}/${a.repo}` }); });

server.registerTool('github.update_org_settings', {
  description: 'Change organization-wide settings',
  inputSchema: { org: z.string(), setting: z.string(), value: z.string() },
}, async (a) => { executed('github.update_org_settings', a); return ok({ updated: a.setting }); });

server.registerTool('db.drop_table', {
  description: 'DROP a database table',
  inputSchema: { database: z.string(), table: z.string() },
}, async (a) => { executed('db.drop_table', a); return ok({ dropped: `${a.database}.${a.table}` }); });

server.registerTool('payments.send_money', {
  description: 'Send a payment',
  inputSchema: { to: z.string(), amount_cents: z.number().int().positive(), currency: z.string().length(3) },
}, async (a) => { executed('payments.send_money', a); return ok({ sent: a.amount_cents, to: a.to, currency: a.currency }); });

server.registerTool('debug.shell', {
  description: 'Run a shell command (newly added upstream; nobody classified it yet)',
  inputSchema: { cmd: z.string() },
}, async (a) => { executed('debug.shell', a); return ok({ ran: a.cmd }); });

await server.connect(new StdioServerTransport());
