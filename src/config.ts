import { readFile } from 'node:fs/promises';
import { z } from 'zod';

const Id = z.string().regex(/^[a-z][a-z0-9._-]{0,127}$/, 'lowercase id: [a-z0-9._-]');

export const ConfigSchema = z.object({
  /** Logical id of the upstream MCP server; policies match on this. */
  serverId: Id,
  upstream: z.discriminatedUnion('type', [
    z.object({
      type: z.literal('stdio'),
      command: z.string().min(1),
      args: z.array(z.string()).default([]),
      cwd: z.string().optional(),
      /** Explicit env only; the SDK passes a minimal safe default environment otherwise. */
      env: z.record(z.string(), z.string()).optional(),
    }),
    z.object({
      type: z.literal('http'),
      url: z.url(),
      headers: z.record(z.string(), z.string()).optional(),
    }),
  ]),
  downstream: z.discriminatedUnion('type', [
    z.object({ type: z.literal('stdio') }),
    z.object({
      type: z.literal('http'),
      host: z.string().default('127.0.0.1'),
      port: z.number().int().min(1).max(65535),
      path: z.string().startsWith('/').default('/mcp'),
      /** Host-header allowlist (DNS-rebinding protection). Defaults to host:port. */
      allowedHosts: z.array(z.string()).optional(),
      maxSessions: z.number().int().positive().default(1_000),
    }),
  ]),
  approvals: z.object({
    /** Serve the approval API from this process. Set false when many stdio instances share one DB
     *  and a single `mcp-fw approvals:serve` process hosts the API (then set publicUrl). */
    serve: z.boolean().default(true),
    host: z.string().default('127.0.0.1'),
    port: z.number().int().min(0).max(65535).default(7801),
    /** Base URL humans/CLI use to reach the approval API (shown to the agent). */
    publicUrl: z.url().optional(),
    holdTimeoutMs: z.number().int().min(0).max(600_000).default(30_000),
    ttlSeconds: z.number().int().min(30).max(86_400).default(900),
    pollIntervalMs: z.number().int().min(100).max(10_000).default(500),
  }).prefault({}),
  filterToolsList: z.boolean().default(true),
  policyCacheTtlMs: z.number().int().min(0).max(300_000).default(5_000),
});
export type FirewallConfig = z.infer<typeof ConfigSchema>;

export interface FirewallSecrets {
  databaseUrl: string;
  hmacSecret: Buffer;
  auditKey: Buffer;
  adminToken: string;
}

function b64Secret(name: string, env: NodeJS.ProcessEnv): Buffer {
  const raw = env[name];
  if (!raw) throw new Error(`${name} is required (base64, >= 32 bytes; generate with: openssl rand -base64 32)`);
  const buf = Buffer.from(raw, 'base64');
  if (buf.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
  return buf;
}

/** Secrets come only from the environment (never from the config file). */
export function loadSecrets(env: NodeJS.ProcessEnv = process.env): FirewallSecrets {
  const databaseUrl = env['MCP_FW_DATABASE_URL'];
  if (!databaseUrl) throw new Error('MCP_FW_DATABASE_URL is required');
  const adminToken = env['MCP_FW_ADMIN_TOKEN'] ?? '';
  if (adminToken.length < 24) throw new Error('MCP_FW_ADMIN_TOKEN is required (>= 24 chars)');
  return { databaseUrl, hmacSecret: b64Secret('MCP_FW_HMAC_SECRET', env), auditKey: b64Secret('MCP_FW_AUDIT_KEY', env), adminToken };
}

export async function loadConfig(path: string): Promise<FirewallConfig> {
  const raw = JSON.parse(await readFile(path, 'utf8')) as unknown;
  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`invalid config ${path}:\n${parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n')}`);
  }
  return parsed.data;
}
