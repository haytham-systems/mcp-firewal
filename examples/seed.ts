/**
 * Seeds a demo tenant: two agents, two human approvers (with Ed25519 keys), tool classes and
 * policies. Writes credentials to examples/keys/ (git-ignored). Safe to re-run: it resets tables.
 *
 *   npm run demo:seed
 */
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import { createPool, migrate } from '../src/db/pool.js';
import { generateAgentKey } from '../src/proxy/agents.js';

const KEYS_DIR = new URL('./keys/', import.meta.url);

export interface DemoCredentials {
  agents: Record<'research' | 'ops', string>;               // agent id -> API key
  approvers: Record<'alice' | 'bob' | 'mallory', string>;    // approver id -> private key PEM path
}

export async function seed(dbUrl: string): Promise<DemoCredentials> {
  await migrate(dbUrl);
  const db = createPool(dbUrl);
  const conn = await db.getConnection();
  try {
    // Demo reset. TRUNCATE bypasses the append-only triggers — never do this in production.
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    for (const t of ['fw_approval_signatures', 'fw_approvals', 'fw_approver_groups', 'fw_approvers', 'fw_policies', 'fw_tool_classes', 'fw_agents', 'fw_audit_log']) {
      await conn.query(`TRUNCATE TABLE ${t}`);
    }
    await conn.query(`UPDATE fw_audit_head SET last_seq = 0, last_hash = UNHEX(REPEAT('00', 32)) WHERE id = 1`);
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
  } finally {
    conn.release();
  }

  // ── Agents ──────────────────────────────────────────────────────────────
  const agents = {} as DemoCredentials['agents'];
  for (const [id, name] of [['research', 'Research assistant'], ['ops', 'Ops automation agent']] as const) {
    const { key, hash } = generateAgentKey();
    await db.execute('INSERT INTO fw_agents (id, display_name, api_key_hash) VALUES (?, ?, ?)', [`agent-${id}`, name, hash]);
    agents[id] = key;
  }

  // ── Human approvers (alice: dba+finance, bob: finance, mallory: registered but in no group) ──
  await mkdir(KEYS_DIR, { recursive: true });
  const approvers = {} as DemoCredentials['approvers'];
  for (const [id, groups] of [['alice', ['dba', 'finance']], ['bob', ['finance']], ['mallory', []]] as const) {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const { kty, crv, x } = await exportJWK(publicKey);
    const jwk = { kty, crv, x };
    const pemPath = new URL(`${id}.key.pem`, KEYS_DIR);
    await writeFile(pemPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    await db.execute('INSERT INTO fw_approvers (id, display_name, kid, public_jwk) VALUES (?, ?, ?, ?)', [id, id, await calculateJwkThumbprint(jwk, 'sha256'), JSON.stringify(jwk)]);
    for (const g of groups) await db.execute('INSERT INTO fw_approver_groups (group_id, approver_id) VALUES (?, ?)', [g, id]);
    approvers[id] = pemPath.pathname;
  }

  // ── Tool classification: risk + resource derivation ──────────────────────
  const classes: [string, string, string, string | null][] = [
    ['acme-ops', 'github.get_file', 'read', 'github:repo/{owner}/{repo}'],
    ['acme-ops', 'github.create_issue', 'write', 'github:repo/{owner}/{repo}'],
    ['acme-ops', 'github.delete_repo', 'destructive', 'github:repo/{owner}/{repo}'],
    ['acme-ops', 'github.update_org_settings', 'write', 'github:org/{org}'],
    ['acme-ops', 'db.drop_table', 'destructive', 'db:{database}/table:{table}'],
    ['acme-ops', 'payments.send_money', 'destructive', 'payments:account/{to}'],
    // debug.shell intentionally unclassified → treated as destructive (fail closed)
  ];
  for (const [s, t, r, tpl] of classes) {
    await db.execute('INSERT INTO fw_tool_classes (server_pattern, tool_pattern, risk, resource_template) VALUES (?, ?, ?, ?)', [s, t, r, tpl]);
  }

  // ── Policies ───────────────────────────────────────────────────────────
  type P = [name: string, agent: string, server: string, tool: string, resource: string, risks: string | null, effect: string, n: number, group: string | null];
  const policies: P[] = [
    // research: read ONE repo; every write/destructive action unconditionally denied
    ['research reads acme/website only', 'agent-research', 'acme-ops', 'github.*', 'github:repo/acme/website', 'read', 'allow', 1, null],
    ['research: no writes, ever', 'agent-research', '*', '*', '**', 'write,destructive', 'deny', 1, null],

    // ops: read/write acme repos; org-wide changes blocked; destructive needs humans
    ['ops reads/writes acme repos', 'agent-ops', 'acme-ops', 'github.*', 'github:repo/acme/*', 'read,write', 'allow', 1, null],
    ['ops: never touch org settings', 'agent-ops', 'acme-ops', 'github.*', 'github:org/**', null, 'deny', 1, null],
    ['prod DB destruction needs a DBA', 'agent-ops', 'acme-ops', 'db.*', 'db:prod/**', 'destructive', 'require_approval', 1, 'dba'],
    ['staging DB is fine', 'agent-ops', 'acme-ops', 'db.*', 'db:staging/**', null, 'allow', 1, null],
    ['payments need two finance approvers', 'agent-ops', 'acme-ops', 'payments.*', '**', null, 'require_approval', 2, 'finance'],
  ];
  for (const p of policies) {
    await db.execute(
      `INSERT INTO fw_policies (name, agent_pattern, server_pattern, tool_pattern, resource_pattern, risk_levels, effect, required_approvals, approver_group)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, p,
    );
  }
  await db.end();

  const creds: DemoCredentials = { agents, approvers };
  await writeFile(new URL('credentials.json', KEYS_DIR), JSON.stringify(creds, null, 2), { mode: 0o600 });
  return creds;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const url = process.env['MCP_FW_DATABASE_URL'];
  if (!url) throw new Error('MCP_FW_DATABASE_URL is required');
  const creds = await seed(url);
  process.stderr.write(`seeded. agent keys + approver keys written to examples/keys/\n${JSON.stringify(creds, null, 2)}\n`);
}
