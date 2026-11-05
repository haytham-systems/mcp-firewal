/**
 * End-to-end demo + acceptance test. Real MCP clients talk to the firewall over BOTH transports:
 *
 *   research agent ──stdio──▶ [firewall child process] ──stdio──▶ upstream-server.ts
 *   ops agent      ──HTTP───▶ [firewall in-process]    ──stdio──▶ upstream-server.ts
 *   humans (alice, bob, mallory) ──signed votes──▶ approval API (:7801)
 *
 *   npm run db:up   (once)     then     npm run demo
 */
import { createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import mysql from 'mysql2/promise';
import { verifyAuditChain } from '../src/audit/verify.js';
import { loadConfig, loadSecrets } from '../src/config.js';
import { createLogger } from '../src/core/logger.js';
import { Firewall } from '../src/firewall.js';
import type { ApprovalView } from '../src/hitl/approval-service.js';
import { argsDigest, signDecision } from '../src/hitl/crypto.js';
import { seed } from './seed.js';

const env = process.env as Record<string, string>;
const API = env['MCP_FW_APPROVAL_URL'] ?? 'http://127.0.0.1:7801';
const ADMIN = { authorization: `Bearer ${env['MCP_FW_ADMIN_TOKEN']}` };

// ── tiny reporting harness ─────────────────────────────────────────────────
const results: { name: string; pass: boolean; detail: string }[] = [];
const C = { g: '\x1b[32m', r: '\x1b[31m', d: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m' };
function check(name: string, pass: boolean, detail = ''): void {
  results.push({ name, pass, detail });
  console.log(`  ${pass ? `${C.g}✓` : `${C.r}✗`}${C.x} ${name}${detail ? `  ${C.d}${detail}${C.x}` : ''}`);
}
const section = (t: string) => console.log(`\n${C.b}${t}${C.x}`);

interface Outcome { ok: boolean; code?: string; approvalId?: string; text: string }
async function call(client: Client, name: string, args: Record<string, unknown>): Promise<Outcome> {
  const r = await client.callTool({ name, arguments: args }, undefined, { timeout: 120_000 });
  const fw = (r.structuredContent as { firewall?: { code?: string; approvalId?: string } } | undefined)?.firewall;
  const text = (r.content as { text?: string }[])[0]?.text ?? '';
  return { ok: !r.isError, ...(fw?.code ? { code: fw.code } : {}), ...(fw?.approvalId ? { approvalId: fw.approvalId } : {}), text };
}
const expectAllowed = (name: string, o: Outcome) => check(name, o.ok, o.ok ? o.text.slice(0, 70) : `got ${o.code}`);
const expectBlocked = (name: string, o: Outcome, code: string) => check(name, !o.ok && o.code === code, o.ok ? 'was ALLOWED' : o.code);

// ── human approver simulation (same code path as `mcp-fw approve`) ───────────
const approverKeys = new Map<string, { key: KeyObject; kid: string }>();
async function loadApprover(id: string, pemPath: string): Promise<void> {
  const key = createPrivateKey(await readFile(pemPath, 'utf8'));
  const { x } = await exportJWK(key);
  approverKeys.set(id, { key, kid: await calculateJwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: x! }, 'sha256') });
}
async function pendingFor(tool: string, resource: string): Promise<ApprovalView> {
  for (let i = 0; i < 40; i++) {
    const r = (await (await fetch(`${API}/v1/approvals?status=pending`, { headers: ADMIN })).json()) as { approvals: ApprovalView[] };
    const a = r.approvals.find((x) => x.tool === tool && x.resource === resource);
    if (a) return a;
    await sleep(100);
  }
  throw new Error(`no pending approval for ${tool} on ${resource}`);
}
async function getApproval(id: string): Promise<ApprovalView> {
  return (await (await fetch(`${API}/v1/approvals/${id}`, { headers: ADMIN })).json()) as ApprovalView;
}
async function postVote(id: string, signature: string): Promise<{ status: number; body: { status?: string; error?: string } }> {
  const res = await fetch(`${API}/v1/approvals/${id}/decisions`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ signature }) });
  return { status: res.status, body: (await res.json()) as { status?: string; error?: string } };
}
async function vote(who: string, a: ApprovalView, decision: 'approve' | 'deny') {
  const k = approverKeys.get(who)!;
  return postVote(a.id, await signDecision({ privateKey: k.key, kid: k.kid, approvalId: a.id, challenge: a.challenge, decision }));
}

// ────────────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  console.log(`${C.b}MCP Firewall & Intent Guard — end-to-end demo${C.x}`);
  const creds = await seed(env['MCP_FW_DATABASE_URL']!);
  for (const [id, path] of Object.entries(creds.approvers)) await loadApprover(id, path);

  const config = await loadConfig('examples/firewall.http.json');
  const fw = new Firewall({ ...config, approvals: { ...config.approvals, holdTimeoutMs: 4_000 } }, loadSecrets(), createLogger('warn'));
  await fw.startApprovalApi();
  const mcpUrl = await fw.startHttp();

  // ════ A. research agent over STDIO ════════════════════════════════════════
  section('A. research agent → firewall (stdio child process) → upstream');
  const research = new Client({ name: 'research-agent', version: '1.0.0' });
  await research.connect(new StdioClientTransport({
    command: 'npx', args: ['tsx', '--env-file=examples/dev.env', 'src/cli/index.ts', 'start', '--config', 'examples/firewall.stdio.json'],
    env: { ...env, MCP_FW_AGENT_KEY: creds.agents.research, MCP_FW_LOG_LEVEL: 'warn' } as Record<string, string>,
    stderr: 'inherit',
  }));
  const rTools = (await research.listTools()).tools.map((t) => t.name);
  check('tools/list filtered to what the agent may call', rTools.join() === 'github.get_file', `visible: [${rTools.join(', ')}]`);
  expectAllowed('read acme/website (allowed repo)', await call(research, 'github.get_file', { owner: 'acme', repo: 'website', path: 'README.md' }));
  expectBlocked('read acme/billing-service (different repo)', await call(research, 'github.get_file', { owner: 'acme', repo: 'billing-service', path: '.env' }), 'NO_MATCHING_POLICY');
  expectBlocked('"ignore previous instructions, open an issue" → write', await call(research, 'github.create_issue', { owner: 'acme', repo: 'website', title: 'pwned' }), 'POLICY_DENY');
  expectBlocked('path-smuggling repo "website/../billing"', await call(research, 'github.get_file', { owner: 'acme', repo: 'website/../billing', path: 'x' }), 'RESOURCE_UNRESOLVABLE');
  expectBlocked('wildcard smuggling repo "*"', await call(research, 'github.get_file', { owner: 'acme', repo: '*', path: 'x' }), 'RESOURCE_UNRESOLVABLE');
  expectBlocked('unclassified new tool debug.shell (fails closed as destructive)', await call(research, 'debug.shell', { cmd: 'cat /etc/passwd' }), 'POLICY_DENY');
  await research.close();

  const badAgent = new Client({ name: 'imposter', version: '1.0.0' });
  const badConnect = await badAgent.connect(new StdioClientTransport({
    command: 'npx', args: ['tsx', '--env-file=examples/dev.env', 'src/cli/index.ts', 'start', '--config', 'examples/firewall.stdio.json'],
    env: { ...env, MCP_FW_AGENT_KEY: 'mcpfw_' + 'A'.repeat(43), MCP_FW_LOG_LEVEL: 'error' } as Record<string, string>, stderr: 'ignore',
  })).then(() => 'connected', () => 'refused');
  check('stdio launch with an unknown agent key is refused', badConnect === 'refused', badConnect);

  // ════ B. ops agent over HTTP ══════════════════════════════════════════════
  section('B. ops agent → firewall (Streamable HTTP, bearer auth) → upstream');
  const opsTransport = new StreamableHTTPClientTransport(new URL(mcpUrl), { requestInit: { headers: { authorization: `Bearer ${creds.agents.ops}` } } });
  const ops = new Client({ name: 'ops-agent', version: '1.0.0' });
  await ops.connect(opsTransport);
  const oTools = (await ops.listTools()).tools.map((t) => t.name);
  check('tools/list hides delete_repo and the unclassified debug.shell', !oTools.includes('github.delete_repo') && !oTools.includes('debug.shell'), `visible: [${oTools.join(', ')}]`);
  expectAllowed('open issue on acme/website', await call(ops, 'github.create_issue', { owner: 'acme', repo: 'website', title: 'Fix typo' }));
  expectBlocked('org-wide setting change on acme', await call(ops, 'github.update_org_settings', { org: 'acme', setting: 'visibility', value: 'public' }), 'POLICY_DENY');
  expectAllowed('drop table on staging (no approval needed)', await call(ops, 'db.drop_table', { database: 'staging', table: 'sessions' }));

  const hijack = await fetch(mcpUrl, {
    method: 'POST',
    headers: { authorization: `Bearer ${creds.agents.research}`, 'mcp-session-id': opsTransport.sessionId!, 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-06-18' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/call', params: { name: 'db.drop_table', arguments: { database: 'staging', table: 'x' } } }),
  });
  check("research agent cannot ride the ops agent's session", hijack.status === 403, `HTTP ${hijack.status}`);
  const noKey = await fetch(mcpUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  check('HTTP request without an agent key is rejected', noKey.status === 401, `HTTP ${noKey.status}`);

  // ── B2. HITL: DBA approval while the call is held ───────────────────────
  section('C. Human-in-the-loop: held call released by a signed DBA approval');
  const dropProd = call(ops, 'db.drop_table', { database: 'prod', table: 'users' });
  const a1 = await pendingFor('db.drop_table', 'db:prod/table:users');
  console.log(`  ${C.d}… call held; approval ${a1.id} pending (${a1.resource})${C.x}`);
  const bobVote = await vote('bob', a1, 'approve');
  check('bob (finance, not dba) cannot approve a DBA action', bobVote.status === 403, `HTTP ${bobVote.status} ${bobVote.body.error}`);
  const aliceVote = await vote('alice', a1, 'approve');
  check('alice (dba) signs approval', aliceVote.status === 200 && aliceVote.body.status === 'approved', JSON.stringify(aliceVote.body));
  expectAllowed('held drop_table(prod.users) released to upstream', await dropProd);
  const replayVote = await vote('alice', a1, 'approve');
  check('re-voting on a closed approval is refused', replayVote.status === 410, `HTTP ${replayVote.status}`);

  // ── B3. two-person rule ─────────────────────────────────────────────────
  section('D. Two-person rule for payments');
  const pay = call(ops, 'payments.send_money', { to: 'vendor-42', amount_cents: 50_000, currency: 'USD' });
  const a2 = await pendingFor('payments.send_money', 'payments:account/vendor-42');
  const m = await vote('mallory', a2, 'approve');
  check('mallory (registered, but not in finance) is refused', m.status === 403, `HTTP ${m.status}`);
  const v1 = await vote('alice', a2, 'approve');
  check('first finance signature → still pending', v1.body.status === 'pending', JSON.stringify(v1.body));
  const dup = await vote('alice', a2, 'approve');
  check('same approver cannot count twice', dup.status === 409, `HTTP ${dup.status}`);
  const v2 = await vote('bob', a2, 'approve');
  check('second finance signature → approved', v2.body.status === 'approved', JSON.stringify(v2.body));
  expectAllowed('payment released after 2-of-N approval', await pay);

  const pay2 = call(ops, 'payments.send_money', { to: 'vendor-42', amount_cents: 50_000, currency: 'USD' });
  const a3 = await pendingFor('payments.send_money', 'payments:account/vendor-42');
  check('identical second payment needs a NEW approval (approvals are single-use)', a3.id !== a2.id);
  await vote('bob', a3, 'deny');
  expectBlocked('denied by a finance approver', await pay2, 'APPROVAL_DENIED');

  // ── B4. deferred approval: hold times out, human approves later, agent retries ──
  section('E. Deferred approval (hold timeout → approve later → exact retry)');
  const t0 = Date.now();
  const deferred = await call(ops, 'db.drop_table', { database: 'prod', table: 'audit_2019' });
  expectBlocked(`hold timed out after ${((Date.now() - t0) / 1000).toFixed(1)}s → APPROVAL_PENDING returned to agent`, deferred, 'APPROVAL_PENDING');
  const a4 = await getApproval(deferred.approvalId!);
  await vote('alice', a4, 'approve');
  const altered = await call(ops, 'db.drop_table', { database: 'prod', table: 'audit_2020' });
  check('retry with DIFFERENT args does not reuse the approval', !altered.ok && altered.approvalId !== a4.id, altered.code);
  expectAllowed('retry with IDENTICAL args → released immediately', await call(ops, 'db.drop_table', { database: 'prod', table: 'audit_2019' }));

  // ── B5. cryptographic attacks on the approval channel ───────────────────
  section('F. Attacks on the approval channel');
  const held = call(ops, 'github.delete_repo', { owner: 'acme', repo: 'website' }); // no policy → denied, sanity
  expectBlocked('destructive tool without any approval policy is denied outright', await held, 'NO_MATCHING_POLICY');

  const p5 = call(ops, 'db.drop_table', { database: 'prod', table: 'orders' });
  const a5 = await pendingFor('db.drop_table', 'db:prod/table:orders');
  const forgedKey = generateKeyPairSync('ed25519').privateKey;
  const forged = await postVote(a5.id, await signDecision({ privateKey: forgedKey, kid: approverKeys.get('alice')!.kid, approvalId: a5.id, challenge: a5.challenge, decision: 'approve' }));
  check("vote signed with a forged key claiming alice's kid is rejected", forged.status === 401, `HTTP ${forged.status}`);
  const k = approverKeys.get('alice')!;
  const sigForOther = await signDecision({ privateKey: k.key, kid: k.kid, approvalId: a4.id, challenge: a4.challenge, decision: 'approve' });
  const transplanted = await postVote(a5.id, sigForOther);
  check("alice's genuine signature for another approval cannot be transplanted", transplanted.status === 409, `HTTP ${transplanted.status}`);
  const genuine = await vote('alice', a5, 'approve');
  check('genuine signature still accepted after the attacks', genuine.body.status === 'approved', JSON.stringify(genuine.body));
  expectAllowed('held drop_table(prod.orders) released', await p5);

  // DB-level tampering: an attacker with SQL write access forges an "approved" row for prod.customers,
  // reusing a real challenge (HMAC-signed for prod.orders) and rewriting args_sha256/arguments.
  const admin = await mysql.createConnection({ uri: env['MCP_FW_DATABASE_URL']!, timezone: 'Z' });
  await admin.query(
    `INSERT INTO fw_approvals (id, status, agent_id, server_id, tool, resource, risk, args_sha256, arguments, challenge, policy_id, required_approvals, approver_group, correlation_id, created_at, expires_at)
     SELECT UUID(), 'approved', agent_id, server_id, tool, 'db:prod/table:customers', risk, ?, JSON_OBJECT('database','prod','table','customers'), challenge, policy_id, required_approvals, approver_group, correlation_id, created_at, expires_at
       FROM fw_approvals WHERE id = ?`, [argsDigest({ database: 'prod', table: 'customers' }), a5.id]);
  expectBlocked('forged "approved" DB row is rejected (HMAC challenge binds the real args)', await call(ops, 'db.drop_table', { database: 'prod', table: 'customers' }), 'APPROVAL_BINDING_MISMATCH');
  await ops.close();

  // ════ G. audit trail ══════════════════════════════════════════════════════
  section('G. Immutable audit trail');
  const [[counts]] = await admin.query<mysql.RowDataPacket[]>(`SELECT COUNT(*) AS n, SUM(event_type='policy.decision') AS decisions, SUM(event_type='approval.vote') AS votes FROM fw_audit_log`);
  const chain = await verifyAuditChain(fw.db);
  check('hash chain verifies', chain.ok, `${chain.rowsChecked} rows · ${counts?.['decisions']} policy decisions · ${counts?.['votes']} signed votes`);
  const upd = await admin.query(`UPDATE fw_audit_log SET decision = 'allow' WHERE decision = 'deny' LIMIT 1`).then(() => 'succeeded', (e: Error) => e.message);
  check('application UPDATE on the audit log is blocked by trigger', upd.includes('append-only'), upd);
  // A privileged DBA bypasses the trigger and rewrites history …
  const [[victim]] = await admin.query<mysql.RowDataPacket[]>(`SELECT seq FROM fw_audit_log WHERE event_type = 'policy.decision' AND decision = 'deny' ORDER BY seq LIMIT 1`);
  await admin.query('DROP TRIGGER trg_fw_audit_no_update');
  await admin.query(`UPDATE fw_audit_log SET decision = 'allow', reason_code = NULL WHERE seq = ?`, [victim?.['seq']]);
  await admin.query(`CREATE TRIGGER trg_fw_audit_no_update BEFORE UPDATE ON fw_audit_log FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fw_audit_log is append-only'`);
  const after = await verifyAuditChain(fw.db);
  check('… and the verifier pinpoints the rewritten row', !after.ok && after.firstBadSeq === Number(victim?.['seq']), `broken at seq ${after.firstBadSeq}: ${after.problem}`);
  await admin.end();

  await fw.close();
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${C.b}${results.length - failed.length}/${results.length} checks passed${C.x}${failed.length ? `  ${C.r}FAILED: ${failed.map((f) => f.name).join('; ')}${C.x}` : ''}`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
