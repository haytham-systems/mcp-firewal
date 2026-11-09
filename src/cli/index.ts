#!/usr/bin/env node
import { generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { calculateJwkThumbprint, exportJWK, type JWK } from 'jose';
import type { RowDataPacket } from 'mysql2/promise';
import { verifyAuditChain } from '../audit/verify.js';
import { loadConfig, loadSecrets } from '../config.js';
import { createLogger } from '../core/logger.js';
import { createPool, migrate } from '../db/pool.js';
import { Firewall } from '../firewall.js';
import type { ApprovalView } from '../hitl/approval-service.js';
import { argumentsMatchChallenge, signDecision } from '../hitl/crypto.js';
import { generateAgentKey } from '../proxy/agents.js';

const USAGE = `mcp-fw — MCP Firewall & Intent Guard

  mcp-fw migrate                                         apply pending Sequelize migrations
  mcp-fw start --config firewall.json                    run the proxy (stdio or http per config)
  mcp-fw approvals:serve [--host 127.0.0.1 --port 7801]  run only the approval API

  mcp-fw agent:create <id> [--name "Display name"]       prints the agent API key ONCE
  mcp-fw approver:keygen <id> --out <dir>                Ed25519 keypair for a human approver
  mcp-fw approver:register <id> --jwk <file> [--name N] [--groups dba,finance]

  mcp-fw approvals [--status pending|approved|denied|expired|consumed|all]
  mcp-fw approve <approvalId> --key <private.pem> [--deny] [--yes]

  mcp-fw policy:list
  mcp-fw audit:verify

Environment: MCP_FW_DATABASE_URL, MCP_FW_HMAC_SECRET, MCP_FW_AUDIT_KEY, MCP_FW_ADMIN_TOKEN,
             MCP_FW_AGENT_KEY (stdio), MCP_FW_APPROVAL_URL (CLI, default http://127.0.0.1:7801)`;

const out = (s: string) => process.stderr.write(`${s}\n`); // stdout stays clean for stdio mode
const dbUrl = () => {
  const u = process.env['MCP_FW_DATABASE_URL'];
  if (!u) throw new Error('MCP_FW_DATABASE_URL is required');
  return u;
};
const apiBase = () => process.env['MCP_FW_APPROVAL_URL'] ?? 'http://127.0.0.1:7801';
const adminToken = () => {
  const t = process.env['MCP_FW_ADMIN_TOKEN'];
  if (!t) throw new Error('MCP_FW_ADMIN_TOKEN is required');
  return t;
};

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${apiBase()}${path}`, init);
  const body = (await res.json().catch(() => ({}))) as T & { error?: string; message?: string };
  if (!res.ok) throw new Error(`${res.status} ${body.error ?? ''} ${body.message ?? ''}`.trim());
  return body;
}

function printApproval(a: ApprovalView): void {
  out(`
  Approval   ${a.id}   [${a.status.toUpperCase()}]
  Agent      ${a.agentId}
  Server     ${a.serverId}
  Tool       ${a.tool}            risk: ${a.risk}
  Resource   ${a.resource}
  Arguments  ${JSON.stringify(a.arguments, null, 2).replace(/\n/g, '\n             ')}
  Args hash  ${a.argsSha256}
  Needs      ${a.requiredApprovals} approval(s)${a.approverGroup ? ` from group '${a.approverGroup}'` : ''}; votes so far: ${a.approvals.map((v) => `${v.approverId}=${v.decision}`).join(', ') || 'none'}
  Expires    ${a.expiresAt}
`);
}

async function main(argv: string[]): Promise<void> {
  const [cmd, ...rest] = argv;
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      config: { type: 'string' }, name: { type: 'string' }, out: { type: 'string' }, jwk: { type: 'string' },
      groups: { type: 'string' }, status: { type: 'string' }, key: { type: 'string' }, deny: { type: 'boolean' },
      yes: { type: 'boolean' }, host: { type: 'string' }, port: { type: 'string' },
    },
  });

  switch (cmd) {
    case 'migrate': {
      await migrate(dbUrl());
      out('schema applied');
      return;
    }

    case 'start': {
      if (!values.config) throw new Error('--config is required');
      const fw = new Firewall(await loadConfig(values.config), loadSecrets(), createLogger());
      const shutdown = () => void fw.close().finally(() => process.exit(0));
      process.once('SIGINT', shutdown).once('SIGTERM', shutdown);
      await fw.startApprovalApi();
      if (fw.config.downstream.type === 'stdio') {
        await fw.runStdio(process.env['MCP_FW_AGENT_KEY']);
        await fw.close();
        process.exit(0);
      }
      await fw.startHttp();
      return;
    }

    case 'approvals:serve': {
      const fw = new Firewall(
        {
          serverId: 'approval-api', upstream: { type: 'stdio', command: 'false', args: [] }, downstream: { type: 'stdio' },
          approvals: {
            serve: true, host: values.host ?? '127.0.0.1', port: Number(values.port ?? 7801), holdTimeoutMs: 0, ttlSeconds: 900, pollIntervalMs: 500,
          },
          filterToolsList: true, policyCacheTtlMs: 5000,
        },
        loadSecrets(), createLogger(),
      );
      await fw.startApprovalApi();
      process.once('SIGINT', () => void fw.close().finally(() => process.exit(0)));
      return;
    }

    case 'agent:create': {
      const id = positionals[0];
      if (!id || !/^[a-z][a-z0-9._-]{0,63}$/.test(id)) throw new Error('usage: agent:create <id>  (lowercase id)');
      const { key, hash } = generateAgentKey();
      const db = createPool(dbUrl());
      await db.execute('INSERT INTO fw_agents (id, display_name, api_key_hash) VALUES (?, ?, ?)', [id, values.name ?? id, hash]);
      await db.end();
      out(`agent '${id}' created. API key (shown once, store it in your secret manager):`);
      process.stdout.write(`${key}\n`);
      return;
    }

    case 'approver:keygen': {
      const id = positionals[0];
      if (!id || !values.out) throw new Error('usage: approver:keygen <id> --out <dir>');
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const { kty, crv, x } = await exportJWK(publicKey);
      const jwk: JWK = { kty, crv, x };
      await mkdir(values.out, { recursive: true });
      const keyPath = join(values.out, `${id}.key.pem`);
      await writeFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      await chmod(keyPath, 0o600);
      await writeFile(join(values.out, `${id}.pub.jwk.json`), JSON.stringify(jwk, null, 2));
      out(`private key: ${keyPath} (0600 — keep it on the approver's machine / hardware token)`);
      out(`public JWK : ${join(values.out, `${id}.pub.jwk.json`)}  kid=${await calculateJwkThumbprint(jwk, 'sha256')}`);
      return;
    }

    case 'approver:register': {
      const id = positionals[0];
      if (!id || !values.jwk) throw new Error('usage: approver:register <id> --jwk <file> [--groups a,b]');
      const raw = JSON.parse(await readFile(values.jwk, 'utf8')) as JWK;
      if (raw.kty !== 'OKP' || raw.crv !== 'Ed25519' || typeof raw.x !== 'string' || 'd' in raw) throw new Error('expected a PUBLIC Ed25519 JWK');
      const jwk: JWK = { kty: raw.kty, crv: raw.crv, x: raw.x };
      const kid = await calculateJwkThumbprint(jwk, 'sha256');
      const db = createPool(dbUrl());
      await db.execute('INSERT INTO fw_approvers (id, display_name, kid, public_jwk) VALUES (?, ?, ?, ?)', [id, values.name ?? id, kid, JSON.stringify(jwk)]);
      for (const g of (values.groups ?? '').split(',').map((x) => x.trim()).filter(Boolean)) {
        await db.execute('INSERT INTO fw_approver_groups (group_id, approver_id) VALUES (?, ?)', [g, id]);
      }
      await db.end();
      out(`approver '${id}' registered (kid=${kid})`);
      return;
    }

    case 'approvals': {
      const { approvals } = await api<{ approvals: ApprovalView[] }>(`/v1/approvals?status=${values.status ?? 'pending'}`, { headers: { authorization: `Bearer ${adminToken()}` } });
      if (approvals.length === 0) out('no approvals');
      approvals.forEach(printApproval);
      return;
    }

    case 'approve': {
      const id = positionals[0];
      if (!id || !values.key) throw new Error('usage: approve <approvalId> --key <private.pem> [--deny] [--yes]');
      const privateKey = createPrivateKey(await readFile(values.key, 'utf8'));
      const { x } = await exportJWK(privateKey);
      const kid = await calculateJwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: x! }, 'sha256');
      const a = await api<ApprovalView>(`/v1/approvals/${id}`, { headers: { authorization: `Bearer ${adminToken()}` } });
      printApproval(a);
      if (a.status !== 'pending') throw new Error(`approval is ${a.status}`);
      if (!argumentsMatchChallenge(a.challenge, a.arguments)) {
        throw new Error('ABORT: displayed arguments do not match the signed challenge — do not approve');
      }
      out('  ✓ arguments verified against the firewall challenge');
      const decision = values.deny ? 'deny' : 'approve';
      if (!values.yes) {
        const rl = createInterface({ input: process.stdin, output: process.stderr });
        const answer = await rl.question(`  Sign "${decision.toUpperCase()}" for this call? Type the tool name to confirm: `);
        rl.close();
        if (answer.trim() !== a.tool) throw new Error('confirmation did not match; nothing signed');
      }
      const signature = await signDecision({ privateKey, kid, approvalId: id, challenge: a.challenge, decision });
      const r = await api<{ status: string }>(`/v1/approvals/${id}/decisions`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ signature }),
      });
      out(`  signed ${decision}; approval is now ${r.status.toUpperCase()}`);
      return;
    }

    case 'policy:list': {
      const db = createPool(dbUrl());
      const [rows] = await db.query<RowDataPacket[]>('SELECT id, name, agent_pattern, server_pattern, tool_pattern, resource_pattern, risk_levels, effect, required_approvals, approver_group, enabled FROM fw_policies ORDER BY id');
      await db.end();
      console.table(rows);
      return;
    }

    case 'audit:verify': {
      const db = createPool(dbUrl());
      const r = await verifyAuditChain(db);
      await db.end();
      out(r.ok ? `✓ audit chain intact (${r.rowsChecked} rows)` : `✗ AUDIT CHAIN BROKEN at seq ${r.firstBadSeq}: ${r.problem}`);
      process.exitCode = r.ok ? 0 : 2;
      return;
    }

    default:
      out(USAGE);
      process.exitCode = cmd ? 1 : 0;
  }
}

main(process.argv.slice(2)).catch((err: unknown) => {
  out(`error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
