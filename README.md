# MCP Firewall & Intent Guard

A security proxy between LLM agents and MCP servers. It intercepts JSON-RPC traffic, enforces
least-privilege policy on every `tools/call`, holds destructive calls for **cryptographically
signed human approval**, and writes a **hash-chained, append-only audit log** to MySQL.

```
                           ┌──────────────────────── MCP Firewall ────────────────────────┐
 Agent (LLM client)        │                                                              │      Upstream MCP server
 ───────────────── stdio / │  downstream      SessionInterceptor                upstream  │ stdio / ──────────────────
   tools/call  ──────────▶ │  Transport ──▶ ┌──────────────────────────┐ ──▶ Transport ──▶│ HTTP  ──▶ tools execute
               ◀────────── │  (server side) │ 1 parse + validate       │    (client side) │      ◀──  results
                 Streamable│                │ 2 audit "intercepted"    │                  │
                 HTTP      │                │ 3 classify tool (risk)   │                  │
                           │                │ 4 render resource id     │                  │
                           │                │ 5 evaluate policy ───────┼──▶ MySQL policies │
                           │                │   deny ▶ tool error      │                  │
                           │                │   allow ▶ forward        │                  │
                           │                │   approval ▶ HOLD ───────┼──▶ fw_approvals   │
                           │                │ 6 audit decision/result  │                  │
                           │                └──────────────────────────┘                  │
                           │  Approval API :7801  ◀── signed votes (Ed25519) ── humans / `mcp-fw approve`
                           └──────────────────────────────────────────────────────────────┘
```

**Transport-agnostic by construction.** The proxy core (`FirewallSession`) bridges any two MCP SDK
`Transport`s and only ever sees `JSONRPCMessage`s, so stdio↔stdio, HTTP↔stdio and HTTP↔HTTP all
run the same enforcement code. `tools/call` is enforced; `tools/list` responses are filtered to the
tools the agent could ever call; everything else (initialize, notifications, server→client requests)
passes through untouched and in order.

## How a decision is made

1. **Classify** the tool (`fw_tool_classes`): risk `read | write | destructive` plus a resource
   template such as `github:repo/{owner}/{repo}`. Most specific pattern wins, ties go to the higher
   risk. **Unclassified tools are `destructive`**, so a tool newly added upstream is never callable by accident.
2. **Render the resource** from arguments. Every placeholder must be a single safe segment: `/`, `*`,
   `.`, `..`, objects and non-integers are rejected, so arguments can't widen their own scope.
3. **Evaluate** (`fw_policies`) with fixed, order-independent precedence:
   **deny > require_approval (strictest wins) > allow > default deny.** A deny can't be outvoted by any
   allow, whatever the prompt says.

Patterns: agent/server/tool ids use `*`/`?` globs. Resources are `/`-segmented: `*` is one segment,
`abc*` is one segment with that prefix, and a trailing `**` matches the rest. For example,
`github:repo/acme/*` allows every acme repo but never matches `github:org/acme`.

## Human-in-the-loop protocol

```
firewall                                   approver (private key never leaves their machine)
────────                                   ──────────────────────────────────────────────────
challenge = HS256-JWT{approval id, agent, server, tool, resource, risk,
                      args_sha256 = SHA-256(canonical args), 256-bit nonce, exp}
          ──── GET /v1/approvals/:id (admin token) ───▶  shows tool + args; CLI recomputes
                                                         SHA-256(args) == challenge.args_sha256
          ◀─── POST /v1/approvals/:id/decisions ──────  EdDSA-JWS{aid, chal = SHA-256(challenge),
                                                                  decision, jti, exp ≤ 2 min}
verify: kid → registered active approver · signature · aid + chal bind THIS approval ·
        approver ∈ required group · one vote per approver · any deny ends it · N approves → approved
release: re-verify the HMAC challenge against the exact held call → atomic approved→consumed → forward
```

- **Hold, then defer.** A call is held open for `holdTimeoutMs`. If nobody decides in time, the agent
  gets `APPROVAL_PENDING` with the approval id. Once approved, retrying the **identical** call releases
  it. Any change to the arguments needs a new approval.
- **Single use.** Every approval is consumed by exactly one execution.
- **Self-authenticating rows.** Editing `fw_approvals` in SQL (e.g. swapping `args_sha256`) breaks the
  HMAC binding, and consumption fails with `APPROVAL_BINDING_MISMATCH`.
- **Non-repudiation.** Every vote's JWS is stored in `fw_approval_signatures`.

## Audit log

Each row stores `entry_hash = SHA-256(prev_hash ‖ canonical(record))`. Appends serialize on a
singleton chain head, so `seq` has no gaps. Triggers block `UPDATE` and `DELETE`, and `mcp-fw audit:verify`
detects edits, deletions, insertions and tail truncation. Arguments are stored as
`HMAC-SHA256(audit key, canonical args)`: the same arguments link across rows, but low-entropy
values can't be brute-forced.

Logged events include `tool.call.intercepted`, `policy.decision`, `approval.requested`,
`approval.vote`, `approval.resolved`, `approval.consumed`, `tool.call.forwarded`, `tool.call.result`,
`tools.list.filtered`, `agent.auth_failed` and `session.opened/closed`.

**Fail closed.** If the audit write for an intercepted call or a forward fails, the call is refused.

## Getting started

```bash
cat > examples/dev.env <<EOF
MCP_FW_DATABASE_URL=mysql://root@127.0.0.1:3307/mcp_firewall
MCP_FW_HMAC_SECRET=$(openssl rand -base64 32)
MCP_FW_AUDIT_KEY=$(openssl rand -base64 32)
MCP_FW_ADMIN_TOKEN=$(openssl rand -base64 32)
MCP_FW_APPROVAL_URL=http://127.0.0.1:7801
EOF

npm install
npm run db:up            # local MySQL on 127.0.0.1:3307, data in ./.mysql (or point MCP_FW_DATABASE_URL anywhere)
npm test                 # unit tests: matching, precedence, smuggling, crypto
npm run demo             # end-to-end: both transports, approvals, attacks, audit tamper detection
```

### Local approval dashboard

The local dashboard lets you send fixture MCP calls through the HTTP firewall, inspect live
approvals, and cast Ed25519 votes in the browser. It talks only to the local demo upstream; it
does not connect to real services. Start the database and, if this is a fresh disposable demo
database, seed it first (`npm run demo:seed` resets the demo tables):

```bash
# Terminal 1: the HTTP firewall and approval API
npm run mcp-fw -- start --config examples/firewall.http.json

# Terminal 2: dashboard
npm run ui
```

Open `http://127.0.0.1:4173`. Choose a scenario and run it; pending actions appear in the inbox.
Open an approval, select a registered key such as `examples/keys/alice.key.pem`, then sign a
vote. The browser checks that the arguments match the challenge before enabling the vote, and
the private key is not uploaded or persisted. The UI bridge binds to loopback by default and
keeps the admin token on the server.

`examples/dev.env` is local-only and ignored by git. In production, generate fresh secrets for
your deployment:

```bash
export MCP_FW_DATABASE_URL='mysql://fw:***@db:3306/mcp_firewall'
export MCP_FW_HMAC_SECRET=$(openssl rand -base64 32)   # challenge signing
export MCP_FW_AUDIT_KEY=$(openssl rand -base64 32)     # argument HMACs
export MCP_FW_ADMIN_TOKEN=$(openssl rand -base64 32)   # approval API read access
```

### Provision

```bash
npx tsx src/cli/index.ts migrate
npx tsx src/cli/index.ts agent:create agent-ops --name "Ops agent"        # prints API key once
npx tsx src/cli/index.ts approver:keygen alice --out ~/.mcp-fw             # on Alice's machine
npx tsx src/cli/index.ts approver:register alice --jwk alice.pub.jwk.json --groups dba,finance
```

Then add classifications and policies (see `examples/seed.ts`):

```sql
INSERT INTO fw_tool_classes (server_pattern, tool_pattern, risk, resource_template)
VALUES ('github', 'github.delete_repo', 'destructive', 'github:repo/{owner}/{repo}');

INSERT INTO fw_policies (name, agent_pattern, server_pattern, tool_pattern, resource_pattern, risk_levels, effect)
VALUES ('read-only agent', 'agent-research', '*', '*', '**', 'write,destructive', 'deny');
```

### Wire into an existing MCP setup

**stdio (Claude Desktop / Claude Code / any MCP client).** Replace the server command with the firewall
and move the real server into `upstream`:

```jsonc
// before:  "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
"github": {
  "command": "npx",
  "args": ["tsx", "/path/to/mcp-firewall/src/cli/index.ts", "start", "--config", "/path/to/github.firewall.json"],
  "env": { "MCP_FW_AGENT_KEY": "mcpfw_…", "MCP_FW_DATABASE_URL": "…", "MCP_FW_HMAC_SECRET": "…",
           "MCP_FW_AUDIT_KEY": "…", "MCP_FW_ADMIN_TOKEN": "…" }
}
```
```json
{ "serverId": "github",
  "upstream":   { "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                  "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "…" } },
  "downstream": { "type": "stdio" },
  "approvals":  { "serve": false, "publicUrl": "http://approvals.internal:7801" } }
```

Several stdio firewalls can share one database. Run a single `mcp-fw approvals:serve` for the
approval API and set `serve: false` everywhere else. Keep the upstream credential (e.g. the GitHub
token) in the firewall config, **not** in the agent's environment, so the agent can only reach the
server through the firewall.

**HTTP.** Use `"downstream": { "type": "http", "port": 7800 }`. Agents connect to
`http://host:7800/mcp` with `Authorization: Bearer <agent key>`. Each session is bound to the agent
that opened it, and the `Host` header is checked against an allowlist. The upstream can be stdio or
`{ "type": "http", "url": "…" }`.

### Approve from the terminal

```bash
npx tsx src/cli/index.ts approvals                         # pending, with full arguments
npx tsx src/cli/index.ts approve <id> --key ~/.mcp-fw/alice.key.pem   # type the tool name to sign
npx tsx src/cli/index.ts approve <id> --key … --deny
npx tsx src/cli/index.ts audit:verify
```

To try it by hand: run `npm run demo:seed`, then
`npm run mcp-fw -- start --config examples/firewall.http.json`. In another terminal run
`npm run demo:call -- db.drop_table '{"database":"prod","table":"users"}'`, and in a third,
`npm run mcp-fw -- approvals` followed by `npm run mcp-fw -- approve <id> --key examples/keys/alice.key.pem`.

## Layout

```
sql/schema.sql            DDL (idempotent): agents, approvers, tool classes, policies, approvals, audit
src/core/                 canonical JSON, glob/resource matching, JSON-RPC types, errors, stderr logger
src/policy/               pure evaluation engine + cached MySQL repository
src/hitl/                 challenge/decision crypto, approval state machine, approval HTTP API
src/audit/                hash-chained append + verifier
src/proxy/                SessionInterceptor (decisions) · FirewallSession (transport bridge) · agent auth
src/firewall.ts           composition root: stdio + Streamable HTTP downstreams, stdio/HTTP upstreams
src/cli/index.ts          mcp-fw CLI
examples/                 upstream test server, seed, configs, end-to-end demo, single-call client
```

## Limits and next steps

- Only `tools/call` is policy-enforced. `resources/read` and `prompts/get` pass through. Extend
  `SessionInterceptor.onClientMessage` the same way if your servers expose sensitive resources.
- Approval holds are in-process; another instance can record the votes (state lives in MySQL) but
  the held socket belongs to the instance that received the call. The deferred-retry path covers failover.
- The audit chain is tamper-*evident*, not tamper-*proof*. Anchor `fw_audit_head.last_hash` to external
  WORM storage periodically, so a DBA who rewrites the entire chain is also detected.
- `fw_approvals.arguments` stores plaintext arguments so approvers can see them. Purge or encrypt
  decided rows on a schedule if arguments can contain secrets.
