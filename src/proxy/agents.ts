import { randomBytes } from 'node:crypto';
import type { RowDataPacket } from 'mysql2/promise';
import { sha256 } from '../core/canonical.js';
import { FirewallError } from '../core/errors.js';
import type { Pool } from '../db/pool.js';

export interface AgentIdentity { readonly id: string; readonly displayName: string }

const KEY_PREFIX = 'mcpfw_';
const KEY_RE = /^mcpfw_[A-Za-z0-9_-]{43}$/;

/** Generates a new agent API key. Only its SHA-256 is stored; show the key to the operator once. */
export function generateAgentKey(): { key: string; hash: Buffer } {
  const key = KEY_PREFIX + randomBytes(32).toString('base64url');
  return { key, hash: sha256(key) };
}

/**
 * Agents authenticate with a high-entropy API key (HTTP: `Authorization: Bearer`, stdio:
 * `MCP_FW_AGENT_KEY` set by the launcher). Lookup is by SHA-256, so the DB never holds a usable
 * credential and comparison happens on a uniformly random index key (no timing oracle).
 */
export class AgentDirectory {
  constructor(private readonly db: Pool) {}

  async authenticate(apiKey: string | undefined): Promise<AgentIdentity> {
    if (!apiKey || !KEY_RE.test(apiKey)) throw new FirewallError('AGENT_UNAUTHENTICATED', 'missing or malformed agent key', 401);
    const [rows] = await this.db.execute<RowDataPacket[]>(
      'SELECT id, display_name, status FROM fw_agents WHERE api_key_hash = ?', [sha256(apiKey)],
    );
    const row = rows[0];
    if (!row) throw new FirewallError('AGENT_UNAUTHENTICATED', 'unknown agent key', 401);
    if (row['status'] !== 'active') throw new FirewallError('AGENT_DISABLED', 'agent is disabled', 403);
    return { id: String(row['id']), displayName: String(row['display_name']) };
  }
}
