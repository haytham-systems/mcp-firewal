import type { RowDataPacket } from 'mysql2/promise';
import { z } from 'zod';
import { isValidResource } from '../core/glob.js';
import type { Logger } from '../core/logger.js';
import type { Pool } from '../db/pool.js';
import { RISKS, type Policy, type ToolClass } from './types.js';

const Glob = z.string().min(1).max(128).regex(/^[A-Za-z0-9_.:/*?-]+$/);
const RiskSchema = z.enum(RISKS);

const PolicyRowSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  agent_pattern: Glob,
  server_pattern: Glob,
  tool_pattern: Glob,
  resource_pattern: z.string().refine((r) => isValidResource(r, true), 'invalid resource pattern'),
  risk_levels: z.string().nullable().transform((s, ctx) => {
    if (s === null || s === '') return null;
    const parsed = z.array(RiskSchema).safeParse(s.split(','));
    if (!parsed.success) { ctx.addIssue({ code: 'custom', message: 'bad risk_levels' }); return z.NEVER; }
    return parsed.data;
  }),
  effect: z.enum(['allow', 'deny', 'require_approval']),
  required_approvals: z.number().int().min(1).max(5),
  approver_group: z.string().nullable(),
});

const ToolClassRowSchema = z.object({
  id: z.number().int(),
  server_pattern: Glob,
  tool_pattern: Glob,
  risk: RiskSchema,
  resource_template: z.string().max(512).nullable(),
});

export interface PolicySnapshot { readonly policies: readonly Policy[]; readonly classes: readonly ToolClass[]; readonly loadedAt: number }

/**
 * Loads policies + tool classes with a short TTL cache. Malformed rows are skipped and logged:
 * a skipped ALLOW only narrows access; a skipped DENY is escalated to an error and the whole
 * snapshot is refused, because silently dropping a deny would widen access.
 */
export class PolicyRepository {
  private cache: PolicySnapshot | null = null;
  private inflight: Promise<PolicySnapshot> | null = null;

  constructor(private readonly db: Pool, private readonly log: Logger, private readonly ttlMs = 5_000) {}

  invalidate(): void { this.cache = null; }

  async snapshot(): Promise<PolicySnapshot> {
    if (this.cache && Date.now() - this.cache.loadedAt < this.ttlMs) return this.cache;
    this.inflight ??= this.load().finally(() => { this.inflight = null; });
    return this.inflight;
  }

  private async load(): Promise<PolicySnapshot> {
    const [[pRows], [cRows]] = await Promise.all([
      this.db.query<RowDataPacket[]>('SELECT * FROM fw_policies WHERE enabled = 1 ORDER BY id'),
      this.db.query<RowDataPacket[]>('SELECT * FROM fw_tool_classes ORDER BY id'),
    ]);

    const policies: Policy[] = [];
    for (const row of pRows) {
      const r = PolicyRowSchema.safeParse(row);
      if (r.success) {
        const p = r.data;
        policies.push({
          id: p.id, name: p.name, agentPattern: p.agent_pattern, serverPattern: p.server_pattern, toolPattern: p.tool_pattern,
          resourcePattern: p.resource_pattern, riskLevels: p.risk_levels, effect: p.effect,
          requiredApprovals: p.required_approvals, approverGroup: p.approver_group,
        });
      } else if (row['effect'] === 'deny') {
        throw new Error(`malformed DENY policy id=${String(row['id'])}; refusing to load a snapshot that would widen access`);
      } else {
        this.log.warn('skipping malformed policy (fail closed)', { id: row['id'], issues: r.error.issues.map((i) => i.message) });
      }
    }

    const classes: ToolClass[] = [];
    for (const row of cRows) {
      const r = ToolClassRowSchema.safeParse(row);
      if (r.success) {
        const c = r.data;
        classes.push({ id: c.id, serverPattern: c.server_pattern, toolPattern: c.tool_pattern, risk: c.risk, resourceTemplate: c.resource_template });
      } else {
        // Dropping a classification makes the tool 'destructive' (stricter), so skipping is safe.
        this.log.warn('skipping malformed tool class (tool falls back to destructive)', { id: row['id'] });
      }
    }

    this.cache = { policies, classes, loadedAt: Date.now() };
    return this.cache;
  }
}

