import { globMatch, isResourceSegment, isValidResource, resourceMatch } from '../core/glob.js';
import type { CallContext, Decision, Policy, Risk, ToolClass } from './types.js';

const RISK_ORDER: Record<Risk, number> = { read: 0, write: 1, destructive: 2 };

/** Specificity of a glob: literal characters count, wildcards don't. */
const specificity = (p: string) => p.replace(/[*?]/g, '').length;

/**
 * Picks the classification for a tool. Most specific (server + tool) pattern wins; ties go to the
 * HIGHER risk. Unclassified tools are 'destructive' — a newly added upstream tool can never be
 * silently callable just because nobody classified it yet.
 */
export function classifyTool(classes: readonly ToolClass[], serverId: string, tool: string): ToolClass {
  let best: ToolClass | undefined;
  let bestScore = -1;
  for (const c of classes) {
    if (!globMatch(c.serverPattern, serverId) || !globMatch(c.toolPattern, tool)) continue;
    const score = specificity(c.toolPattern) * 1000 + specificity(c.serverPattern);
    if (score > bestScore || (score === bestScore && best && RISK_ORDER[c.risk] > RISK_ORDER[best.risk])) {
      best = c;
      bestScore = score;
    }
  }
  return best ?? { id: 0, serverPattern: '*', toolPattern: '*', risk: 'destructive', resourceTemplate: null };
}

const PLACEHOLDER_RE = /\{([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\}/g;

/**
 * Renders a resource id from a template and the call arguments.
 * Each placeholder must resolve to a string or safe integer that is a single valid segment —
 * an argument like `"acme/../../org"` or `"*"` cannot widen the resource. Throws on failure.
 */
export function renderResource(template: string | null, tool: string, args: Readonly<Record<string, unknown>>): string {
  if (template === null) return `tool:${tool}`;
  const rendered = template.replace(PLACEHOLDER_RE, (_m, path: string) => {
    let v: unknown = args;
    for (const key of path.split('.')) {
      if (v === null || typeof v !== 'object' || Array.isArray(v) || !Object.hasOwn(v, key)) {
        throw new Error(`argument '${path}' missing`);
      }
      v = (v as Record<string, unknown>)[key];
    }
    const s = typeof v === 'string' ? v : typeof v === 'number' && Number.isSafeInteger(v) ? String(v) : null;
    if (s === null || s.includes('*') || !isResourceSegment(s)) throw new Error(`argument '${path}' is not a valid resource segment`);
    return s;
  });
  if (!isValidResource(rendered, false)) throw new Error(`rendered resource '${rendered}' is invalid`);
  return rendered;
}

const policyApplies = (p: Policy, ctx: CallContext, risk: Risk) =>
  globMatch(p.agentPattern, ctx.agentId) &&
  globMatch(p.serverPattern, ctx.serverId) &&
  globMatch(p.toolPattern, ctx.tool) &&
  (p.riskLevels === null || p.riskLevels.includes(risk));

/**
 * Pure, order-independent evaluation:
 *   deny  >  require_approval (strictest wins)  >  allow  >  default deny.
 */
export function evaluate(policies: readonly Policy[], classes: readonly ToolClass[], ctx: CallContext): Decision {
  const cls = classifyTool(classes, ctx.serverId, ctx.tool);
  let resource: string;
  try {
    resource = renderResource(cls.resourceTemplate, ctx.tool, ctx.args);
  } catch (err) {
    return {
      effect: 'deny', code: 'RESOURCE_UNRESOLVABLE', risk: cls.risk, matchedPolicyIds: [],
      reason: err instanceof Error ? err.message : 'resource unresolvable',
    };
  }

  const matched = policies.filter((p) => policyApplies(p, ctx, cls.risk) && resourceMatch(p.resourcePattern, resource));
  const ids = matched.map((p) => p.id);

  const deny = matched.find((p) => p.effect === 'deny');
  if (deny) {
    return { effect: 'deny', code: 'POLICY_DENY', reason: `denied by policy '${deny.name}'`, risk: cls.risk, resource, matchedPolicyIds: ids };
  }
  const approvals = matched.filter((p) => p.effect === 'require_approval');
  if (approvals.length > 0) {
    const strictest = approvals.reduce((a, b) => (b.requiredApprovals > a.requiredApprovals ? b : a));
    return {
      effect: 'require_approval', risk: cls.risk, resource, matchedPolicyIds: ids, policyId: strictest.id,
      requiredApprovals: strictest.requiredApprovals, approverGroup: strictest.approverGroup,
    };
  }
  if (matched.some((p) => p.effect === 'allow')) return { effect: 'allow', risk: cls.risk, resource, matchedPolicyIds: ids };
  return { effect: 'deny', code: 'NO_MATCHING_POLICY', reason: 'no policy grants this call', risk: cls.risk, resource, matchedPolicyIds: [] };
}

/**
 * tools/list filtering: hide a tool when no policy could ever let this agent call it, or a
 * blanket ('**') deny covers it. Purely cosmetic hardening — every call is still evaluated.
 */
export function isToolVisible(policies: readonly Policy[], classes: readonly ToolClass[], agentId: string, serverId: string, tool: string): boolean {
  const { risk } = classifyTool(classes, serverId, tool);
  const ctx: CallContext = { agentId, serverId, tool, args: {} };
  const applicable = policies.filter((p) => policyApplies(p, ctx, risk));
  if (applicable.some((p) => p.effect === 'deny' && p.resourcePattern === '**')) return false;
  return applicable.some((p) => p.effect !== 'deny');
}
