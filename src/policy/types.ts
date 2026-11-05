export const RISKS = ['read', 'write', 'destructive'] as const;
export type Risk = (typeof RISKS)[number];

export type Effect = 'allow' | 'deny' | 'require_approval';

export interface ToolClass {
  readonly id: number;
  readonly serverPattern: string;
  readonly toolPattern: string;
  readonly risk: Risk;
  /** e.g. 'github:repo/{owner}/{repo}'; null → 'tool:<name>' */
  readonly resourceTemplate: string | null;
}

export interface Policy {
  readonly id: number;
  readonly name: string;
  readonly agentPattern: string;
  readonly serverPattern: string;
  readonly toolPattern: string;
  readonly resourcePattern: string;
  /** null = applies to every risk level */
  readonly riskLevels: readonly Risk[] | null;
  readonly effect: Effect;
  readonly requiredApprovals: number;
  readonly approverGroup: string | null;
}

export interface CallContext {
  readonly agentId: string;
  readonly serverId: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
}

interface Base { readonly matchedPolicyIds: readonly number[] }
export type Decision =
  | (Base & { effect: 'allow'; risk: Risk; resource: string })
  | (Base & {
      effect: 'require_approval';
      risk: Risk;
      resource: string;
      policyId: number;
      requiredApprovals: number;
      approverGroup: string | null;
    })
  | (Base & {
      effect: 'deny';
      code: 'POLICY_DENY' | 'NO_MATCHING_POLICY' | 'RESOURCE_UNRESOLVABLE';
      reason: string;
      risk?: Risk;
      resource?: string;
    });
