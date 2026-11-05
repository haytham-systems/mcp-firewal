/** Machine-readable reasons surfaced in audit rows and (opaquely) to the agent. */
export type ReasonCode =
  | 'POLICY_DENY'
  | 'NO_MATCHING_POLICY'
  | 'RESOURCE_UNRESOLVABLE'
  | 'INVALID_REQUEST'
  | 'AGENT_UNAUTHENTICATED'
  | 'AGENT_DISABLED'
  | 'APPROVAL_PENDING'
  | 'APPROVAL_DENIED'
  | 'APPROVAL_EXPIRED'
  | 'APPROVAL_BINDING_MISMATCH'
  | 'AUDIT_UNAVAILABLE'
  | 'FIREWALL_ERROR';

export class FirewallError extends Error {
  override readonly name = 'FirewallError';

  constructor(
    readonly code: ReasonCode,
    message: string,
    readonly httpStatus: 400 | 401 | 403 | 404 | 409 | 410 | 500 = 403,
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }
}

export const isFirewallError = (e: unknown): e is FirewallError => e instanceof FirewallError;
