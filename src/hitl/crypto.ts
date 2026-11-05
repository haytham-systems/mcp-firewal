import { randomBytes, type KeyObject } from 'node:crypto';
import { decodeJwt, importJWK, jwtVerify, SignJWT, type JWK } from 'jose';
import { z } from 'zod';
import { b64url, canonicalJson, sha256 } from '../core/canonical.js';
import type { Risk } from '../policy/types.js';

export const CHALLENGE_TYP = 'mcp-fw-challenge+jwt';
export const DECISION_TYP = 'mcp-fw-decision+jwt';
const ISSUER = 'mcp-firewall';
const CHALLENGE_AUD = 'mcp-firewall-approver';

/** SHA-256 over canonical JSON of the arguments — the value an approver's signature ultimately binds. */
export const argsDigest = (args: unknown): Buffer => sha256(canonicalJson(args ?? {}));

export const ChallengeClaimsSchema = z.object({
  iss: z.literal(ISSUER),
  aud: z.literal(CHALLENGE_AUD),
  sub: z.uuid(),                 // approval id
  agent: z.string(),
  server: z.string(),
  tool: z.string(),
  resource: z.string(),
  risk: z.enum(['read', 'write', 'destructive']),
  args_sha256: z.string(),       // base64url
  nonce: z.string().min(43),     // 256-bit, base64url
  iat: z.number().int(),
  exp: z.number().int(),
});
export type ChallengeClaims = z.infer<typeof ChallengeClaimsSchema>;

/**
 * Firewall-side challenge minting/verification (HS256, server-held secret).
 * The challenge makes the approval row self-authenticating: if someone edits args_sha256, tool,
 * or agent in MySQL, the HMAC no longer verifies and the approval cannot be consumed.
 */
export class ChallengeSigner {
  private readonly key: Uint8Array;

  constructor(secret: Buffer) {
    if (secret.length < 32) throw new Error('HMAC secret must be at least 32 bytes');
    this.key = new Uint8Array(secret);
  }

  async mint(input: { approvalId: string; agent: string; server: string; tool: string; resource: string; risk: Risk; argsSha256: Buffer; ttlSeconds: number }): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      agent: input.agent, server: input.server, tool: input.tool, resource: input.resource, risk: input.risk,
      args_sha256: b64url(input.argsSha256), nonce: b64url(randomBytes(32)),
    })
      .setProtectedHeader({ alg: 'HS256', typ: CHALLENGE_TYP })
      .setIssuer(ISSUER).setAudience(CHALLENGE_AUD).setSubject(input.approvalId)
      .setIssuedAt(now).setExpirationTime(now + input.ttlSeconds)
      .sign(this.key);
  }

  /** Verifies integrity. Expiry is checked separately against the DB row (`expiresAt`), so a past `exp` is tolerated here. */
  async verify(challenge: string): Promise<ChallengeClaims> {
    const { payload } = await jwtVerify(challenge, this.key, {
      algorithms: ['HS256'], typ: CHALLENGE_TYP, issuer: ISSUER, audience: CHALLENGE_AUD,
      currentDate: new Date(0), // integrity only; lifetime is enforced by the approval state machine
    });
    return ChallengeClaimsSchema.parse(payload);
  }
}

export const DecisionClaimsSchema = z.object({
  aid: z.uuid(),                        // approval id
  chal: z.string().length(43),          // base64url(SHA-256(challenge JWT))
  decision: z.enum(['approve', 'deny']),
  jti: z.string().min(16).max(128),
  iat: z.number().int(),
  exp: z.number().int(),
});
export type DecisionClaims = z.infer<typeof DecisionClaimsSchema>;

export const challengeHash = (challenge: string): string => b64url(sha256(challenge));

/** Verifies an approver's EdDSA-signed decision against their registered public key. */
export async function verifyDecision(jws: string, approverJwk: JWK): Promise<DecisionClaims> {
  const key = await importJWK(approverJwk, 'EdDSA');
  const { payload } = await jwtVerify(jws, key, {
    algorithms: ['EdDSA'], typ: DECISION_TYP, maxTokenAge: '5m', clockTolerance: 5, requiredClaims: ['jti', 'iat', 'exp'],
  });
  return DecisionClaimsSchema.parse(payload);
}

/**
 * Approver-side signing (used by the CLI and examples). The private key never leaves the
 * approver's machine; the firewall only ever sees the resulting JWS.
 */
export async function signDecision(input: { privateKey: KeyObject; kid: string; approvalId: string; challenge: string; decision: 'approve' | 'deny' }): Promise<string> {
  return new SignJWT({ aid: input.approvalId, chal: challengeHash(input.challenge), decision: input.decision })
    .setProtectedHeader({ alg: 'EdDSA', kid: input.kid, typ: DECISION_TYP })
    .setJti(b64url(randomBytes(18)))
    .setIssuedAt()
    .setExpirationTime('2m')
    .sign(input.privateKey);
}

/**
 * Lets an approver confirm, without the HMAC secret, that the arguments they are shown are the
 * ones the firewall bound into the challenge.
 */
export function argumentsMatchChallenge(challenge: string, args: unknown): boolean {
  const claims = decodeJwt(challenge);
  return claims['args_sha256'] === b64url(argsDigest(args));
}
