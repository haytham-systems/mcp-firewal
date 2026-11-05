import { createHash, createHmac } from 'node:crypto';

/**
 * Deterministic JSON (RFC 8785-style: sorted keys, no whitespace). Used for every hash the
 * firewall computes, so agents, approvers and the audit verifier agree byte-for-byte.
 * Rejects values that have no stable JSON form instead of silently dropping them.
 */
export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > 64) throw new TypeError('canonicalJson: nesting too deep');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('canonicalJson: non-finite number');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v, depth + 1)).join(',')}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k], depth + 1)}`).join(',')}}`;
    }
    default:
      throw new TypeError(`canonicalJson: unsupported type ${typeof value}`);
  }
}

export const sha256 = (data: string | Buffer): Buffer => createHash('sha256').update(data).digest();
export const hmacSha256 = (key: Buffer, data: string | Buffer): Buffer => createHmac('sha256', key).update(data).digest();
export const b64url = (b: Buffer): string => b.toString('base64url');
