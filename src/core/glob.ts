/**
 * Two matchers, both regex-free so policy data can never inject a pattern.
 *
 * 1. `globMatch` — flat identifiers (agent ids, server ids, tool names). '*' matches any run of
 *    characters, '?' exactly one. Case-sensitive.
 *
 * 2. `resourceMatch` — '/'-segmented resource ids such as 'github:repo/acme/website'.
 *      '*'       one whole segment
 *      'abc*'    one segment starting with 'abc'
 *      '**'      (last segment only) one or more remaining segments
 *    A resource policy for 'github:repo/acme/*' therefore never matches 'github:org/acme'.
 */

export function globMatch(pattern: string, value: string): boolean {
  let p = 0;
  let v = 0;
  let star = -1;
  let mark = 0;
  while (v < value.length) {
    if (p < pattern.length && (pattern[p] === '?' || pattern[p] === value[v])) {
      p++;
      v++;
    } else if (p < pattern.length && pattern[p] === '*') {
      star = p++;
      mark = v;
    } else if (star !== -1) {
      p = star + 1;
      v = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

const SEGMENT_RE = /^[A-Za-z0-9_.:@~+=-]{1,200}$/;
const PREFIX_WILDCARD_RE = /^[A-Za-z0-9_.:@~+=-]{0,199}\*$/;

/** Validates a resource pattern (wildcards allowed) or a concrete resource (no wildcards). */
export function isValidResource(r: string, allowWildcards: boolean): boolean {
  if (r.length === 0 || r.length > 512) return false;
  const segs = r.split('/');
  return segs.every((s, i) => {
    if (s === '**') return allowWildcards && i === segs.length - 1;
    if (s.endsWith('*')) return allowWildcards && PREFIX_WILDCARD_RE.test(s);
    return SEGMENT_RE.test(s) && !isDotSegment(s);
  });
}

/** '.' and '..' are rejected: upstreams that build paths from arguments would resolve them upward. */
const isDotSegment = (s: string) => s === '.' || s === '..';

export const isResourceSegment = (s: string): boolean => SEGMENT_RE.test(s) && !isDotSegment(s);

/** Does `pattern` match the concrete `resource`? Invalid inputs never match (fail closed). */
export function resourceMatch(pattern: string, resource: string): boolean {
  if (!isValidResource(pattern, true) || !isValidResource(resource, false)) return false;
  const p = pattern.split('/');
  const r = resource.split('/');
  for (let i = 0; i < p.length; i++) {
    const ps = p[i]!;
    if (ps === '**') return r.length > i;
    const rs = r[i];
    if (rs === undefined) return false;
    if (ps.endsWith('*') ? !rs.startsWith(ps.slice(0, -1)) : ps !== rs) return false;
  }
  return p.length === r.length;
}
