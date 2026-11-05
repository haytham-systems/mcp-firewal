import assert from 'node:assert/strict';
import { test } from 'node:test';
import { globMatch, resourceMatch } from '../src/core/glob.js';
import { classifyTool, evaluate, isToolVisible, renderResource } from '../src/policy/engine.js';
import type { Policy, ToolClass } from '../src/policy/types.js';

test('globMatch', () => {
  assert.ok(globMatch('github.*', 'github.get_file'));
  assert.ok(globMatch('*', 'anything'));
  assert.ok(globMatch('agent-?', 'agent-1'));
  assert.ok(!globMatch('github.*', 'gitlab.get_file'));
  assert.ok(!globMatch('db.drop_table', 'db.drop_tables'));
});

test('resourceMatch', () => {
  const cases: [string, string, boolean][] = [
    ['github:repo/acme/*', 'github:repo/acme/website', true],
    ['github:repo/acme/*', 'github:org/acme', false],
    ['github:repo/acme/*', 'github:repo/acme/website/extra', false],
    ['github:repo/acme/web*', 'github:repo/acme/website', true],
    ['db:prod/**', 'db:prod/table:users', true],
    ['db:prod/**', 'db:prod', false],
    ['**', 'tool:x', true],
    ['github:repo/acme/website', 'github:repo/acme/*', false], // wildcard is never a concrete resource
  ];
  for (const [p, r, want] of cases) assert.equal(resourceMatch(p, r), want, `${p} vs ${r}`);
});

test('renderResource rejects smuggling', () => {
  const t = 'github:repo/{owner}/{repo}';
  assert.equal(renderResource(t, 'x', { owner: 'acme', repo: 'web' }), 'github:repo/acme/web');
  for (const repo of ['a/b', '*', '', '..', 'web site']) {
    assert.throws(() => renderResource(t, 'x', { owner: 'acme', repo }), Error, repo);
  }
  assert.throws(() => renderResource(t, 'x', { owner: 'acme' }));
  assert.throws(() => renderResource(t, 'x', { owner: 'acme', repo: { toString: () => 'web' } }));
  assert.equal(renderResource('db:{a.b}', 'x', { a: { b: 7 } }), 'db:7');
  assert.equal(renderResource(null, 'debug.shell', {}), 'tool:debug.shell');
});

const classes: ToolClass[] = [
  { id: 1, serverPattern: '*', toolPattern: 'github.*', risk: 'write', resourceTemplate: 'github:repo/{owner}/{repo}' },
  { id: 2, serverPattern: 'acme', toolPattern: 'github.get_file', risk: 'read', resourceTemplate: 'github:repo/{owner}/{repo}' },
];
const P = (p: Partial<Policy> & Pick<Policy, 'id' | 'effect'>): Policy => ({
  name: `p${p.id}`, agentPattern: '*', serverPattern: '*', toolPattern: '*', resourcePattern: '**',
  riskLevels: null, requiredApprovals: 1, approverGroup: null, ...p,
});
const ctx = (tool: string, args: Record<string, unknown> = { owner: 'acme', repo: 'web' }) => ({ agentId: 'a', serverId: 'acme', tool, args });

test('classification: most specific wins, unclassified is destructive', () => {
  assert.equal(classifyTool(classes, 'acme', 'github.get_file').risk, 'read');
  assert.equal(classifyTool(classes, 'acme', 'github.create_issue').risk, 'write');
  assert.equal(classifyTool(classes, 'acme', 'shell.exec').risk, 'destructive');
});

test('precedence: deny > require_approval > allow > default deny (order independent)', () => {
  const allow = P({ id: 1, effect: 'allow' });
  const appr = P({ id: 2, effect: 'require_approval', requiredApprovals: 2 });
  const deny = P({ id: 3, effect: 'deny', riskLevels: ['write'] });
  assert.equal(evaluate([], classes, ctx('github.get_file')).effect, 'deny');
  assert.equal(evaluate([allow], classes, ctx('github.get_file')).effect, 'allow');
  for (const order of [[allow, appr], [appr, allow]]) {
    const d = evaluate(order, classes, ctx('github.get_file'));
    assert.equal(d.effect, 'require_approval');
    assert.equal(d.effect === 'require_approval' && d.requiredApprovals, 2);
  }
  for (const order of [[allow, appr, deny], [deny, appr, allow]]) {
    assert.equal(evaluate(order, classes, ctx('github.create_issue')).effect, 'deny');
    assert.equal(evaluate(order, classes, ctx('github.get_file')).effect, 'require_approval'); // deny only covers 'write'
  }
});

test('strictest approval policy wins', () => {
  const d = evaluate([P({ id: 1, effect: 'require_approval', requiredApprovals: 1, approverGroup: 'a' }), P({ id: 2, effect: 'require_approval', requiredApprovals: 3, approverGroup: 'b' })], classes, ctx('github.get_file'));
  assert.deepEqual(d.effect === 'require_approval' && [d.requiredApprovals, d.approverGroup], [3, 'b']);
});

test('resource-scoped allow does not leak to other resources', () => {
  const allow = P({ id: 1, effect: 'allow', resourcePattern: 'github:repo/acme/web' });
  assert.equal(evaluate([allow], classes, ctx('github.get_file')).effect, 'allow');
  assert.equal(evaluate([allow], classes, ctx('github.get_file', { owner: 'acme', repo: 'billing' })).effect, 'deny');
});

test('tools/list visibility', () => {
  const ps = [P({ id: 1, effect: 'allow', riskLevels: ['read'] }), P({ id: 2, effect: 'deny', toolPattern: 'github.create_*' })];
  assert.ok(isToolVisible(ps, classes, 'a', 'acme', 'github.get_file'));
  assert.ok(!isToolVisible(ps, classes, 'a', 'acme', 'github.create_issue'));
  assert.ok(!isToolVisible(ps, classes, 'a', 'acme', 'shell.exec'));
});
