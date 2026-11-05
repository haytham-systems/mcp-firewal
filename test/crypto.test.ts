import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { calculateJwkThumbprint, exportJWK, SignJWT } from 'jose';
import { canonicalJson } from '../src/core/canonical.js';
import { argsDigest, argumentsMatchChallenge, ChallengeSigner, signDecision, verifyDecision } from '../src/hitl/crypto.js';

test('canonicalJson is key-order independent and rejects non-JSON values', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: [1, 'x'], c: null } }), '{"a":{"c":null,"d":[1,"x"]},"b":1}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
  assert.throws(() => canonicalJson({ n: NaN }));
  assert.throws(() => canonicalJson({ f: () => 1 }));
});

const signer = new ChallengeSigner(randomBytes(32));
const mint = (args: Record<string, unknown>) => signer.mint({
  approvalId: randomUUID(), agent: 'agent-ops', server: 'acme', tool: 'db.drop_table', resource: 'db:prod/table:users',
  risk: 'destructive', argsSha256: argsDigest(args), ttlSeconds: 60,
});

test('challenge round-trips and detects tampering / wrong key', async () => {
  const ch = await mint({ database: 'prod', table: 'users' });
  assert.equal((await signer.verify(ch)).tool, 'db.drop_table');
  const [h, p, s] = ch.split('.');
  const forgedPayload = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, 'base64url').toString()), tool: 'x' })).toString('base64url');
  await assert.rejects(signer.verify(`${h}.${forgedPayload}.${s}`));
  await assert.rejects(new ChallengeSigner(randomBytes(32)).verify(ch));
  assert.ok(argumentsMatchChallenge(ch, { table: 'users', database: 'prod' }));
  assert.ok(!argumentsMatchChallenge(ch, { database: 'prod', table: 'orders' }));
});

test('decision signatures: valid, wrong key, wrong typ, alg confusion', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const { kty, crv, x } = await exportJWK(publicKey);
  const jwk = { kty, crv, x };
  const kid = await calculateJwkThumbprint(jwk, 'sha256');
  const ch = await mint({ database: 'prod', table: 'users' });
  const aid = randomUUID();

  const ok = await verifyDecision(await signDecision({ privateKey, kid, approvalId: aid, challenge: ch, decision: 'approve' }), jwk);
  assert.equal(ok.aid, aid);
  assert.equal(ok.decision, 'approve');

  const other = generateKeyPairSync('ed25519').privateKey;
  await assert.rejects(verifyDecision(await signDecision({ privateKey: other, kid, approvalId: aid, challenge: ch, decision: 'approve' }), jwk));

  const wrongTyp = await new SignJWT({ aid, chal: 'x'.repeat(43), decision: 'approve' })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' }).setJti('j'.repeat(20)).setIssuedAt().setExpirationTime('1m').sign(privateKey);
  await assert.rejects(verifyDecision(wrongTyp, jwk));

  const hs = await new SignJWT({ aid, chal: 'x'.repeat(43), decision: 'approve' })
    .setProtectedHeader({ alg: 'HS256', kid, typ: 'mcp-fw-decision+jwt' }).setJti('j'.repeat(20)).setIssuedAt().setExpirationTime('1m')
    .sign(new TextEncoder().encode(x!));
  await assert.rejects(verifyDecision(hs, jwk));
});
