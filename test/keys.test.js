import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  decodeKey,
  generateKeypair,
  HEADER,
  isPowerKey,
  keyFrom,
  keyIdFor,
  mintKey,
  PREFIX,
  PROFULLSTACK_KEYS,
  verifyKey,
  verifyRequest,
} from '../src/index.js';

const pair = await generateKeypair();
const keys = { [pair.kid]: pair.publicKey };
const NOW = 1_800_000_000;

describe('keypair', () => {
  it('is base64url and names itself', async () => {
    assert.match(pair.publicKey, /^[A-Za-z0-9_-]{43}$/);
    assert.match(pair.privateKey, /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/);
    assert.equal(pair.kid, await keyIdFor(pair.publicKey));
    assert.equal(pair.kid.length, 8);
  });

  it('the shipped key list is a frozen map of kid to public key', () => {
    assert.ok(Object.isFrozen(PROFULLSTACK_KEYS));
    for (const [kid, pub] of Object.entries(PROFULLSTACK_KEYS)) {
      assert.match(kid, /^[A-Za-z0-9_-]{8}$/);
      assert.match(pub, /^[A-Za-z0-9_-]{43}$/);
    }
  });
});

describe('mint + verify', () => {
  it('round-trips a lifetime key', async () => {
    const { key, claims } = await mintKey({ privateKey: pair.privateKey, sub: 'pay_1', now: NOW });
    assert.ok(key.startsWith(PREFIX));
    assert.deepEqual(claims, { v: 1, kid: pair.kid, sub: 'pay_1', plan: 'lifetime', scope: '*', iat: NOW, exp: null });
    const result = await verifyKey(key, { publicKeys: keys, now: NOW + 10 * 365 * 86400 });
    assert.equal(result.ok, true);
    assert.deepEqual(result.claims, claims);
    assert.deepEqual(decodeKey(key), claims);
  });

  it('honours an expiry', async () => {
    const { key } = await mintKey({ privateKey: pair.privateKey, sub: 'pay_2', plan: 'year', exp: NOW + 100, now: NOW });
    assert.equal((await verifyKey(key, { publicKeys: keys, now: NOW + 99 })).ok, true);
    const late = await verifyKey(key, { publicKeys: keys, now: NOW + 100 });
    assert.deepEqual(late, { ok: false, reason: 'expired' });
  });

  it('refuses a past expiry at mint time', async () => {
    await assert.rejects(mintKey({ privateKey: pair.privateKey, sub: 'x', exp: NOW - 1, now: NOW }), /future/);
    await assert.rejects(mintKey({ privateKey: pair.privateKey, sub: '' }), /subject/);
    await assert.rejects(mintKey({ privateKey: 'nodot', sub: 'x' }), /generateKeypair/);
  });

  it('rejects a tampered payload', async () => {
    const { key } = await mintKey({ privateKey: pair.privateKey, sub: 'pay_3', now: NOW });
    const dot = key.indexOf('.');
    const forged = { ...decodeKey(key), plan: 'everything' };
    const payload = Buffer.from(JSON.stringify(forged)).toString('base64url');
    const tampered = `${PREFIX}${payload}${key.slice(dot)}`;
    assert.deepEqual(await verifyKey(tampered, { publicKeys: keys, now: NOW }), { ok: false, reason: 'bad signature' });
  });

  it('rejects a key from a signer it does not know', async () => {
    const other = await generateKeypair();
    const { key } = await mintKey({ privateKey: other.privateKey, sub: 'pay_4', now: NOW });
    assert.deepEqual(await verifyKey(key, { publicKeys: keys, now: NOW }), { ok: false, reason: 'unknown signer' });
    // Same kid, different key: the signature is what decides.
    const spoof = await mintKey({ privateKey: other.privateKey, sub: 'pay_4', kid: pair.kid, now: NOW });
    assert.deepEqual(await verifyKey(spoof.key, { publicKeys: keys, now: NOW }), { ok: false, reason: 'bad signature' });
  });

  it('honours a revocation list by subject', async () => {
    const { key } = await mintKey({ privateKey: pair.privateKey, sub: 'pay_5', now: NOW });
    assert.equal((await verifyKey(key, { publicKeys: keys, now: NOW, revoked: ['pay_9'] })).ok, true);
    assert.deepEqual(await verifyKey(key, { publicKeys: keys, now: NOW, revoked: new Set(['pay_5']) }), { ok: false, reason: 'revoked' });
  });

  it('never throws on garbage', async () => {
    for (const junk of [undefined, null, 42, '', 'pfs_', 'pfs_x', 'pfs_.sig', 'cp_abc.def', `${PREFIX}!!!.!!!`, `${PREFIX}${Buffer.from('[1]').toString('base64url')}.x`]) {
      const result = await verifyKey(junk, { publicKeys: keys });
      assert.equal(result.ok, false);
    }
    assert.equal(isPowerKey('pfs_abc.def'), true);
    assert.equal(isPowerKey('pfs_abcdef'), false);
    assert.equal(decodeKey('nope'), null);
  });
});

const { key: requestKey } = await mintKey({ privateKey: pair.privateKey, sub: 'pay_6', now: NOW });

describe('reading a key off a request', () => {
  const key = requestKey;

  it('reads the bearer, the header and x-api-key', () => {
    assert.equal(keyFrom(new Request('https://x/', { headers: { authorization: `Bearer ${key}` } })), key);
    assert.equal(keyFrom(new Request('https://x/', { headers: { [HEADER]: ` ${key} ` } })), key);
    assert.equal(keyFrom(new Request('https://x/', { headers: { 'x-api-key': key } })), key);
    assert.equal(keyFrom(new Headers({ authorization: `bearer ${key}` })), key);
  });

  it('ignores other credentials', () => {
    assert.equal(keyFrom(new Request('https://x/', { headers: { authorization: 'Bearer cp_abc.def' } })), null);
    assert.equal(keyFrom(new Request('https://x/', { headers: { 'x-api-key': 'sk_live_123' } })), null);
    assert.equal(keyFrom(new Request('https://x/')), null);
    assert.equal(keyFrom(null), null);
  });

  it('verifyRequest returns the claims or null', async () => {
    const good = await verifyRequest(new Request('https://x/', { headers: { authorization: `Bearer ${key}` } }), { publicKeys: keys, now: NOW });
    assert.equal(good?.sub, 'pay_6');
    assert.equal(await verifyRequest(new Request('https://x/'), { publicKeys: keys }), null);
    assert.equal(await verifyRequest(new Request('https://x/', { headers: { authorization: 'Bearer pfs_a.b' } }), { publicKeys: keys }), null);
  });
});
