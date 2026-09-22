/**
 * @profullstack/keys: one key for every Profullstack service.
 *
 * A Power Key is a signed, self-describing token, `pfs_<payload>.<signature>`,
 * carrying who it was issued to, what plan it is on and when (if ever) it
 * expires. It is minted once, at profullstack.com/shop, with a private key that
 * lives only there. Every other property verifies it OFFLINE with the public
 * half, which ships in this package: no shared database, no callback to a
 * central server on the request path, nothing for fifty sites to agree on
 * except a public key.
 *
 * Ed25519 over Web Crypto, which is what Node 20+, Bun and every edge runtime
 * have in common. Nothing here imports node:.
 */

import { PROFULLSTACK_KEYS } from './keys.js';

export { PROFULLSTACK_KEYS } from './keys.js';

/** Token prefix. A key never starts with anything else. */
export const PREFIX = 'pfs_';

/** Header a client may put the key in, besides `Authorization: Bearer`. */
export const HEADER = 'x-power-key';

/** Where a key is bought. Advertised by anything that refuses for lack of one. */
export const SHOP_URL = 'https://profullstack.com/shop';

const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64Url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(s) {
  const bin = atob(String(s).replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
}

const ALG = { name: 'Ed25519' };

async function importPublic(x) {
  return crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x }, ALG, false, ['verify']);
}

function splitPrivate(privateKey) {
  const dot = String(privateKey).indexOf('.');
  if (dot < 0) throw new Error('a private key is "<public>.<secret>", as generateKeypair() returns it');
  return { x: privateKey.slice(0, dot), d: privateKey.slice(dot + 1) };
}

async function importPrivate(privateKey) {
  const { x, d } = splitPrivate(privateKey);
  return crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x, d }, ALG, false, ['sign']);
}

/** A short key id from a public key, so a token names which key signed it. */
export async function keyIdFor(publicKey) {
  const digest = await crypto.subtle.digest('SHA-256', fromBase64Url(publicKey));
  return toBase64Url(new Uint8Array(digest).slice(0, 6));
}

/**
 * Make a signing pair.
 *
 * Returns base64url strings: `publicKey` goes into the verifying side's key
 * list, `privateKey` (which carries the public half too, so it can be
 * imported on its own) stays wherever keys are minted. `kid` is derived from
 * the public key and is what a token carries.
 */
export async function generateKeypair() {
  const pair = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { kid: await keyIdFor(jwk.x), publicKey: jwk.x, privateKey: `${jwk.x}.${jwk.d}` };
}

/** Is this string shaped like a Power Key? Says nothing about validity. */
export function isPowerKey(token) {
  return typeof token === 'string' && token.startsWith(PREFIX) && token.indexOf('.') > PREFIX.length;
}

/**
 * Mint a key.
 *
 * @param {object} args
 * @param {string} args.privateKey   from generateKeypair()
 * @param {string} args.sub          who it is for: an order or payment reference, never an email
 * @param {string} [args.plan]       'lifetime' (default) or anything the shop sells
 * @param {number|null} [args.exp]   unix seconds; null (default) never expires
 * @param {string} [args.scope]      '*' (default) or a space-separated list of services
 * @param {string} [args.kid]        overrides the key id derived from the public half
 * @param {number} [args.now]        unix seconds, for tests
 */
export async function mintKey({
  privateKey,
  sub,
  plan = 'lifetime',
  exp = null,
  scope = '*',
  kid,
  now = Math.floor(Date.now() / 1000),
}) {
  if (!privateKey) throw new Error('minting needs a private key');
  if (!sub || typeof sub !== 'string') throw new Error('a key needs a subject');
  if (exp !== null && (!Number.isFinite(exp) || exp <= now)) throw new Error('exp must be a future unix time or null');
  const key = await importPrivate(privateKey);
  const claims = {
    v: 1,
    kid: kid ?? (await keyIdFor(splitPrivate(privateKey).x)),
    sub,
    plan,
    scope,
    iat: now,
    exp,
  };
  const payload = toBase64Url(enc.encode(JSON.stringify(claims)));
  const signed = `${PREFIX}${payload}`;
  const sig = await crypto.subtle.sign(ALG, key, enc.encode(signed));
  return { key: `${signed}.${toBase64Url(new Uint8Array(sig))}`, claims };
}

/**
 * Read the claims off a key WITHOUT verifying it. For display and for
 * deciding which public key to try; never for granting anything.
 */
export function decodeKey(token) {
  if (!isPowerKey(token)) return null;
  try {
    const payload = token.slice(PREFIX.length, token.indexOf('.'));
    const claims = JSON.parse(dec.decode(fromBase64Url(payload)));
    return claims && typeof claims === 'object' && !Array.isArray(claims) ? claims : null;
  } catch {
    return null;
  }
}

/**
 * Verify a key. Resolves to `{ ok: true, claims }` or `{ ok: false, reason }`
 * and never throws: a token is untrusted text off the wire.
 *
 * @param {string} token
 * @param {object} [options]
 * @param {Record<string,string>} [options.publicKeys]   kid -> base64url public key; defaults to Profullstack's
 * @param {Iterable<string>} [options.revoked]           subjects no longer honoured
 * @param {number} [options.now]                         unix seconds, for tests
 */
export async function verifyKey(
  token,
  { publicKeys = PROFULLSTACK_KEYS, revoked, now = Math.floor(Date.now() / 1000) } = {},
) {
  if (!isPowerKey(token)) return { ok: false, reason: 'not a key' };
  const dot = token.indexOf('.');
  const signed = token.slice(0, dot);
  const sigPart = token.slice(dot + 1);
  const claims = decodeKey(token);
  if (!claims || claims.v !== 1 || typeof claims.kid !== 'string' || typeof claims.sub !== 'string') {
    return { ok: false, reason: 'malformed' };
  }
  const publicKey = publicKeys?.[claims.kid];
  if (!publicKey) return { ok: false, reason: 'unknown signer' };
  let valid = false;
  try {
    const key = await importPublic(publicKey);
    valid = await crypto.subtle.verify(ALG, key, fromBase64Url(sigPart), enc.encode(signed));
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: 'bad signature' };
  if (claims.exp !== null && claims.exp !== undefined && (!Number.isFinite(claims.exp) || claims.exp <= now)) {
    return { ok: false, reason: 'expired' };
  }
  if (revoked) {
    const set = revoked instanceof Set ? revoked : new Set(revoked);
    if (set.has(claims.sub)) return { ok: false, reason: 'revoked' };
  }
  return { ok: true, claims };
}

/**
 * The key a request presents, if any: `Authorization: Bearer pfs_...`,
 * the `x-power-key` header, or `x-api-key` when it holds a Power Key.
 * Accepts a Request or a Headers.
 */
export function keyFrom(requestOrHeaders) {
  const headers = requestOrHeaders?.headers ?? requestOrHeaders;
  if (!headers || typeof headers.get !== 'function') return null;
  const direct = headers.get(HEADER)?.trim();
  if (isPowerKey(direct)) return direct;
  const auth = (headers.get('authorization') ?? '').trim();
  const m = /^Bearer\s+(pfs_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(auth);
  if (m) return m[1];
  const apiKey = headers.get('x-api-key')?.trim();
  return isPowerKey(apiKey) ? apiKey : null;
}

/** `keyFrom` + `verifyKey` in one call: the claims, or null. */
export async function verifyRequest(request, options) {
  const token = keyFrom(request);
  if (!token) return null;
  const result = await verifyKey(token, options);
  return result.ok ? result.claims : null;
}
