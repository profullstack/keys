# @profullstack/keys

One key for every Profullstack service.

A Power Key is bought once at [profullstack.com/shop](https://profullstack.com/shop) and opens every Profullstack property: no crawler paywall, no rate limit, no per-site pass. It is an Ed25519-signed token, `pfs_<payload>.<signature>`, that carries its own plan and expiry. Any site verifies it offline with the public key that ships in this package. There is no shared database and nothing is called on the request path.

```
npm install @profullstack/keys
```

Runs in Node 20+, Bun and at the edge. Zero dependencies, Web Crypto only.

## Honour a key

```js
import { verifyRequest } from '@profullstack/keys';

// Hono, Next.js middleware, Bun.serve, anything with a Request.
const claims = await verifyRequest(request);
if (claims) {
  // claims.sub   the order it was issued to
  // claims.plan  'lifetime'
  // claims.exp   null for lifetime, unix seconds otherwise
}
```

A client sends the key as `Authorization: Bearer pfs_...`, as an `x-power-key` header, or as `x-api-key`. `verifyRequest` reads all three and returns the claims, or `null` when there is no key or it does not verify.

For finer control:

```js
import { keyFrom, verifyKey } from '@profullstack/keys';

const token = keyFrom(request);              // string | null
const result = await verifyKey(token, {
  revoked: ['pay_abc'],                       // subjects you no longer honour
});
// { ok: true, claims } or { ok: false, reason: 'expired' | 'revoked' | 'bad signature' | ... }
```

`verifyKey` never throws. A token is untrusted text off the wire.

## Sites that already honour it

`@profullstack/x402-gateway` 0.7.0 and up treats a valid Power Key as a paid pass, and `@profullstack/throttle` skips metering for it. Every property running either honours a key with no code of its own.

## Mint a key

Only the shop does this. The private key lives on profullstack.com and nowhere else.

```js
import { generateKeypair, mintKey } from '@profullstack/keys';

const { kid, publicKey, privateKey } = await generateKeypair();
// publicKey goes into src/keys.js and ships; privateKey goes into the vault.

const { key } = await mintKey({ privateKey, sub: 'pay_abc', plan: 'lifetime' });
// pfs_eyJ2IjoxLCJraWQiOi...  give it to the buyer once
```

`privateKey` is `"<public>.<secret>"` so it imports on its own. `sub` is an order or payment reference, never an email: the token is what the buyer carries around, and it should not carry them.

## Rotation

Add the new public key to `PROFULLSTACK_KEYS`, release, then start signing with it. The old key stays in the list until every token signed with it has expired. A lifetime key never expires, so the old key stays.

Revocation is by subject: pass `revoked` with the subjects of refunded or leaked keys. profullstack.com publishes the current list at `/keys/revoked.json`.

## API

| Export | What |
| --- | --- |
| `verifyRequest(request, options?)` | claims or null |
| `keyFrom(request \| headers)` | the token a request presents, or null |
| `verifyKey(token, options?)` | `{ ok, claims }` or `{ ok: false, reason }` |
| `decodeKey(token)` | claims without verification, for display |
| `isPowerKey(token)` | shaped like a key |
| `mintKey({ privateKey, sub, plan?, exp?, scope? })` | a signed key |
| `generateKeypair()` | `{ kid, publicKey, privateKey }` |
| `PROFULLSTACK_KEYS` | kid to public key, what `verifyKey` uses by default |
| `PREFIX`, `HEADER`, `SHOP_URL` | `pfs_`, `x-power-key`, where to buy one |

## Licence

MIT
