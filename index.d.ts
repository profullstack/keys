/** Claims carried by a Power Key. */
export interface KeyClaims {
  v: 1;
  /** Which signing key made it; looked up in `publicKeys`. */
  kid: string;
  /** Who it is for: an order or payment reference, never an email. */
  sub: string;
  /** 'lifetime', or whatever the shop sold. */
  plan: string;
  /** '*' or a space-separated list of services. */
  scope: string;
  /** Issued at, unix seconds. */
  iat: number;
  /** Expiry, unix seconds, or null for never. */
  exp: number | null;
}

export type VerifyResult = { ok: true; claims: KeyClaims } | { ok: false; reason: 'not a key' | 'malformed' | 'unknown signer' | 'bad signature' | 'expired' | 'revoked' };

export interface VerifyOptions {
  /** kid -> base64url Ed25519 public key. Defaults to Profullstack's keys. */
  publicKeys?: Record<string, string>;
  /** Subjects no longer honoured. */
  revoked?: Iterable<string>;
  /** Unix seconds, for tests. */
  now?: number;
}

export interface MintArgs {
  /** From generateKeypair(): "<public>.<secret>". */
  privateKey: string;
  sub: string;
  plan?: string;
  exp?: number | null;
  scope?: string;
  kid?: string;
  now?: number;
}

/** Token prefix, `pfs_`. */
export const PREFIX: string;
/** Header a client may put the key in, `x-power-key`. */
export const HEADER: string;
/** Where a key is bought. */
export const SHOP_URL: string;
/** Profullstack's public keys, by kid. */
export const PROFULLSTACK_KEYS: Readonly<Record<string, string>>;

export function generateKeypair(): Promise<{ kid: string; publicKey: string; privateKey: string }>;
export function keyIdFor(publicKey: string): Promise<string>;
export function isPowerKey(token: unknown): token is string;
export function mintKey(args: MintArgs): Promise<{ key: string; claims: KeyClaims }>;
export function decodeKey(token: string): KeyClaims | null;
export function verifyKey(token: string, options?: VerifyOptions): Promise<VerifyResult>;
export function keyFrom(requestOrHeaders: Request | Headers | { headers: Headers }): string | null;
export function verifyRequest(request: Request | Headers | { headers: Headers }, options?: VerifyOptions): Promise<KeyClaims | null>;
