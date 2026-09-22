/**
 * Profullstack's signing keys, by key id. A token names its `kid`, and this
 * is where a verifier looks it up. Rotation is adding a key here and shipping
 * a release; an old key stays until every token signed with it has expired,
 * which for a lifetime key means it stays.
 *
 * These are PUBLIC keys. The private halves are on profullstack.com only.
 */
export const PROFULLSTACK_KEYS = Object.freeze({
  // 2026-09-22, the first key. Signs everything sold at profullstack.com/shop.
  jLvYMNng: 'qrvW8CoCGQay-aO3F52XZ4b0jqi6C4F36MBz61FPvok',
});
