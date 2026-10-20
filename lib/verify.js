'use strict';
// Cascade receipt-bundle verifier. Node built-ins only; no network access.
// The format and the four checks are specified in SPEC.md.

const crypto = require('node:crypto');

const GENESIS = 'genesis';
const HASH_HEX_LEN = 16; // format v1: SHA-256 truncated to 64 bits (see SPEC.md)
// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32-byte raw key follows it.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

class InputError extends Error {}

// Parse bundle JSON text into {run, chain, publicKey}. Throws InputError on
// anything that is not a non-empty bundle of object entries.
function parseBundle(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    throw new InputError(`not valid JSON (${e.message})`);
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new InputError('not a bundle: expected a JSON object with a "chain" array');
  }
  const chain = Array.isArray(obj.chain) ? obj.chain : Array.isArray(obj.entries) ? obj.entries : null;
  if (!chain) throw new InputError('not a bundle: no "chain" (or "entries") array');
  if (!chain.length) throw new InputError('the bundle has no entries to check');
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      throw new InputError(`entry ${i + 1} is not a JSON object`);
    }
  }
  return {
    run: obj.run || obj.run_id || null,
    chain,
    publicKey: obj.public_key || obj.publicKey || null,
  };
}

// Accepts a PEM block, base64 SPKI DER, or a base64 raw 32-byte Ed25519 key.
// Returns {keyObject, spkiB64}. Throws InputError if it is not an Ed25519 key.
function loadPublicKey(str) {
  const s = String(str || '');
  const m = s.match(/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/);
  const b64 = (m ? m[1] : s).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
    throw new InputError('key is not a PEM block or base64 Ed25519 public key');
  }
  let der = Buffer.from(b64, 'base64');
  if (der.length === 32) der = Buffer.concat([ED25519_SPKI_PREFIX, der]);
  let keyObject;
  try {
    keyObject = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (e) {
    throw new InputError(`key could not be parsed (${e.message})`);
  }
  if (keyObject.asymmetricKeyType !== 'ed25519') {
    throw new InputError(`key is ${keyObject.asymmetricKeyType}, not Ed25519`);
  }
  const spki = keyObject.export({ format: 'der', type: 'spki' });
  return { keyObject, spkiB64: spki.toString('base64') };
}

function entryHash(prev, rest) {
  return crypto
    .createHash('sha256')
    .update(prev + JSON.stringify(rest), 'utf8')
    .digest('hex')
    .slice(0, HASH_HEX_LEN);
}

function decodeSig(sig) {
  if (typeof sig !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(sig)) return null;
  const b = Buffer.from(sig, 'base64');
  return b.length === 64 ? b : null;
}

const elapsedMs = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;

// 1. Chain integrity: every entry re-hashes to its stored hash and links to
//    the previous entry's hash, starting from "genesis".
function checkChain(chain) {
  const t0 = process.hrtime.bigint();
  let prev = GENESIS;
  for (let i = 0; i < chain.length; i++) {
    const { hash, sig, ...rest } = chain[i];
    if (rest.prev !== prev) {
      return { pass: false, brokenAt: i + 1, ms: elapsedMs(t0),
        detail: `entry ${i + 1}: prev is ${JSON.stringify(rest.prev)}, expected ${JSON.stringify(prev)}` };
    }
    const h = entryHash(prev, rest);
    if (h !== hash) {
      return { pass: false, brokenAt: i + 1, ms: elapsedMs(t0),
        detail: `entry ${i + 1}: content hashes to ${h}, but the entry claims ${JSON.stringify(hash)}` };
    }
    prev = hash;
  }
  return { pass: true, brokenAt: null, ms: elapsedMs(t0), head: prev,
    detail: `${chain.length} links walked from genesis; head ${prev}` };
}

// 2. Signatures: EVERY entry must carry an Ed25519 signature over its hash
//    string that verifies under the pinned key. A missing signature FAILS;
//    skipping unsigned entries would let anyone strip the signatures, edit
//    entries, rebuild the hash links and pass.
function checkSignatures(chain, keyObject) {
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    if (typeof e.sig !== 'string' || !e.sig) {
      return { pass: false, brokenAt: i + 1, ms: elapsedMs(t0),
        detail: `entry ${i + 1} has no signature; every entry must be signed` };
    }
    const sig = decodeSig(e.sig);
    const good = sig !== null && typeof e.hash === 'string' &&
      crypto.verify(null, Buffer.from(e.hash, 'utf8'), keyObject, sig);
    if (!good) {
      return { pass: false, brokenAt: i + 1, ms: elapsedMs(t0),
        detail: `entry ${i + 1}: signature does not verify under the pinned key` };
    }
  }
  return { pass: true, brokenAt: null, ms: elapsedMs(t0),
    detail: `${chain.length} of ${chain.length} signatures verified` };
}

// 3. Exclusivity: replay ASSIGN/RELEASE; an ASSIGN of a cell currently held
//    by a different agent is a duplicate grant.
function checkExclusivity(chain) {
  const t0 = process.hrtime.bigint();
  const held = new Map();
  let dupes = 0, assigns = 0, firstAt = null;
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    if (e.verb === 'ASSIGN') {
      assigns++;
      const holder = held.get(e.cell);
      if (holder && holder !== e.agent) {
        dupes++;
        if (firstAt === null) firstAt = { at: i + 1, cell: e.cell, agent: e.agent, holder };
      }
      held.set(e.cell, e.agent);
    } else if (e.verb === 'RELEASE') {
      held.delete(e.cell);
    }
  }
  return {
    pass: dupes === 0, brokenAt: firstAt ? firstAt.at : null, ms: elapsedMs(t0),
    detail: dupes === 0
      ? `0 duplicate grants across ${assigns} ASSIGNs`
      : `${dupes} duplicate grant(s); first at entry ${firstAt.at}: ${JSON.stringify(firstAt.cell)} ` +
        `granted to ${JSON.stringify(firstAt.agent)} while held by ${JSON.stringify(firstAt.holder)}`,
  };
}

// 4. Zero tokens: no entry records tokens_used > 0 or names a model.
function checkZeroTokens(chain) {
  const t0 = process.hrtime.bigint();
  let count = 0, firstAt = null;
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    const paid = Number(e.tokens_used) > 0 ||
      (e.model !== undefined && e.model !== null && e.model !== '' && e.model !== false);
    if (paid) {
      count++;
      if (firstAt === null) firstAt = i + 1;
    }
  }
  return {
    pass: count === 0, brokenAt: firstAt, ms: elapsedMs(t0),
    detail: count === 0
      ? 'no entry records model tokens or names a model'
      : `${count} entr${count === 1 ? 'y' : 'ies'} record model tokens or a model; first at entry ${firstAt}`,
  };
}

const CHECKS = [
  { id: 'chain', title: 'Chain integrity' },
  { id: 'signatures', title: 'Signatures' },
  { id: 'exclusivity', title: 'Exclusivity' },
  { id: 'zero_tokens', title: 'Zero tokens' },
];

// Run all four checks. All four always run, so one report shows every
// failure; each failing check names its first broken entry (1-based).
function verifyBundle(bundle, keyObject) {
  const t0 = process.hrtime.bigint();
  const { chain } = bundle;
  const results = [
    checkChain(chain),
    checkSignatures(chain, keyObject),
    checkExclusivity(chain),
    checkZeroTokens(chain),
  ].map((r, i) => ({ ...CHECKS[i], ...r }));
  const totalMs = elapsedMs(t0);
  return {
    pass: results.every((r) => r.pass),
    entries: chain.length,
    checks: results,
    totalMs,
    entriesPerSec: totalMs > 0 ? Math.round(chain.length / (totalMs / 1000)) : null,
  };
}

module.exports = {
  InputError, parseBundle, loadPublicKey, verifyBundle, entryHash,
  checkChain, checkSignatures, checkExclusivity, checkZeroTokens, CHECKS, GENESIS,
};
