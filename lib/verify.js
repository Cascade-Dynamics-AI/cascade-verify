'use strict';
// Cascade receipt-bundle verifier. Node built-ins only; no network access.
// The format and the four checks are specified in SPEC.md.

const crypto = require('node:crypto');

const GENESIS = 'genesis';
// v1: SHA-256 truncated to 64 bits; v2: the full 256 bits (SPEC.md §2, §6).
const HASH_HEX_LEN = { 1: 16, 2: 64 };
const CHAIN_FORMAT_V2 = 'cascade-chain/2';
const SEAL_FORMAT_V2 = 'cascade-seal/2';
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
    seal: obj.seal === undefined ? null : obj.seal,
    anchor: obj.anchor === undefined ? null : obj.anchor,
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

// The chain hash of an entry body (the entry without hash and sig).
function entryHash(prev, rest, v = 1) {
  return crypto
    .createHash('sha256')
    .update(prev + JSON.stringify(rest), 'utf8')
    .digest('hex')
    .slice(0, HASH_HEX_LEN[v]);
}

// The exact bytes a seal signature covers: these five keys, in this order.
function sealMessage(s) {
  return JSON.stringify({ format: s.format, run: s.run, seq: s.seq, head: s.head, at: s.at });
}

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

function decodeSig(sig) {
  if (typeof sig !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(sig)) return null;
  const b = Buffer.from(sig, 'base64');
  return b.length === 64 ? b : null;
}

const elapsedMs = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;

// 1. Chain integrity: every entry re-hashes to its stored hash and links to
//    the previous entry's hash, starting from "genesis" (or a segment's
//    anchor). Each entry is checked by the rules of its own format (v1 = no
//    `v` field, v2 = `v: 2`); v2 adds position (`seq`), the run header, the
//    rollover boundary, and completeness against the signed seal (SPEC.md §6).
//    Entries are named by their position in the whole chain (= `seq` in v2).
function checkChain(chain, { seal = null, anchor = null } = {}) {
  const t0 = process.hrtime.bigint();
  const info = { formats: { v1: 0, v2: 0 }, segment: null, seal: null, notes: [] };
  const fail = (brokenAt, detail) => ({ pass: false, brokenAt, ms: elapsedMs(t0), detail, ...info });
  let prev = GENESIS, offset = 0, hdrRun;
  if (anchor !== null) {
    const first = chain[0];
    if (!isObj(anchor) || !Number.isInteger(anchor.seq) || anchor.seq < 1 || typeof anchor.hash !== 'string') {
      return fail(1, 'the bundle\'s anchor is malformed (expected {seq, hash})');
    }
    if (first.v !== 2 || first.seq !== anchor.seq + 1) {
      return fail(1, `the anchor names entry ${anchor.seq}, but the first entry is not v2 entry ${anchor.seq + 1}`);
    }
    prev = anchor.hash;
    offset = anchor.seq;
    info.segment = { from: offset + 1, to: offset + chain.length };
  }
  const prefix = crypto.createHash('sha256'); // v1 prefix digest, for a rollover header
  for (let i = 0; i < chain.length; i++) {
    const pos = offset + i + 1;
    const e = chain[i];
    const { hash, sig, ...rest } = e;
    if (e.v !== undefined && e.v !== 2) return fail(pos, `entry ${pos}: unknown format v=${JSON.stringify(e.v)}`);
    const v = e.v === 2 ? 2 : 1;
    if (v === 1 && info.formats.v2 > 0) {
      return fail(pos, `entry ${pos}: v1 entry after v2 entries (a format downgrade is never valid)`);
    }
    if (rest.prev !== prev) {
      return fail(pos, `entry ${pos}: prev is ${JSON.stringify(rest.prev)}, expected ${JSON.stringify(prev)}`);
    }
    const h = entryHash(prev, rest, v);
    if (h !== hash) {
      return fail(pos, `entry ${pos}: content hashes to ${h}, but the entry claims ${JSON.stringify(hash)}`);
    }
    if (v === 2) {
      if (e.seq !== pos) return fail(pos, `entry ${pos}: seq is ${JSON.stringify(e.seq)}, expected ${pos}`);
      if (info.formats.v2 === 0) {
        const hdr = e.hdr;
        if (hdr === undefined && info.segment && i === 0) {
          info.notes.push('the run header is before this segment and was not checked');
        } else if (!isObj(hdr) || hdr.format !== CHAIN_FORMAT_V2) {
          return fail(pos, `entry ${pos}: the first v2 entry has no run header`);
        } else {
          hdrRun = hdr.run;
          const ro = hdr.rollover;
          if (pos === 1) {
            if (ro !== undefined) return fail(pos, `entry ${pos}: a rollover header on the first entry`);
          } else if (!isObj(ro) || ro.from_format !== 1 || ro.entries !== pos - 1 || ro.head !== prev) {
            return fail(pos, `entry ${pos}: the rollover header does not match the ${pos - 1} v1 entries before it`);
          } else if (info.segment) {
            info.notes.push('the v1 prefix before the rollover is not in this segment and was not checked');
          } else if (ro.prefix_sha256 !== prefix.digest('hex')) {
            return fail(pos, `entry ${pos}: the rollover header's prefix_sha256 does not match entries 1-${pos - 1}`);
          }
        }
      } else if (e.hdr !== undefined) {
        return fail(pos, `entry ${pos}: a run header on a later entry`);
      }
      info.formats.v2++;
    } else {
      prefix.update(JSON.stringify(e) + '\n', 'utf8');
      info.formats.v1++;
    }
    prev = hash;
  }
  // Completeness against the signed seal (its signature is check 2).
  const n = offset + chain.length;
  const lastV2 = chain[chain.length - 1].v === 2;
  if (seal === null) {
    if (lastV2) return fail(null, 'the bundle has no seal, so nothing shows the chain is complete (required for v2)');
    info.notes.push('no seal: entries dropped from the end of a v1 bundle would not be detected');
  } else {
    if (!isObj(seal) || seal.format !== SEAL_FORMAT_V2 || !Number.isInteger(seal.seq) || seal.seq < 1 ||
        typeof seal.head !== 'string') {
      return fail(null, 'the seal is malformed (expected {format, run, seq, head, at, sig})');
    }
    info.seal = { seq: seal.seq, at: seal.at === undefined ? null : seal.at };
    if (hdrRun !== undefined && hdrRun !== null && seal.run !== hdrRun) {
      return fail(null, `the seal is for run ${JSON.stringify(seal.run)}, the chain header says ${JSON.stringify(hdrRun)}`);
    }
    if (seal.seq > n) {
      return fail(n + 1, `entries ${n + 1}-${seal.seq} are missing: the signed seal commits to ${seal.seq} entries, the bundle ends at entry ${n}`);
    }
    if (seal.seq <= offset) {
      return fail(null, `the seal covers entries up to ${seal.seq}, before this segment starts at ${offset + 1}`);
    }
    const at = chain[seal.seq - offset - 1];
    if (at.hash !== seal.head) {
      return fail(seal.seq, `entry ${seal.seq}: its hash differs from the head the signed seal commits to`);
    }
    if (seal.seq < n) info.notes.push(`the seal covers entries up to ${seal.seq}; entries ${seal.seq + 1}-${n} are newer than it`);
  }
  const span = info.segment ? `entries ${info.segment.from}-${info.segment.to} (a segment)` : `${chain.length} links walked from genesis`;
  const sealed = info.seal ? `; sealed at entry ${info.seal.seq}` : '';
  return { pass: true, brokenAt: null, ms: elapsedMs(t0), head: prev, ...info,
    detail: `${span}; head ${prev}${sealed}` };
}

// 2. Signatures: EVERY entry must carry an Ed25519 signature over its hash
//    string that verifies under the pinned key. A missing signature FAILS;
//    skipping unsigned entries would let anyone strip the signatures, edit
//    entries, rebuild the hash links and pass.
//    A seal, when the bundle has one, must also be signed by the pinned key.
function checkSignatures(chain, keyObject, { seal = null, anchor = null } = {}) {
  const t0 = process.hrtime.bigint();
  const offset = isObj(anchor) && Number.isInteger(anchor.seq) ? anchor.seq : 0;
  for (let i = 0; i < chain.length; i++) {
    const pos = offset + i + 1;
    const e = chain[i];
    if (typeof e.sig !== 'string' || !e.sig) {
      return { pass: false, brokenAt: pos, ms: elapsedMs(t0),
        detail: `entry ${pos} has no signature; every entry must be signed` };
    }
    const sig = decodeSig(e.sig);
    const good = sig !== null && typeof e.hash === 'string' &&
      crypto.verify(null, Buffer.from(e.hash, 'utf8'), keyObject, sig);
    if (!good) {
      return { pass: false, brokenAt: pos, ms: elapsedMs(t0),
        detail: `entry ${pos}: signature does not verify under the pinned key` };
    }
  }
  if (seal !== null) {
    const sig = isObj(seal) ? decodeSig(seal.sig) : null;
    const good = sig !== null && crypto.verify(null, Buffer.from(sealMessage(seal), 'utf8'), keyObject, sig);
    if (!good) {
      return { pass: false, brokenAt: null, ms: elapsedMs(t0),
        detail: 'the seal\'s signature does not verify under the pinned key' };
    }
  }
  return { pass: true, brokenAt: null, ms: elapsedMs(t0),
    detail: `${chain.length} of ${chain.length} signatures verified${seal !== null ? ', and the seal' : ''}` };
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
  const ctx = { seal: bundle.seal === undefined ? null : bundle.seal, anchor: bundle.anchor === undefined ? null : bundle.anchor };
  const chainResult = checkChain(chain, ctx);
  const results = [
    chainResult,
    checkSignatures(chain, keyObject, ctx),
    checkExclusivity(chain),
    checkZeroTokens(chain),
  ].map((r, i) => ({ ...CHECKS[i], ...r }));
  const totalMs = elapsedMs(t0);
  const { formats, segment, seal, notes } = chainResult;
  return {
    pass: results.every((r) => r.pass),
    entries: chain.length,
    formats, segment, seal, notes,
    checks: results,
    totalMs,
    entriesPerSec: totalMs > 0 ? Math.round(chain.length / (totalMs / 1000)) : null,
  };
}

module.exports = {
  InputError, parseBundle, loadPublicKey, verifyBundle, entryHash, sealMessage,
  checkChain, checkSignatures, checkExclusivity, checkZeroTokens, CHECKS, GENESIS,
  CHAIN_FORMAT_V2, SEAL_FORMAT_V2,
};
