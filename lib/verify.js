'use strict';
// Cascade receipt-bundle verifier. Node built-ins only; no network access.
// The format and the four checks are specified in SPEC.md.

const crypto = require('node:crypto');

const GENESIS = 'genesis';
// v1: SHA-256 truncated to 64 bits; v2: the full 256 bits (SPEC.md §2, §6).
const HASH_HEX_LEN = { 1: 16, 2: 64 };
const CHAIN_FORMAT_V2 = 'cascade-chain/2';
const SEAL_FORMAT_V2 = 'cascade-seal/2';
// Session keys (SPEC.md §7): a root key certifies short-lived session keys;
// entries and seals signed by one name it with `kid`.
const SEAL_FORMAT_V3 = 'cascade-seal/3';
const CERT_FORMAT = 'cascade-key-cert/1';
const ANCHOR_FORMAT = 'cascade-anchor/1';
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
    certs: Array.isArray(obj.certs) ? obj.certs : [],
    anchors: Array.isArray(obj.anchors) ? obj.anchors : [],
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
  return { keyObject, spkiB64: spki.toString('base64'), id: keyId(spki) };
}

// A key's id: the first 16 hex of SHA-256 over its SPKI DER. Session certs
// name themselves (`kid`) and their root (`root`) this way.
function keyId(spkiDer) {
  return crypto.createHash('sha256').update(spkiDer).digest('hex').slice(0, 16);
}

// The keys a verification trusts (SPEC.md §4, §7):
//   roots: keys that certify session keys (and sign anchors)
//   plain: keys that sign entries directly, with no `kid` (a legacy
//          production key, or an on-prem deployment's own key)
// Accepts a keyring, or a bare KeyObject (the 0.2 API: one plain key).
function toKeyring(k) {
  if (k && typeof k === 'object' && (Array.isArray(k.roots) || Array.isArray(k.plain))) {
    return { roots: k.roots || [], plain: k.plain || [] };
  }
  const spki = k.export({ format: 'der', type: 'spki' });
  return { roots: [], plain: [{ keyObject: k, spkiB64: spki.toString('base64'), id: keyId(spki) }] };
}

// The chain hash of an entry body (the entry without hash and sig).
function entryHash(prev, rest, v = 1) {
  return crypto
    .createHash('sha256')
    .update(prev + JSON.stringify(rest), 'utf8')
    .digest('hex')
    .slice(0, HASH_HEX_LEN[v]);
}

// The exact bytes a seal signature covers: these five keys, in this order
// (seal/2), plus the signing session key's `kid` (seal/3).
function sealMessage(s) {
  if (s.format === SEAL_FORMAT_V3) {
    return JSON.stringify({ format: s.format, run: s.run, seq: s.seq, head: s.head, at: s.at, kid: s.kid });
  }
  return JSON.stringify({ format: s.format, run: s.run, seq: s.seq, head: s.head, at: s.at });
}

// The exact bytes a root signs to certify a session key: these six keys, in
// this order.
function certMessage(c) {
  return JSON.stringify({ format: c.format, kid: c.kid, key: c.key, root: c.root,
    not_before: c.not_before, not_after: c.not_after });
}

// The exact bytes a root signs for an anchor: these five keys, in this order.
function anchorMessage(a) {
  return JSON.stringify({ format: a.format, at: a.at, count: a.count, merkle_root: a.merkle_root,
    cutover: a.cutover === true });
}

// Merkle tree over chain heads (SPEC.md §8). Domain-separated so a leaf can
// never be read as a node: leaf = H("leaf:" + JSON{run,seq,head}),
// node = H("node:" + left + right). An odd node is carried up unchanged.
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
function anchorLeaf(leaf) {
  return sha256hex('leaf:' + JSON.stringify({ run: leaf.run, seq: leaf.seq, head: leaf.head }));
}
function merkleNode(left, right) { return sha256hex('node:' + left + right); }
// Walk an inclusion proof ([{side: 'L'|'R', hash}], leaf to root).
function merkleRootFromProof(leafHash, proof) {
  let h = leafHash;
  for (const step of proof) {
    if (!isObj(step) || typeof step.hash !== 'string' || (step.side !== 'L' && step.side !== 'R')) return null;
    h = step.side === 'L' ? merkleNode(step.hash, h) : merkleNode(h, step.hash);
  }
  return h;
}

// Check every session cert the bundle carries against the root keys. Returns
// {byKid: Map(kid -> {cert, keyObject}), error}. Certs no entry uses are still
// checked: a bundle should carry nothing that does not verify.
function loadCerts(certs, roots) {
  const byKid = new Map();
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i];
    const name = `session cert ${i + 1}`;
    if (!isObj(c) || c.format !== CERT_FORMAT || typeof c.kid !== 'string' || typeof c.key !== 'string' ||
        typeof c.root !== 'string' || typeof c.not_before !== 'string' || typeof c.not_after !== 'string') {
      return { byKid, error: `${name} is malformed (expected {format, kid, key, root, not_before, not_after, root_sig})` };
    }
    let k;
    try { k = loadPublicKey(c.key); } catch (e) { return { byKid, error: `${name} (${c.kid}): ${e.message}` }; }
    if (k.id !== c.kid) return { byKid, error: `${name}: kid ${c.kid} is not the id of its key (${k.id})` };
    const root = roots.find((r) => r.id === c.root);
    if (!root) return { byKid, error: `${name} (${c.kid}) is certified by root ${c.root}, which is not a pinned root key` };
    const sig = decodeSig(c.root_sig);
    if (!sig || !crypto.verify(null, Buffer.from(certMessage(c), 'utf8'), root.keyObject, sig)) {
      return { byKid, error: `${name} (${c.kid}): the root signature does not verify under root ${root.id}` };
    }
    if (!(Date.parse(c.not_before) < Date.parse(c.not_after))) {
      return { byKid, error: `${name} (${c.kid}): not_before is not before not_after` };
    }
    byKid.set(c.kid, { cert: c, keyObject: k.keyObject });
  }
  return { byKid, error: null };
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
    if (v === 1 && e.kid !== undefined) {
      return fail(pos, `entry ${pos}: a session-key kid on a v1 entry (session keys sign v2 entries only)`);
    }
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
    if (!isObj(seal) || (seal.format !== SEAL_FORMAT_V2 && seal.format !== SEAL_FORMAT_V3) ||
        !Number.isInteger(seal.seq) || seal.seq < 1 || typeof seal.head !== 'string' ||
        (seal.format === SEAL_FORMAT_V3 && typeof seal.kid !== 'string')) {
      return fail(null, 'the seal is malformed (expected {format, run, seq, head, at, sig}, plus kid for cascade-seal/3)');
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
//    string. A missing signature FAILS; skipping unsigned entries would let
//    anyone strip the signatures, edit entries, rebuild the hash links and pass.
//    - An entry with `kid` is signed by that session key, whose cert must be
//      in the bundle and certified by a pinned root (SPEC.md §7). Session keys
//      only move forward: an entry signed by an older session key after a
//      newer one fails.
//    - An entry without `kid` must verify under a pinned plain key (a legacy
//      production key, or an on-prem deployment's own key). Plain entries may
//      only come before the first session-signed entry: once a chain is
//      session-signed, the plain key never signs it again.
//    The seal must be signed the same way: seal/3 by a session key whose cert
//    window contains the seal's time, seal/2 by a plain key (legacy only).
function checkSignatures(chain, keys, { seal = null, anchor = null, certs = [] } = {}) {
  const t0 = process.hrtime.bigint();
  const { roots, plain } = toKeyring(keys);
  const offset = isObj(anchor) && Number.isInteger(anchor.seq) ? anchor.seq : 0;
  const fail = (brokenAt, detail) => ({ pass: false, brokenAt, ms: elapsedMs(t0), detail, keys: used });
  const used = { plain: [], sessions: [] };
  const { byKid, error } = loadCerts(certs, roots);
  if (error) return fail(null, error);
  let current = null;           // the newest session cert seen so far along the chain
  let plainCount = 0, sessionCount = 0;
  const verifyWith = (keyObject, msg, sig) => crypto.verify(null, Buffer.from(msg, 'utf8'), keyObject, sig);
  const plainMatch = (msg, sig) => plain.find((k) => verifyWith(k.keyObject, msg, sig));
  for (let i = 0; i < chain.length; i++) {
    const pos = offset + i + 1;
    const e = chain[i];
    if (typeof e.sig !== 'string' || !e.sig) return fail(pos, `entry ${pos} has no signature; every entry must be signed`);
    const sig = decodeSig(e.sig);
    if (sig === null || typeof e.hash !== 'string') return fail(pos, `entry ${pos}: the signature is malformed`);
    if (e.kid !== undefined) {
      const s = byKid.get(e.kid);
      if (!s) return fail(pos, `entry ${pos} is signed by session key ${JSON.stringify(e.kid)}, but the bundle has no cert for it`);
      if (current && current.cert.kid !== e.kid && Date.parse(s.cert.not_before) < Date.parse(current.cert.not_before)) {
        return fail(pos, `entry ${pos} is signed by session key ${e.kid}, which is older than ${current.cert.kid} used before it`);
      }
      if (!verifyWith(s.keyObject, e.hash, sig)) return fail(pos, `entry ${pos}: signature does not verify under session key ${e.kid}`);
      if (!used.sessions.includes(e.kid)) used.sessions.push(e.kid);
      current = s;
      sessionCount++;
    } else {
      if (current) {
        return fail(pos, `entry ${pos} has no session key after session-signed entries (the plain key never signs a chain again once session keys have)`);
      }
      if (!plain.length) return fail(pos, `entry ${pos} is signed directly, but no plain key is pinned`);
      const k = plainMatch(e.hash, sig);
      if (!k) return fail(pos, `entry ${pos}: signature does not verify under the pinned key${plain.length > 1 ? 's' : ''}`);
      if (!used.plain.includes(k.id)) used.plain.push(k.id);
      plainCount++;
    }
  }
  if (seal !== null) {
    const sig = isObj(seal) ? decodeSig(seal.sig) : null;
    if (sig === null) return fail(null, 'the seal\'s signature is missing or malformed');
    if (seal.format === SEAL_FORMAT_V3) {
      const s = byKid.get(seal.kid);
      if (!s) return fail(null, `the seal is signed by session key ${JSON.stringify(seal.kid)}, but the bundle has no cert for it`);
      const at = Date.parse(seal.at);
      if (!(at >= Date.parse(s.cert.not_before) && at <= Date.parse(s.cert.not_after))) {
        return fail(null, `the seal's time ${seal.at} is outside session key ${seal.kid}'s window (${s.cert.not_before} to ${s.cert.not_after})`);
      }
      if (current && Date.parse(s.cert.not_before) < Date.parse(current.cert.not_before)) {
        return fail(null, `the seal is signed by session key ${seal.kid}, older than ${current.cert.kid} that signed entries`);
      }
      if (!verifyWith(s.keyObject, sealMessage(seal), sig)) return fail(null, `the seal's signature does not verify under session key ${seal.kid}`);
      if (!used.sessions.includes(seal.kid)) used.sessions.push(seal.kid);
    } else {
      if (current) return fail(null, 'the seal is signed directly, but the chain is session-signed (a cascade-seal/3 is required)');
      if (!plainMatch(sealMessage(seal), sig)) return fail(null, 'the seal\'s signature does not verify under the pinned key');
    }
  }
  const parts = [];
  if (plainCount) parts.push(`${plainCount} by the pinned key`);
  if (sessionCount) parts.push(`${sessionCount} by ${used.sessions.length} certified session key${used.sessions.length === 1 ? '' : 's'}`);
  return { pass: true, brokenAt: null, ms: elapsedMs(t0), keys: used,
    detail: `${chain.length} of ${chain.length} signatures verified` +
      (sessionCount ? ` (${parts.join(', ')})` : '') + (seal !== null ? ', and the seal' : '') };
}

// 5. Anchored: each anchor the bundle carries is a root-signed Merkle root
//    over chain heads, published in the public anchor log (SPEC.md §8). For
//    each: the root signature verifies, the inclusion proof leads from this
//    run's (seq, head) to that Merkle root, and the chain's entry at seq has
//    that hash. A bundle with no anchors SKIPs (pass: null): anchoring is
//    hourly, so a fresh run may not be anchored yet. Whether the anchor matches
//    the PUBLIC log copy is checked by the caller (cascade-verify
//    --fetch-anchors, or the verify page), since this library never goes
//    online.
function checkAnchors(chain, keys, { anchors = [], anchor = null, run = null } = {}) {
  const t0 = process.hrtime.bigint();
  const { roots } = toKeyring(keys);
  const offset = isObj(anchor) && Number.isInteger(anchor.seq) ? anchor.seq : 0;
  const fail = (brokenAt, detail) => ({ pass: false, brokenAt, ms: elapsedMs(t0), detail });
  if (!anchors.length) return { pass: null, brokenAt: null, ms: elapsedMs(t0), detail: 'the bundle carries no anchors (anchoring is hourly)', anchors: [] };
  const out = [];
  for (let i = 0; i < anchors.length; i++) {
    const a = anchors[i];
    const name = `anchor ${i + 1}`;
    if (!isObj(a) || !isObj(a.doc) || !isObj(a.leaf) || !Array.isArray(a.proof)) {
      return fail(null, `${name} is malformed (expected {doc, leaf, proof, url})`);
    }
    const d = a.doc;
    if (d.format !== ANCHOR_FORMAT || typeof d.merkle_root !== 'string' || typeof d.at !== 'string') {
      return fail(null, `${name}: the anchor document is malformed`);
    }
    const root = roots.find((r) => r.id === d.root);
    if (!root) return fail(null, `${name} is signed by root ${JSON.stringify(d.root)}, which is not a pinned root key`);
    const sig = decodeSig(d.sig);
    if (!sig || !crypto.verify(null, Buffer.from(anchorMessage(d), 'utf8'), root.keyObject, sig)) {
      return fail(null, `${name} (${d.at}): the root signature does not verify`);
    }
    const { leaf } = a;
    if (run !== null && leaf.run !== run) return fail(null, `${name} is for run ${JSON.stringify(leaf.run)}, not this bundle's run ${JSON.stringify(run)}`);
    if (merkleRootFromProof(anchorLeaf(leaf), a.proof) !== d.merkle_root) {
      return fail(null, `${name} (${d.at}): the inclusion proof does not lead to the signed Merkle root`);
    }
    const idx = leaf.seq - offset - 1;
    if (Number.isInteger(leaf.seq) && idx >= 0 && idx < chain.length) {
      if (chain[idx].hash !== leaf.head) return fail(leaf.seq, `entry ${leaf.seq}: its hash differs from the head anchored at ${d.at}`);
    } else {
      return fail(null, `${name} anchors entry ${leaf.seq}, which is not in this bundle`);
    }
    out.push({ at: d.at, seq: leaf.seq, cutover: d.cutover === true, url: a.url || null });
  }
  const last = out[out.length - 1];
  return { pass: true, brokenAt: null, ms: elapsedMs(t0), anchors: out,
    detail: `${out.length} anchor${out.length === 1 ? '' : 's'} verified; latest covers entry ${last.seq} at ${last.at}` +
      (out.some((x) => x.cutover) ? '; includes the cutover anchor' : '') };
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
  { id: 'anchored', title: 'Anchored' },
];

// Run all five checks. All always run, so one report shows every failure;
// each failing check names its first broken entry (1-based). `keys` is a
// keyring {roots, plain} or a bare KeyObject (one plain key). Check 5 may
// SKIP (pass: null) and a skip does not fail the bundle.
function verifyBundle(bundle, keys) {
  const t0 = process.hrtime.bigint();
  const { chain } = bundle;
  const ctx = {
    seal: bundle.seal === undefined ? null : bundle.seal,
    anchor: bundle.anchor === undefined ? null : bundle.anchor,
    certs: Array.isArray(bundle.certs) ? bundle.certs : [],
    anchors: Array.isArray(bundle.anchors) ? bundle.anchors : [],
    run: bundle.run === undefined ? null : bundle.run,
  };
  const chainResult = checkChain(chain, ctx);
  const results = [
    chainResult,
    checkSignatures(chain, keys, ctx),
    checkExclusivity(chain),
    checkZeroTokens(chain),
    checkAnchors(chain, keys, ctx),
  ].map((r, i) => ({ ...CHECKS[i], ...r }));
  const totalMs = elapsedMs(t0);
  const { formats, segment, seal, notes } = chainResult;
  return {
    pass: results.every((r) => r.pass !== false),
    entries: chain.length,
    formats, segment, seal, notes,
    checks: results,
    totalMs,
    entriesPerSec: totalMs > 0 ? Math.round(chain.length / (totalMs / 1000)) : null,
  };
}

module.exports = {
  InputError, parseBundle, loadPublicKey, verifyBundle, entryHash, sealMessage,
  certMessage, anchorMessage, anchorLeaf, merkleNode, merkleRootFromProof, keyId, toKeyring,
  checkChain, checkSignatures, checkExclusivity, checkZeroTokens, checkAnchors, CHECKS, GENESIS,
  CHAIN_FORMAT_V2, SEAL_FORMAT_V2, SEAL_FORMAT_V3, CERT_FORMAT, ANCHOR_FORMAT,
};
