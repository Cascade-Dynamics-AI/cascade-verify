'use strict';
// Session keys and anchors (SPEC.md §7-8): a legacy chain signed by the plain
// production key rolls over to v2, continues under root-certified session
// keys, and is anchored. Bundles are built here from the spec, independently
// of the server, so the two implementations check each other.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

const V = require('../lib/verify.js');

const CLI = path.join(__dirname, '..', 'bin', 'cascade-verify.js');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cascade-verify-session-'));
const writeTmp = (name, data) => { const p = path.join(TMP, name); fs.writeFileSync(p, JSON.stringify(data)); return p; };
const verdicts = (r) => r.checks.map((c) => c.pass);

function mkKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return { priv: privateKey, pub: publicKey, spkiB64: der.toString('base64'), id: V.keyId(der) };
}
const sign = (priv, msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), priv).toString('base64');

function mkCert(root, sess, notBefore, notAfter) {
  const c = { format: V.CERT_FORMAT, kid: sess.id, key: sess.spkiB64, root: root.id,
    not_before: notBefore, not_after: notAfter };
  return { ...c, root_sig: sign(root.priv, V.certMessage(c)) };
}

const RUN = 'ab12cd34';

// A chain builder that follows SPEC.md: v1 entries, a rollover into v2, then
// v2 entries, each signed by the key given for it (a session key adds kid).
function buildChain(steps) {
  const chain = [];
  let prev = 'genesis';
  const prefix = crypto.createHash('sha256');
  let v2Started = false;
  for (const s of steps) {
    const seq = chain.length + 1;
    let e;
    if (s.v === 1) {
      e = { t: null, verb: s.verb, cell: s.cell, agent: s.agent, prev };
      if (s.kid) e.kid = s.kid; // only for the "kid on v1" attack
      e.hash = V.entryHash(prev, e, 1);
    } else {
      e = { v: 2, seq, t: null, verb: s.verb, cell: s.cell, agent: s.agent };
      if (!v2Started) {
        e.hdr = { format: V.CHAIN_FORMAT_V2, run: RUN, key: s.hdrKey || null };
        if (seq > 1) e.hdr.rollover = { from_format: 1, entries: seq - 1, head: prev, prefix_sha256: prefix.digest('hex') };
        v2Started = true;
      }
      e.prev = prev;
      if (s.kid) e.kid = s.kid;
      e.hash = V.entryHash(prev, e, 2);
    }
    e.sig = sign(s.key.priv, e.hash);
    if (s.v === 1) prefix.update(JSON.stringify(e) + '\n', 'utf8');
    chain.push(e);
    prev = e.hash;
  }
  return chain;
}

function seal3(chain, sess, at) {
  const last = chain[chain.length - 1];
  const s = { format: V.SEAL_FORMAT_V3, run: RUN, seq: last.seq || chain.length, head: last.hash, at, kid: sess.id };
  return { ...s, sig: sign(sess.priv, V.sealMessage(s)) };
}

// Merkle tree over leaves (SPEC.md §8); returns {root, proofFor(i)}.
function merkle(leafHashes) {
  const levels = [leafHashes];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1], next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? V.merkleNode(cur[i], cur[i + 1]) : cur[i]);
    levels.push(next);
  }
  return {
    root: levels[levels.length - 1][0],
    proofFor(i) {
      const proof = [];
      for (let l = 0; l < levels.length - 1; l++) {
        const sib = i % 2 === 0 ? i + 1 : i - 1;
        if (sib < levels[l].length) proof.push({ side: i % 2 === 0 ? 'R' : 'L', hash: levels[l][sib] });
        i = Math.floor(i / 2);
      }
      return proof;
    },
  };
}

function mkAnchor(root, at, leaf, { cutover = false, others = 4 } = {}) {
  const leaves = [];
  for (let i = 0; i < others; i++) leaves.push({ run: `run${i}`, seq: i + 1, head: crypto.randomBytes(32).toString('hex') });
  const idx = 2 % (others + 1);
  leaves.splice(idx, 0, leaf);
  const t = merkle(leaves.map(V.anchorLeaf));
  const d = { format: V.ANCHOR_FORMAT, at, count: leaves.length, merkle_root: t.root, cutover };
  const doc = { ...d, root: root.id, sig: sign(root.priv, V.anchorMessage(d)) };
  return { doc, leaf, proof: t.proofFor(idx), url: null };
}

// The scenario every test starts from: 3 legacy v1 entries, rollover, 3
// entries under session key A, rotation, 3 under session key B, seal by B,
// a cutover anchor over the legacy head and a later anchor.
function scenario() {
  const root = mkKey(), legacy = mkKey(), A = mkKey(), B = mkKey();
  const step = (v, key, kid, i) => ({ v, key, kid, verb: i % 2 ? 'RELEASE' : 'ASSIGN', cell: `bay/${Math.floor(i / 2)}`, agent: 'robot-a' });
  const steps = [];
  for (let i = 0; i < 3; i++) steps.push(step(1, legacy, null, i));
  for (let i = 3; i < 6; i++) steps.push({ ...step(2, A, A.id, i), hdrKey: root.spkiB64 });
  for (let i = 6; i < 9; i++) steps.push(step(2, B, B.id, i));
  const chain = buildChain(steps);
  const certs = [
    mkCert(root, A, '2026-10-22T10:00:00.000Z', '2026-10-23T11:00:00.000Z'),
    mkCert(root, B, '2026-10-22T11:00:00.000Z', '2026-10-23T12:00:00.000Z'),
  ];
  const seal = seal3(chain, B, '2026-10-22T11:30:00.000Z');
  const anchors = [
    mkAnchor(root, '2026-10-22T10:00:01.000Z', { run: RUN, seq: 3, head: chain[2].hash }, { cutover: true }),
    mkAnchor(root, '2026-10-22T11:00:00.000Z', { run: RUN, seq: 6, head: chain[5].hash }),
  ];
  const bundle = { run: RUN, format: 2, chain, certs, seal, anchors, public_key: root.spkiB64 };
  const keys = { roots: [V.loadPublicKey(root.spkiB64)], plain: [V.loadPublicKey(legacy.spkiB64)] };
  return { root, legacy, A, B, bundle, keys, steps };
}

const verify = (bundle, keys) => V.verifyBundle(V.parseBundle(JSON.stringify(bundle)), keys);

test('legacy prefix, rollover, two session keys, seal/3 and anchors: all five checks pass', () => {
  const { bundle, keys, A, B } = scenario();
  const r = verify(bundle, keys);
  assert.deepEqual(verdicts(r), [true, true, true, true, true], JSON.stringify(r.checks, null, 1));
  const sig = r.checks[1];
  assert.deepEqual(sig.keys.sessions, [A.id, B.id]);
  assert.equal(sig.keys.plain.length, 1);
  assert.match(sig.detail, /3 by the pinned key, 6 by 2 certified session keys/);
  assert.match(r.checks[4].detail, /2 anchors verified.*cutover/);
});

test('the CLI passes it with --root and --key, and fails it on the built-in production keys', () => {
  const { bundle, root, legacy } = scenario();
  const file = writeTmp('session-ok.json', bundle);
  const ok = spawnSync(process.execPath, [CLI, file, '--root', root.spkiB64, '--key', legacy.spkiB64, '--json'], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  const rep = JSON.parse(ok.stdout);
  assert.equal(rep.keys.used.sessions.length, 2);
  const human = spawnSync(process.execPath, [CLI, file, '--root', root.spkiB64, '--key', legacy.spkiB64], { encoding: 'utf8' });
  assert.match(human.stdout, /session keys: 2 certified by the root/);
  assert.match(human.stdout, /VERIFIED: 5\/5 checks passed/);
  const prod = spawnSync(process.execPath, [CLI, file, '--json'], { encoding: 'utf8' });
  assert.equal(prod.status, 1); // these test keys are not Cascade's
});

test('a session-signed chain needs no plain key at all', () => {
  const root = mkKey(), A = mkKey();
  const chain = buildChain([0, 1, 2].map((i) => ({ v: 2, key: A, kid: A.id, verb: 'ASSIGN', cell: `c/${i}`, agent: `a${i}`, hdrKey: root.spkiB64 })));
  const bundle = { run: RUN, chain, certs: [mkCert(root, A, '2026-10-22T10:00:00.000Z', '2026-10-23T11:00:00.000Z')],
    seal: seal3(chain, A, '2026-10-22T10:05:00.000Z') };
  const r = verify(bundle, { roots: [V.loadPublicKey(root.spkiB64)], plain: [] });
  assert.deepEqual(verdicts(r), [true, true, true, true, null]);
});

test('attack: an entry naming a session key with no cert in the bundle fails check 2 at that entry', () => {
  const { bundle, keys } = scenario();
  bundle.certs = bundle.certs.slice(1); // drop A's cert
  const r = verify(bundle, keys);
  assert.equal(r.checks[1].pass, false);
  assert.equal(r.checks[1].brokenAt, 4);
  assert.match(r.checks[1].detail, /no cert/);
});

test('attack: a cert signed by a different root fails check 2', () => {
  const { bundle, keys, A } = scenario();
  const other = mkKey();
  bundle.certs[0] = mkCert(other, A, bundle.certs[0].not_before, bundle.certs[0].not_after);
  const r = verify(bundle, keys);
  assert.equal(r.checks[1].pass, false);
  assert.match(r.checks[1].detail, /not a pinned root/);
  // ...and a cert claiming the right root id but signed by another key.
  const s2 = scenario();
  const forged = { ...s2.bundle.certs[0] };
  forged.root_sig = sign(other.priv, V.certMessage(forged));
  s2.bundle.certs[0] = forged;
  const r2 = verify(s2.bundle, s2.keys);
  assert.equal(r2.checks[1].pass, false);
  assert.match(r2.checks[1].detail, /root signature does not verify/);
});

test('attack: a cert whose kid is not its key\'s id fails check 2', () => {
  const { bundle, keys, root, A } = scenario();
  const imposter = mkKey();
  const c = { format: V.CERT_FORMAT, kid: A.id, key: imposter.spkiB64, root: root.id,
    not_before: bundle.certs[0].not_before, not_after: bundle.certs[0].not_after };
  bundle.certs[0] = { ...c, root_sig: sign(root.priv, V.certMessage(c)) };
  const r = verify(bundle, keys);
  assert.equal(r.checks[1].pass, false);
  assert.match(r.checks[1].detail, /is not the id of its key/);
});

test('attack: an entry relabelled with another valid session key\'s kid fails (check 1 catches the edit; re-hashed, check 2)', () => {
  const { bundle, keys, B } = scenario();
  bundle.chain[3].kid = B.id; // signed by A
  assert.equal(verify(bundle, keys).checks[0].pass, false);
  // A forger who re-hashes and re-links still cannot re-sign as B... but can as nobody:
  const s = scenario();
  const steps = s.steps.map((st, i) => (i === 3 ? { ...st, kid: s.B.id } : st)); // claims B, signed by A
  s.bundle.chain = buildChain(steps);
  s.bundle.seal = seal3(s.bundle.chain, s.B, '2026-10-22T11:30:00.000Z');
  s.bundle.anchors = [];
  const r = verify(s.bundle, s.keys);
  assert.equal(r.checks[0].pass, true);
  assert.equal(r.checks[1].pass, false);
  assert.equal(r.checks[1].brokenAt, 4);
  assert.match(r.checks[1].detail, /does not verify under session key/);
});

test('attack: a plain-key entry after session-signed entries fails check 2 (the legacy key is retired)', () => {
  const s = scenario();
  const steps = [...s.steps, { v: 2, key: s.legacy, kid: null, verb: 'ASSIGN', cell: 'bay/9', agent: 'forger' }];
  s.bundle.chain = buildChain(steps);
  s.bundle.seal = seal3(s.bundle.chain, s.B, '2026-10-22T11:30:00.000Z');
  s.bundle.anchors = [];
  const r = verify(s.bundle, s.keys);
  assert.equal(r.checks[1].pass, false);
  assert.equal(r.checks[1].brokenAt, 10);
  assert.match(r.checks[1].detail, /no session key after session-signed entries/);
});

test('attack: an older session key signing after a newer one fails check 2', () => {
  const s = scenario();
  const steps = [...s.steps, { v: 2, key: s.A, kid: s.A.id, verb: 'ASSIGN', cell: 'bay/9', agent: 'late' }];
  s.bundle.chain = buildChain(steps);
  s.bundle.seal = seal3(s.bundle.chain, s.B, '2026-10-22T11:30:00.000Z');
  s.bundle.anchors = [];
  const r = verify(s.bundle, s.keys);
  assert.equal(r.checks[1].pass, false);
  assert.equal(r.checks[1].brokenAt, 10);
  assert.match(r.checks[1].detail, /older than/);
});

test('attack: the seal signed by a different session key than it names, or outside its window, fails check 2', () => {
  const s = scenario();
  const bad = { ...s.bundle.seal };
  bad.sig = sign(s.A.priv, V.sealMessage(bad)); // names B, signed by A
  s.bundle.seal = bad;
  const r = verify(s.bundle, s.keys);
  assert.equal(r.checks[1].pass, false);
  assert.match(r.checks[1].detail, /seal's signature does not verify under session key/);

  const s2 = scenario();
  s2.bundle.seal = seal3(s2.bundle.chain, s2.B, '2026-10-25T00:00:00.000Z'); // after B's not_after
  const r2 = verify(s2.bundle, s2.keys);
  assert.equal(r2.checks[1].pass, false);
  assert.match(r2.checks[1].detail, /outside session key/);
});

test('attack: a seal/2 signed by the legacy key over a session-signed chain fails check 2', () => {
  const s = scenario();
  const last = s.bundle.chain[s.bundle.chain.length - 1];
  const seal = { format: V.SEAL_FORMAT_V2, run: RUN, seq: last.seq, head: last.hash, at: '2026-10-22T11:30:00.000Z' };
  s.bundle.seal = { ...seal, sig: sign(s.legacy.priv, V.sealMessage(seal)) };
  const r = verify(s.bundle, s.keys);
  assert.equal(r.checks[1].pass, false);
  assert.match(r.checks[1].detail, /cascade-seal\/3 is required/);
});

test('attack: a kid on a v1 entry fails check 1', () => {
  const s = scenario();
  const steps = s.steps.map((st, i) => (i === 1 ? { ...st, kid: s.A.id } : st));
  s.bundle.chain = buildChain(steps);
  const r = verify(s.bundle, s.keys);
  assert.equal(r.checks[0].pass, false);
  assert.equal(r.checks[0].brokenAt, 2);
  assert.match(r.checks[0].detail, /kid on a v1 entry/);
});

test('attack: anchors that do not check out fail check 5', () => {
  // A tampered inclusion proof.
  const s1 = scenario();
  s1.bundle.anchors[1].proof[0].hash = '0'.repeat(64);
  const r1 = verify(s1.bundle, s1.keys);
  assert.equal(r1.checks[4].pass, false);
  assert.match(r1.checks[4].detail, /inclusion proof/);
  // An anchor signed by another root.
  const s2 = scenario();
  const other = mkKey();
  s2.bundle.anchors[0] = mkAnchor(other, '2026-10-22T10:00:01.000Z', s2.bundle.anchors[0].leaf);
  const r2 = verify(s2.bundle, s2.keys);
  assert.equal(r2.checks[4].pass, false);
  assert.match(r2.checks[4].detail, /not a pinned root/);
  // An anchor whose head is not the chain's (history rewritten after anchoring).
  const s3 = scenario();
  s3.bundle.anchors[1] = mkAnchor(s3.root, '2026-10-22T11:00:00.000Z', { run: RUN, seq: 6, head: 'f'.repeat(64) });
  const r3 = verify(s3.bundle, s3.keys);
  assert.equal(r3.checks[4].pass, false);
  assert.equal(r3.checks[4].brokenAt, 6);
  // An anchor for another run.
  const s4 = scenario();
  s4.bundle.anchors[1] = mkAnchor(s4.root, '2026-10-22T11:00:00.000Z', { run: 'ffffffff', seq: 6, head: s4.bundle.chain[5].hash });
  assert.match(verify(s4.bundle, s4.keys).checks[4].detail, /not this bundle's run/);
  // An edited signed field (count).
  const s5 = scenario();
  s5.bundle.anchors[0].doc.count += 1;
  assert.match(verify(s5.bundle, s5.keys).checks[4].detail, /root signature does not verify/);
});

test('the 0.2 API still works: verifyBundle(bundle, KeyObject) checks plain entries with that key', () => {
  const s = scenario();
  const plainOnly = { run: RUN, chain: s.bundle.chain.slice(0, 3) };
  const r = V.verifyBundle(V.parseBundle(JSON.stringify(plainOnly)), V.loadPublicKey(s.legacy.spkiB64).keyObject);
  assert.deepEqual(verdicts(r), [true, true, true, true, null]);
});

function runCliAsync(args) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [CLI, ...args]);
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('--fetch-anchors: passes when the public log matches, fails when it differs or is missing', async () => {
  const s = scenario();
  const { anchorFile } = require('../lib/fetch-anchors.js');
  const log = new Map(s.bundle.anchors.map((a) => [`/anchors/${anchorFile(a.doc.at)}`, JSON.stringify(a.doc)]));
  const server = http.createServer((req, res) => {
    const body = log.get(req.url);
    if (!body) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}/anchors/`;
  try {
    const file = writeTmp('fetch.json', s.bundle);
    const args = [file, '--root', s.root.spkiB64, '--key', s.legacy.spkiB64, '--fetch-anchors', '--anchor-log', base, '--json'];
    const ok = await runCliAsync(args);
    assert.equal(ok.code, 0, ok.stdout + ok.stderr);
    assert.match(JSON.parse(ok.stdout).checks[4].detail, /all 2 match the public log/);

    // The log holds a different (also validly signed) anchor for that time.
    const first = s.bundle.anchors[0].doc;
    log.set(`/anchors/${anchorFile(first.at)}`, JSON.stringify({ ...first, merkle_root: 'e'.repeat(64) }));
    const differs = await runCliAsync(args);
    assert.equal(differs.code, 1);
    assert.match(JSON.parse(differs.stdout).checks[4].detail, /differs from the public log copy.*merkle_root/);

    log.clear();
    const missing = await runCliAsync(args);
    assert.equal(missing.code, 1);
    assert.match(JSON.parse(missing.stdout).checks[4].detail, /could not be fetched/);
  } finally {
    server.close();
  }
});

test('cross-check: the live page\'s runChecks agrees with the library on session-key bundles and the attacks', async (t) => {
  const { pageRunChecks } = require('../reference/page-checks.js');
  const { anchorFile } = require('../lib/fetch-anchors.js');
  const subtle = await crypto.webcrypto.subtle.importKey('spki', Buffer.from(mkKey().spkiB64, 'base64'), { name: 'Ed25519' }, false, ['verify']).then(() => true, () => false);
  if (!subtle) { t.skip('this Node lacks WebCrypto Ed25519'); return; }
  const cases = {};
  cases.good = scenario();
  cases.noCert = scenario(); cases.noCert.bundle.certs = cases.noCert.bundle.certs.slice(1);
  cases.plainAfter = scenario();
  cases.plainAfter.bundle.chain = buildChain([...cases.plainAfter.steps, { v: 2, key: cases.plainAfter.legacy, kid: null, verb: 'ASSIGN', cell: 'x/1', agent: 'f' }]);
  cases.plainAfter.bundle.seal = seal3(cases.plainAfter.bundle.chain, cases.plainAfter.B, '2026-10-22T11:30:00.000Z');
  cases.plainAfter.bundle.anchors = [];
  cases.badProof = scenario(); cases.badProof.bundle.anchors[1].proof[0].hash = '0'.repeat(64);
  for (const [name, s] of Object.entries(cases)) {
    const log = new Map(s.bundle.anchors.map((a) => [`/anchors/${anchorFile(a.doc.at)}`, a.doc]));
    const fetch = async (url) => (log.has(url)
      ? { ok: true, status: 200, json: async () => log.get(url) }
      : { ok: false, status: 404, json: async () => ({}) });
    const page = await pageRunChecks(s.bundle, s.legacy.spkiB64, { rootB64: s.root.spkiB64, fetch });
    const lib = verify(s.bundle, s.keys);
    assert.deepEqual(page.map((r) => r.pass), verdicts(lib), `${name}: page ${JSON.stringify(page.map((r) => r.detail))}`);
    assert.equal(page[1].brokenAt, lib.checks[1].brokenAt, `${name}: same first broken entry for check 2`);
  }
  // With the log unreachable, the page SKIPs check 5 (the CLI without --fetch-anchors PASSes it offline).
  const s = scenario();
  const page = await pageRunChecks(s.bundle, s.legacy.spkiB64, { rootB64: s.root.spkiB64 });
  assert.equal(page[4].pass, null);
  assert.match(page[4].detail, /not compared with the public log \(offline\)/);
  // A log that holds a different anchor for that time: the page FAILs check 5.
  const forged = async () => ({ ok: true, status: 200, json: async () => ({ ...s.bundle.anchors[0].doc, merkle_root: 'e'.repeat(64) }) });
  const p2 = await pageRunChecks(s.bundle, s.legacy.spkiB64, { rootB64: s.root.spkiB64, fetch: forged });
  assert.equal(p2[4].pass, false);
  assert.match(p2[4].detail, /differs from the public log/);
});
