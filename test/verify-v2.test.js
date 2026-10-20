'use strict';
// Format v2 (SPEC.md §6): full 256-bit hashes signed in full, `seq` and a run
// header in the signed body, and a signed seal over the entry count and head.
// Fixtures were written by Cascade's own writer (jarvis/chain.mjs, format v2)
// with a throwaway key whose public half is embedded in each fixture.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const { parseBundle, loadPublicKey, verifyBundle, entryHash, sealMessage } = require('../lib/verify.js');
const { pageRunChecks } = require('../reference/page-checks.js');

const CLI = path.join(__dirname, '..', 'bin', 'cascade-verify.js');
const FX = (name) => path.join(__dirname, 'fixtures', name);
const load = (name) => JSON.parse(fs.readFileSync(FX(name), 'utf8'));
const V2_KEY = loadPublicKey(load('v2-sample.json').public_key).spkiB64;
const V1_KEY = loadPublicKey(load('proof-sample.json').public_key).spkiB64;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cascade-verify-v2-'));

function writeTmp(name, data) {
  const p = path.join(TMP, name);
  fs.writeFileSync(p, JSON.stringify(data));
  return p;
}
function runJson(args) {
  const r = spawnSync(process.execPath, [CLI, ...args, '--json'], { encoding: 'utf8' });
  return { code: r.status, report: JSON.parse(r.stdout), stderr: r.stderr };
}
const verdicts = (report) => report.checks.map((c) => c.pass);
const check = (bundle, key) => runJson([writeTmp(`b-${crypto.randomUUID()}.json`, bundle), '--key', key]);

function throwawayKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, b64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64') };
}
const signWith = (privateKey, msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('base64');

// What someone holding a signing key can do: relink every entry by its own
// format, re-sign, and re-seal over the new end. Without a key: no sigs, no seal sig.
function rebuild(bundle, privateKey) {
  let prev = bundle.anchor ? bundle.anchor.hash : 'genesis';
  bundle.chain = bundle.chain.map((e) => {
    const { hash, sig, ...rest } = e;
    rest.prev = prev;
    const h = entryHash(prev, rest, rest.v === 2 ? 2 : 1);
    prev = h;
    return privateKey ? { ...rest, hash: h, sig: signWith(privateKey, h) } : { ...rest, hash: h };
  });
  if (bundle.seal) {
    const n = (bundle.anchor ? bundle.anchor.seq : 0) + bundle.chain.length;
    const s = { format: 'cascade-seal/2', run: bundle.seal.run, seq: n, head: prev, at: bundle.seal.at };
    bundle.seal = privateKey ? { ...s, sig: signWith(privateKey, sealMessage(s)) } : { ...s, sig: bundle.seal.sig };
  }
  return bundle;
}

test('v2 sample, rollover and segment fixtures pass 4/4 under the pinned key', () => {
  const v2 = check(load('v2-sample.json'), V2_KEY);
  assert.equal(v2.code, 0, v2.stderr);
  assert.deepEqual(verdicts(v2.report), [true, true, true, true]);
  assert.deepEqual(v2.report.formats, { v1: 0, v2: 120 });
  assert.equal(v2.report.seal.seq, 120);

  const ro = check(load('v2-rollover.json'), V2_KEY);
  assert.equal(ro.code, 0, ro.stderr);
  assert.deepEqual(ro.report.formats, { v1: 12, v2: 24 });

  const seg = check(load('v2-segment.json'), V2_KEY);
  assert.equal(seg.code, 0, seg.stderr);
  assert.deepEqual(seg.report.segment, { from: 71, to: 120 });
  assert.ok(seg.report.notes.some((n) => /run header is before this segment/.test(n)));
});

test('v1 public sample still passes 4/4 and is reported as v1 without a seal', () => {
  const r = runJson([FX('proof-sample.json'), '--key', V1_KEY]);
  assert.equal(r.code, 0);
  assert.deepEqual(r.report.formats, { v1: 2252, v2: 0 });
  assert.equal(r.report.seal, null);
});

test('v2 tamper: one changed field fails check 1 at that entry', () => {
  const b = load('v2-sample.json');
  b.chain[49].detail += ' [FORGED]';
  const r = check(b, V2_KEY);
  assert.equal(r.code, 1);
  assert.deepEqual(verdicts(r.report), [false, true, true, true]);
  assert.equal(r.report.checks[0].broken_at, 50);
});

test('v2 strip-signature: relinked, unsigned chain passes check 1 but fails check 2 at entry 1', () => {
  const b = rebuild(load('v2-sample.json'), null);
  b.chain[10].detail = 'edited after stripping';
  rebuild(b, null);
  const r = check(b, V2_KEY);
  assert.deepEqual(verdicts(r.report), [true, false, true, true]);
  assert.equal(r.report.checks[1].broken_at, 1);
  assert.match(r.report.checks[1].detail, /no signature/);
});

test('v2 truncation: dropping the tail fails check 1 and names the first missing entry', () => {
  const b = load('v2-sample.json');
  b.chain = b.chain.slice(0, 115);
  const r = check(b, V2_KEY);
  assert.equal(r.code, 1);
  assert.deepEqual(verdicts(r.report), [false, true, true, true]);
  assert.equal(r.report.checks[0].broken_at, 116);
  assert.match(r.report.checks[0].detail, /entries 116-120 are missing/);
  const human = spawnSync(process.execPath, [CLI, writeTmp('cut.json', b), '--key', V2_KEY], { encoding: 'utf8' });
  assert.match(human.stdout, /First failure: check 1 \(Chain integrity\) at entry 116/);
});

test('v2 truncation with the seal removed fails: a v2 bundle must carry a seal', () => {
  const b = load('v2-sample.json');
  b.chain = b.chain.slice(0, 115);
  delete b.seal;
  const r = check(b, V2_KEY);
  assert.equal(r.code, 1);
  assert.equal(r.report.checks[0].pass, false);
  assert.match(r.report.checks[0].detail, /no seal/);
});

test('v2 truncation with the seal edited to match fails check 2 (the seal is signed)', () => {
  const b = load('v2-sample.json');
  b.chain = b.chain.slice(0, 115);
  b.seal = { ...b.seal, seq: 115, head: b.chain[114].hash };
  const r = check(b, V2_KEY);
  assert.deepEqual(verdicts(r.report), [true, false, true, true]);
  assert.match(r.report.checks[1].detail, /seal/);
});

test('v2 wrong key fails check 2 at entry 1', () => {
  const r = check(load('v2-sample.json'), throwawayKey().b64);
  assert.deepEqual(verdicts(r.report), [true, false, true, true]);
  assert.equal(r.report.checks[1].broken_at, 1);
});

test('v2 structure: downgrade, wrong seq, missing header, short hash and a forged rollover all fail check 1, even when validly re-signed', () => {
  const k = throwawayKey();
  const cases = {
    downgrade: [(b) => b.chain.push({ t: null, verb: 'ASSIGN', cell: 'x', agent: 'y', detail: 'v1 after v2' }), 121, /downgrade/],
    seq: [(b) => { b.chain[30].seq = 99; }, 31, /seq/],
    header: [(b) => { delete b.chain[0].hdr; }, 1, /run header/],
    short: [null, 20, /hashes to/],
    // an edited v1 entry changes the v1 head the boundary entry commits to
    rolloverEdit: [null, 13, /rollover header does not match/],
    // the v1 prefix re-signed by another key keeps every v1 hash (a v1 hash
    // does not cover sig) — only prefix_sha256 notices
    rolloverResigned: [null, 13, /prefix_sha256/],
  };
  for (const [name, [mutate, at, re]] of Object.entries(cases)) {
    let b;
    if (name === 'short') {
      b = rebuild(load('v2-sample.json'), k.privateKey);
      b.chain[19].hash = b.chain[19].hash.slice(0, 16);
    } else if (name === 'rolloverEdit') {
      b = load('v2-rollover.json');
      b.chain[3].detail = 'edited v1 entry';
      rebuild(b, k.privateKey);
    } else if (name === 'rolloverResigned') {
      b = rebuild(load('v2-rollover.json'), k.privateKey);
    } else {
      b = load('v2-sample.json');
      mutate(b);
      rebuild(b, k.privateKey);
    }
    const r = check(b, k.b64);
    assert.equal(r.report.checks[0].pass, false, name);
    assert.equal(r.report.checks[0].broken_at, at, name);
    assert.match(r.report.checks[0].detail, re, name);
  }
});

test('v2 segment: the anchor is required and must match', () => {
  const lost = load('v2-segment.json');
  delete lost.anchor;
  let r = check(lost, V2_KEY);
  assert.equal(r.report.checks[0].pass, false);
  assert.equal(r.report.checks[0].broken_at, 1);
  const moved = load('v2-segment.json');
  moved.anchor.seq = 60;
  r = check(moved, V2_KEY);
  assert.equal(r.report.checks[0].pass, false);
  assert.equal(r.report.checks[0].broken_at, 1);
});

test('cross-check: CLI and the page\'s runChecks agree on v2 bundles, passing and failing', async (t) => {
  const ok = await crypto.webcrypto.subtle
    .importKey('spki', Buffer.from(V2_KEY, 'base64'), { name: 'Ed25519' }, false, ['verify'])
    .then(() => true, () => false);
  if (!ok) { t.skip('this Node lacks WebCrypto Ed25519'); return; }
  const cut = load('v2-sample.json'); cut.chain = cut.chain.slice(0, 115);
  const tampered = load('v2-sample.json'); tampered.chain[49].detail += ' [FORGED]';
  const stripped = rebuild(load('v2-sample.json'), null);
  const noSeal = load('v2-sample.json'); delete noSeal.seal;
  const badSeal = load('v2-sample.json'); badSeal.seal.at = '2000-01-01T00:00:00.000Z';
  const copies = {
    sample: load('v2-sample.json'), rollover: load('v2-rollover.json'), segment: load('v2-segment.json'),
    cut, tampered, stripped, noSeal, badSeal,
  };
  for (const [name, b] of Object.entries(copies)) {
    const page = await pageRunChecks(b, V2_KEY);
    const lib = verifyBundle(parseBundle(JSON.stringify(b)), loadPublicKey(V2_KEY).keyObject);
    assert.deepEqual(page.map((r) => r.pass), lib.checks.map((c) => c.pass), `verdicts on ${name}`);
    for (const i of [0, 1]) {
      assert.equal(page[i].brokenAt ?? null, lib.checks[i].brokenAt, `${name} check ${i + 1} broken entry`);
    }
  }
});
