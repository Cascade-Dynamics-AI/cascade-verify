'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const { parseBundle, loadPublicKey, verifyBundle, entryHash } = require('../lib/verify.js');
const { pageRunChecks } = require('../reference/page-checks.js');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'cascade-verify.js');
const SAMPLE_PATH = path.join(__dirname, 'fixtures', 'proof-sample.json');
const SAMPLE_TEXT = fs.readFileSync(SAMPLE_PATH, 'utf8');
const SAMPLE_KEY_B64 = loadPublicKey(JSON.parse(SAMPLE_TEXT).public_key).spkiB64;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cascade-verify-test-'));

const sample = () => JSON.parse(SAMPLE_TEXT);

function writeTmp(name, data) {
  const p = path.join(TMP, name);
  fs.writeFileSync(p, typeof data === 'string' ? data : JSON.stringify(data));
  return p;
}

function run(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function runJson(args) {
  const r = run([...args, '--json']);
  return { ...r, report: JSON.parse(r.stdout) };
}

const verdicts = (report) => report.checks.map((c) => c.pass);

// Rebuild prev/hash links from genesis; sign with privateKey, or strip
// signatures when privateKey is null. This is what a forger can always do.
function rebuild(chain, privateKey) {
  let prev = 'genesis';
  return chain.map((e) => {
    const { hash, sig, ...rest } = e;
    rest.prev = prev;
    const h = entryHash(prev, rest);
    prev = h;
    const out = { ...rest, hash: h };
    if (privateKey) out.sig = crypto.sign(null, Buffer.from(h, 'utf8'), privateKey).toString('base64');
    return out;
  });
}

function throwawayKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pem: publicKey.export({ format: 'pem', type: 'spki' }),
    b64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64') };
}

// The copies the cross-check runs against.
function strippedCopy() {
  const b = sample();
  b.chain[1].detail += ' [FORGED]';
  b.chain = rebuild(b.chain, null);
  return b;
}
function tamperedCopy() { // the same mutation the live page's tamper switch makes
  const b = sample();
  b.chain[1] = { ...b.chain[1], detail: (b.chain[1].detail || '') + ' [FORGED]' };
  return b;
}

test('real sample passes 4/4 on the built-in production keys (anchors skip) and reports throughput', () => {
  const r = runJson([SAMPLE_PATH]);
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(verdicts(r.report), [true, true, true, true, null]);
  assert.equal(r.report.entries, 2252);
  assert.equal(r.report.key.source, 'builtin');
  assert.equal(r.report.key.embedded_differs, false);
  assert.ok(r.report.entries_per_sec > 0);
  const human = run([SAMPLE_PATH]);
  assert.equal(human.code, 0);
  assert.match(human.stdout, /VERIFIED: 4\/4 checks passed \(1 skipped\)/);
  assert.match(human.stdout, /SKIP  5\. Anchored/);
  assert.match(human.stdout, /entries\/s/);
  assert.doesNotMatch(human.stderr, /WARNING/); // the built-in keys are an independent pin
});

test('--embedded-key checks against the bundle\'s own key, with a warning', () => {
  const r = run([SAMPLE_PATH, '--embedded-key']);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /WARNING/);
  assert.match(r.stdout, /EMBEDDED in the bundle/);
  assert.equal(run([SAMPLE_PATH, '--embedded-key', '--key', SAMPLE_KEY_B64]).code, 2);
});

test('pinning the published key by string, PEM file or raw 32-byte key passes without the warning', () => {
  const pemFile = writeTmp('pub.pem', JSON.parse(SAMPLE_TEXT).public_key);
  const raw32 = Buffer.from(SAMPLE_KEY_B64, 'base64').subarray(12).toString('base64');
  for (const k of [SAMPLE_KEY_B64, pemFile, raw32, `--key=${SAMPLE_KEY_B64}`]) {
    const args = k.startsWith('--key=') ? [SAMPLE_PATH, k] : [SAMPLE_PATH, '--key', k];
    const r = run(args);
    assert.equal(r.code, 0, `${k}: ${r.stderr}`);
    assert.doesNotMatch(r.stderr, /WARNING/);
    assert.match(r.stdout, /pinned by you/);
  }
});

test('one byte changed fails check 1 at that entry', () => {
  const b = sample();
  const i = 1500; // 0-based; entry 1501
  const d = b.chain[i].detail;
  b.chain[i].detail = d.slice(0, 3) + String.fromCharCode(d.charCodeAt(3) ^ 1) + d.slice(4);
  const r = runJson([writeTmp('one-byte.json', b)]);
  assert.equal(r.code, 1);
  assert.deepEqual(verdicts(r.report), [false, true, true, true, null]);
  assert.equal(r.report.checks[0].broken_at, 1501);
  assert.match(run([writeTmp('one-byte.json', b)]).stdout, /check 1 \(Chain integrity\) at entry 1501/);
});

test('signatures stripped and hashes rebuilt passes check 1 but fails check 2', () => {
  const r = runJson([writeTmp('stripped.json', strippedCopy())]);
  assert.equal(r.code, 1);
  assert.deepEqual(verdicts(r.report), [true, false, true, true, null]);
  assert.equal(r.report.checks[1].broken_at, 1);
  assert.match(r.report.checks[1].detail, /no signature/);
});

test('regression: one unsigned entry in an otherwise signed chain fails check 2', () => {
  const b = sample();
  delete b.chain[999].sig;
  const r = runJson([writeTmp('one-unsigned.json', b)]);
  assert.equal(r.code, 1);
  assert.deepEqual(verdicts(r.report), [true, false, true, true, null]);
  assert.equal(r.report.checks[1].broken_at, 1000);
});

test('a wrong pinned key fails check 2', () => {
  const r = runJson([SAMPLE_PATH, '--key', throwawayKey().b64]);
  assert.equal(r.code, 1);
  assert.deepEqual(verdicts(r.report), [true, false, true, true, null]);
  assert.equal(r.report.checks[1].broken_at, 1);
  assert.equal(r.report.key.embedded_differs, true);
});

test('duplicate holder injected and re-signed with a throwaway key fails check 3 (and check 2 once the real key is pinned)', () => {
  const k = throwawayKey();
  const b = sample();
  // The first entry is ASSIGN maze/0-0 to unit-01; grant the same cell to
  // another agent while unit-01 still holds it.
  const forged = { t: null, verb: 'ASSIGN', cell: b.chain[0].cell, agent: 'unit-99', entry: 9999,
    detail: `unit-99 → ${b.chain[0].cell} · reserve`, prev: '' };
  b.chain.splice(1, 0, forged);
  b.chain = rebuild(b.chain, k.privateKey);
  b.public_key = k.pem;
  const file = writeTmp('dup.json', b);

  const embedded = runJson([file, '--embedded-key']);
  assert.equal(embedded.code, 1);
  assert.deepEqual(verdicts(embedded.report), [true, true, false, true, null]);
  assert.equal(embedded.report.checks[2].broken_at, 2);

  const pinned = runJson([file, '--key', SAMPLE_KEY_B64]);
  assert.deepEqual(verdicts(pinned.report), [true, false, false, true, null]);
  const builtin = runJson([file]);
  assert.deepEqual(verdicts(builtin.report), [true, false, false, true, null]);
});

test('a re-signed bundle passes everything under its own embedded key; the built-in keys and pinning catch it', () => {
  const k = throwawayKey();
  const b = sample();
  b.chain[10].detail += ' (edited)';
  b.chain = rebuild(b.chain, k.privateKey);
  b.public_key = k.pem;
  const file = writeTmp('resigned.json', b);
  assert.equal(run([file, '--embedded-key']).code, 0);
  const builtin = runJson([file]);
  assert.equal(builtin.code, 1);
  assert.deepEqual(verdicts(builtin.report), [true, false, true, true, null]);
  assert.equal(builtin.report.key.embedded_differs, true);
  const pinned = runJson([file, '--key', SAMPLE_KEY_B64]);
  assert.equal(pinned.code, 1);
  assert.deepEqual(verdicts(pinned.report), [true, false, true, true, null]);
});

test('a tokens field or a model name fails check 4', () => {
  const k = throwawayKey();
  for (const [field, value] of [['tokens_used', 12], ['model', 'any-model-name']]) {
    const b = sample();
    b.chain[42][field] = value;
    b.chain = rebuild(b.chain, k.privateKey);
    b.public_key = k.pem;
    const r = runJson([writeTmp(`paid-${field}.json`, b), '--key', k.b64]);
    assert.equal(r.code, 1);
    assert.deepEqual(verdicts(r.report), [true, true, true, false, null], field);
    assert.equal(r.report.checks[3].broken_at, 43);
  }
});

test('tokens_used: 0 is allowed', () => {
  const k = throwawayKey();
  const b = sample();
  b.chain[42].tokens_used = 0;
  b.chain = rebuild(b.chain, k.privateKey);
  b.public_key = k.pem;
  assert.equal(run([writeTmp('zero-tokens.json', b), '--key', k.b64]).code, 0);
});

test('empty, malformed and unreadable input exits 2', () => {
  const cases = {
    'empty-file.json': '',
    'not-json.json': '{"chain": [',
    'array.json': '[]',
    'no-chain.json': '{}',
    'empty-chain.json': '{"chain": []}',
    'null-entry.json': '{"chain": [null], "public_key": "x"}',
  };
  for (const [name, text] of Object.entries(cases)) {
    const r = run([writeTmp(name, text)]);
    assert.equal(r.code, 2, `${name}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /bad input/, name);
  }
  // A bundle with no embedded key still verifies on the built-in keys, but
  // --embedded-key has nothing to use.
  const noKey = writeTmp('no-key.json', JSON.stringify({ chain: sample().chain }));
  assert.equal(run([noKey]).code, 0);
  assert.equal(run([noKey, '--embedded-key']).code, 2);
  assert.equal(run([path.join(TMP, 'does-not-exist.json')]).code, 2);
  assert.equal(run([SAMPLE_PATH, '--key', 'not a key!']).code, 2);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'pem', type: 'spki' });
  assert.equal(run([SAMPLE_PATH, '--key', rsa]).code, 2);
  assert.equal(run([]).code, 2);
  assert.equal(run([SAMPLE_PATH, '--bogus']).code, 2);
  const j = run([writeTmp('empty-chain.json', '{"chain": []}'), '--json']);
  assert.equal(j.code, 2);
  assert.equal(JSON.parse(j.stdout).ok, false);
});

test('the CLI never touches the network unless --fetch-anchors is given', () => {
  const src = fs.readFileSync(CLI, 'utf8') + fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
  assert.doesNotMatch(src, /require\(['"]node:(https?|net|tls|dgram|dns|http2)['"]\)|fetch\(/);
  // The one online module is loaded only inside the --fetch-anchors branch.
  const cli = fs.readFileSync(CLI, 'utf8');
  const loads = cli.match(/require\(['"]\.\.\/lib\/fetch-anchors\.js['"]\)/g) || [];
  assert.equal(loads.length, 1);
  assert.match(cli, /if \(args\.fetchAnchors\) \{\s*\n\s*await require\('\.\.\/lib\/fetch-anchors\.js'\)/);
});

test('cross-check: CLI and the live page\'s runChecks agree on sample, stripped and tampered copies', async (t) => {
  const subtleEd25519 = await crypto.webcrypto.subtle
    .importKey('spki', Buffer.from(SAMPLE_KEY_B64, 'base64'), { name: 'Ed25519' }, false, ['verify'])
    .then(() => true, () => false);
  if (!subtleEd25519) { t.skip('this Node lacks WebCrypto Ed25519'); return; }

  const copies = { sample: sample(), stripped: strippedCopy(), tampered: tamperedCopy() };
  const expected = {
    sample: [true, true, true, true, null],
    stripped: [true, false, true, true, null],
    tampered: [false, true, true, true, null],
  };
  for (const [name, b] of Object.entries(copies)) {
    const page = await pageRunChecks(b, SAMPLE_KEY_B64);
    const lib = verifyBundle(parseBundle(JSON.stringify(b)), loadPublicKey(SAMPLE_KEY_B64).keyObject);
    const cli = runJson([writeTmp(`xcheck-${name}.json`, b), '--key', SAMPLE_KEY_B64]).report;
    assert.deepEqual(page.map((r) => r.pass), expected[name], `page on ${name}`);
    assert.deepEqual(lib.checks.map((c) => c.pass), expected[name], `lib on ${name}`);
    assert.deepEqual(verdicts(cli), expected[name], `cli on ${name}`);
    // Same first broken entry for checks 1 and 2.
    for (const i of [0, 1]) {
      assert.equal(cli.checks[i].broken_at, page[i].brokenAt, `${name} check ${i + 1} broken entry`);
    }
  }
});
