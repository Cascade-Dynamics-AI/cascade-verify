#!/usr/bin/env node
'use strict';
// cascade-verify: check a Cascade receipt bundle offline.
// Exit 0 = all four checks pass, 1 = a check failed, 2 = bad input.

const fs = require('node:fs');
const crypto = require('node:crypto');
const { InputError, parseBundle, loadPublicKey, verifyBundle } = require('../lib/verify.js');
const { version } = require('../package.json');

const USAGE = `cascade-verify ${version}

Usage: cascade-verify <bundle.json> [--key <PEM|base64 file or string>] [--json]

  --key <k>    Pin this Ed25519 public key (a file path, a PEM block or base64).
               Without it the key embedded in the bundle is used, which does
               NOT detect a bundle that was re-signed with a different key.
  --json       Print the result as JSON on stdout.
  -h, --help   Show this help.
  --version    Print the version.

Exit codes: 0 all checks pass, 1 a check failed, 2 bad input.
Runs fully offline.`;

function parseArgs(argv) {
  const out = { bundle: null, key: null, json: false, help: false, version: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '-h' || a === '--help') out.help = true;
    else if (a === '--version') out.version = true;
    else if (a === '--key') {
      if (i + 1 >= argv.length) throw new InputError('--key needs a value');
      out.key = argv[++i];
    } else if (a.startsWith('--key=')) out.key = a.slice('--key='.length);
    else if (a.startsWith('-') && a !== '-') throw new InputError(`unknown option ${a}`);
    else if (out.bundle === null) out.bundle = a;
    else throw new InputError(`unexpected argument ${a}`);
  }
  return out;
}

function readKeyArg(k) {
  let text = k;
  try {
    if (fs.statSync(k).isFile()) text = fs.readFileSync(k, 'utf8');
  } catch { /* not a file: treat the value as the key itself */ }
  return loadPublicKey(text);
}

const fingerprint = (spkiB64) =>
  crypto.createHash('sha256').update(Buffer.from(spkiB64, 'base64')).digest('hex').slice(0, 16)
    .replace(/(.{4})(?!$)/g, '$1:');

const fmt = (n) => n.toLocaleString('en-US');

function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`cascade-verify: ${e.message}\n\n${USAGE}\n`);
    return 2;
  }
  if (args.help) { process.stdout.write(USAGE + '\n'); return 0; }
  if (args.version) { process.stdout.write(version + '\n'); return 0; }
  if (!args.bundle) { process.stderr.write(USAGE + '\n'); return 2; }

  let bundle, key, keySource;
  try {
    let text;
    try {
      text = fs.readFileSync(args.bundle === '-' ? 0 : args.bundle, 'utf8');
    } catch (e) {
      throw new InputError(`cannot read ${args.bundle} (${e.code || e.message})`);
    }
    bundle = parseBundle(text);
    if (args.key) {
      key = readKeyArg(args.key);
      keySource = 'pinned';
    } else if (bundle.publicKey) {
      key = loadPublicKey(bundle.publicKey);
      keySource = 'embedded';
    } else {
      throw new InputError('the bundle embeds no public key; pass one with --key');
    }
  } catch (e) {
    if (!(e instanceof InputError)) throw e;
    if (args.json) process.stdout.write(JSON.stringify({ ok: false, error: e.message }) + '\n');
    process.stderr.write(`cascade-verify: bad input: ${e.message}\n`);
    return 2;
  }

  const embeddedDiffers = keySource === 'pinned' && bundle.publicKey &&
    (() => { try { return loadPublicKey(bundle.publicKey).spkiB64 !== key.spkiB64; } catch { return true; } })();

  if (keySource === 'embedded') {
    process.stderr.write(
      '\n  WARNING: no --key given, so signatures are checked against the key EMBEDDED IN THE BUNDLE.\n' +
      '  A bundle that was edited and re-signed with a different key would still pass check 2.\n' +
      '  Pin your own copy of the signer\'s public key, obtained in advance: --key <file|PEM|base64>\n\n');
  }

  const report = verifyBundle(bundle, key.keyObject);

  if (args.json) {
    process.stdout.write(JSON.stringify({
      ok: report.pass,
      run: bundle.run,
      entries: report.entries,
      key: { source: keySource, spki_b64: key.spkiB64, fingerprint: fingerprint(key.spkiB64),
        embedded_differs: Boolean(embeddedDiffers) },
      formats: report.formats,
      seal: report.seal,
      segment: report.segment,
      notes: report.notes,
      checks: report.checks.map((c) => ({ id: c.id, title: c.title, pass: c.pass,
        broken_at: c.brokenAt, detail: c.detail, ms: +c.ms.toFixed(2) })),
      total_ms: +report.totalMs.toFixed(2),
      entries_per_sec: report.entriesPerSec,
    }, null, 2) + '\n');
    return report.pass ? 0 : 1;
  }

  const out = [];
  out.push(`cascade-verify ${version}: run ${bundle.run || '(unnamed)'}, ${fmt(report.entries)} entries`);
  out.push(`key: ${keySource === 'pinned' ? 'pinned with --key' : 'EMBEDDED in the bundle (not independently pinned)'}`);
  out.push(`     ${key.spkiB64}  (sha256 ${fingerprint(key.spkiB64)})`);
  if (embeddedDiffers) out.push('     note: the bundle embeds a DIFFERENT key than the one you pinned');
  const { v1, v2 } = report.formats;
  out.push(`format: ${v2 === 0 ? 'v1' : v1 === 0 ? 'v2' : `v1 (${fmt(v1)} entries), then v2 (${fmt(v2)} entries)`}` +
    (v2 === 0 && v1 === 0 ? ' (not determined: the chain check stopped early)' : ''));
  if (report.seal) out.push(`seal: commits to entry ${fmt(report.seal.seq)}, signed ${report.seal.at || '(no time)'}`);
  if (report.segment) out.push(`segment: entries ${fmt(report.segment.from)}-${fmt(report.segment.to)} of a longer chain`);
  for (const n of report.notes) out.push(`note: ${n}`);
  out.push('');
  report.checks.forEach((c, i) => {
    out.push(`  ${c.pass ? 'PASS' : 'FAIL'}  ${i + 1}. ${c.title.padEnd(16)} ${c.detail}  (${c.ms.toFixed(1)} ms)`);
  });
  out.push('');
  const passed = report.checks.filter((c) => c.pass).length;
  const rate = report.entriesPerSec ? `, ${fmt(report.entriesPerSec)} entries/s` : '';
  if (report.pass) {
    out.push(`VERIFIED: 4/4 checks passed. ${fmt(report.entries)} entries in ${report.totalMs.toFixed(1)} ms${rate}`);
  } else {
    const first = report.checks.find((c) => !c.pass);
    out.push(`NOT VERIFIED: ${passed}/4 checks passed. First failure: check ${report.checks.indexOf(first) + 1} ` +
      `(${first.title})${first.brokenAt ? ` at entry ${first.brokenAt}` : ''}. ` +
      `${fmt(report.entries)} entries in ${report.totalMs.toFixed(1)} ms${rate}`);
  }
  process.stdout.write(out.join('\n') + '\n');
  return report.pass ? 0 : 1;
}

process.exitCode = main(process.argv.slice(2));
