#!/usr/bin/env node
'use strict';
// cascade-verify: check a Cascade receipt bundle offline.
// Exit 0 = every check passes (a skipped check is not a failure),
// 1 = a check failed, 2 = bad input.

const fs = require('node:fs');
const { InputError, parseBundle, loadPublicKey, verifyBundle } = require('../lib/verify.js');
const { version } = require('../package.json');

// Cascade's published production keys (SPEC.md §4). Pinned here so a bundle
// is never checked against a key it brings itself.
//   root:  generated inside AWS KMS (alias/cascade/receipt-root), cannot be
//          exported; certifies session keys and signs anchors.
//   plain: the legacy production key, which signed entries directly until the
//          move to KMS session keys. Retired: it signs nothing new.
const PRODUCTION_ROOTS = ['MCowBQYDK2VwAyEAulsbuhPp9+zChbyASphQrkm1+TWGrO0Cd8GMQFYWCXw='];
const PRODUCTION_PLAIN = ['MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8='];
const PRODUCTION_ANCHOR_LOG = 'https://cascadedynamics.ai/anchors/';

const USAGE = `cascade-verify ${version}

Usage: cascade-verify <bundle.json> [options]

  With no key options, the bundle is checked against Cascade's published
  production keys, built into this tool.

  --key <k>          Pin this Ed25519 key for entries signed directly (no
                     session key), e.g. an on-prem deployment's own key.
                     A file path, a PEM block or base64. Replaces the built-in
                     legacy key; the built-in root stays unless --root is given.
  --root <k>         Pin this root key for session-key certificates and anchors.
                     Repeatable. Replaces the built-in root.
  --embedded-key     Check against the key EMBEDDED in the bundle. This does NOT
                     detect a bundle that was re-signed with a different key.
  --fetch-anchors    Also download each anchor from the public anchor log and
                     require it to match the bundle's copy (needs network).
  --anchor-log <url> Base URL of the anchor log (default ${PRODUCTION_ANCHOR_LOG}).
  --json             Print the result as JSON on stdout.
  -h, --help         Show this help.
  --version          Print the version.

Exit codes: 0 all checks pass, 1 a check failed, 2 bad input.
Runs fully offline unless --fetch-anchors is given.`;

function parseArgs(argv) {
  const out = { bundle: null, key: null, roots: [], embedded: false, fetchAnchors: false,
    anchorLog: PRODUCTION_ANCHOR_LOG, json: false, help: false, version: false };
  const value = (i, name) => {
    if (i + 1 >= argv.length) throw new InputError(`${name} needs a value`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '-h' || a === '--help') out.help = true;
    else if (a === '--version') out.version = true;
    else if (a === '--embedded-key') out.embedded = true;
    else if (a === '--fetch-anchors') out.fetchAnchors = true;
    else if (a === '--key') out.key = value(i++, '--key');
    else if (a.startsWith('--key=')) out.key = a.slice('--key='.length);
    else if (a === '--root') out.roots.push(value(i++, '--root'));
    else if (a.startsWith('--root=')) out.roots.push(a.slice('--root='.length));
    else if (a === '--anchor-log') out.anchorLog = value(i++, '--anchor-log');
    else if (a.startsWith('--anchor-log=')) out.anchorLog = a.slice('--anchor-log='.length);
    else if (a.startsWith('-') && a !== '-') throw new InputError(`unknown option ${a}`);
    else if (out.bundle === null) out.bundle = a;
    else throw new InputError(`unexpected argument ${a}`);
  }
  if (out.embedded && (out.key || out.roots.length)) throw new InputError('--embedded-key cannot be combined with --key or --root');
  return out;
}

function readKeyArg(k) {
  let text = k;
  try {
    if (fs.statSync(k).isFile()) text = fs.readFileSync(k, 'utf8');
  } catch { /* not a file: treat the value as the key itself */ }
  return loadPublicKey(text);
}

const fingerprint = (id) => id.replace(/(.{4})(?!$)/g, '$1:');
const fmt = (n) => n.toLocaleString('en-US');

async function main(argv) {
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

  let bundle, roots, plain, plainSource, rootSource;
  try {
    let text;
    try {
      text = fs.readFileSync(args.bundle === '-' ? 0 : args.bundle, 'utf8');
    } catch (e) {
      throw new InputError(`cannot read ${args.bundle} (${e.code || e.message})`);
    }
    bundle = parseBundle(text);
    if (args.embedded) {
      if (!bundle.publicKey) throw new InputError('the bundle embeds no public key');
      plain = [loadPublicKey(bundle.publicKey)];
      roots = [loadPublicKey(bundle.publicKey)];
      plainSource = rootSource = 'embedded';
    } else {
      plain = args.key ? [readKeyArg(args.key)] : PRODUCTION_PLAIN.map(loadPublicKey);
      plainSource = args.key ? 'pinned' : 'builtin';
      roots = args.roots.length ? args.roots.map(readKeyArg) : PRODUCTION_ROOTS.map(loadPublicKey);
      rootSource = args.roots.length ? 'pinned' : 'builtin';
    }
  } catch (e) {
    if (!(e instanceof InputError)) throw e;
    if (args.json) process.stdout.write(JSON.stringify({ ok: false, error: e.message }) + '\n');
    process.stderr.write(`cascade-verify: bad input: ${e.message}\n`);
    return 2;
  }

  const embeddedDiffers = !args.embedded && bundle.publicKey &&
    (() => {
      try {
        const id = loadPublicKey(bundle.publicKey).id;
        return !plain.some((k) => k.id === id) && !roots.some((k) => k.id === id);
      } catch { return true; }
    })();

  if (args.embedded) {
    process.stderr.write(
      '\n  WARNING: --embedded-key: signatures are checked against the key EMBEDDED IN THE BUNDLE.\n' +
      '  A bundle that was edited and re-signed with a different key would still pass check 2.\n' +
      '  Drop --embedded-key to use the published production keys, or pin your own with --key/--root.\n\n');
  }

  const report = verifyBundle(bundle, { roots, plain });
  // The only online step, loaded only when asked for.
  if (args.fetchAnchors) {
    await require('../lib/fetch-anchors.js').fetchAnchors(bundle, report, args.anchorLog, `cascade-verify/${version}`);
  }
  const sigCheck = report.checks.find((c) => c.id === 'signatures');
  const usedKeys = sigCheck.keys || { plain: [], sessions: [] };

  if (args.json) {
    const keyInfo = (k, source) => ({ source, spki_b64: k.spkiB64, fingerprint: fingerprint(k.id) });
    process.stdout.write(JSON.stringify({
      ok: report.pass,
      run: bundle.run,
      entries: report.entries,
      // `key`: the key for directly signed entries (kept from 0.2 for callers that read it).
      key: { ...keyInfo(plain[0], plainSource), embedded_differs: Boolean(embeddedDiffers) },
      keys: {
        roots: roots.map((k) => keyInfo(k, rootSource)),
        plain: plain.map((k) => keyInfo(k, plainSource)),
        used: usedKeys,
      },
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

  const label = { builtin: 'Cascade production (built in)', pinned: 'pinned by you', embedded: 'EMBEDDED in the bundle (not independently pinned)' };
  const out = [];
  out.push(`cascade-verify ${version}: run ${bundle.run || '(unnamed)'}, ${fmt(report.entries)} entries`);
  if (usedKeys.sessions.length) {
    out.push(`root key: ${label[rootSource]}`);
    for (const k of roots) out.push(`     ${k.spkiB64}  (sha256 ${fingerprint(k.id)})`);
    out.push(`session keys: ${usedKeys.sessions.length} certified by the root (${usedKeys.sessions.join(', ')})`);
  }
  if (usedKeys.plain.length || !usedKeys.sessions.length) {
    out.push(`${usedKeys.sessions.length ? 'legacy key' : 'key'}: ${label[plainSource]}` +
      (plainSource === 'builtin' ? ' — the pre-KMS production key, retired' : ''));
    for (const k of plain) out.push(`     ${k.spkiB64}  (sha256 ${fingerprint(k.id)})`);
  }
  if (embeddedDiffers) out.push('     note: the bundle embeds a DIFFERENT key than the ones checked against');
  const { v1, v2 } = report.formats;
  out.push(`format: ${v2 === 0 ? 'v1' : v1 === 0 ? 'v2' : `v1 (${fmt(v1)} entries), then v2 (${fmt(v2)} entries)`}` +
    (v2 === 0 && v1 === 0 ? ' (not determined: the chain check stopped early)' : ''));
  if (report.seal) out.push(`seal: commits to entry ${fmt(report.seal.seq)}, signed ${report.seal.at || '(no time)'}`);
  if (report.segment) out.push(`segment: entries ${fmt(report.segment.from)}-${fmt(report.segment.to)} of a longer chain`);
  for (const n of report.notes) out.push(`note: ${n}`);
  out.push('');
  report.checks.forEach((c, i) => {
    const mark = c.pass === null ? 'SKIP' : c.pass ? 'PASS' : 'FAIL';
    out.push(`  ${mark}  ${i + 1}. ${c.title.padEnd(16)} ${c.detail}  (${c.ms.toFixed(1)} ms)`);
  });
  out.push('');
  const ran = report.checks.filter((c) => c.pass !== null);
  const passed = ran.filter((c) => c.pass).length;
  const skipped = report.checks.length - ran.length;
  const skipNote = skipped ? ` (${skipped} skipped)` : '';
  const rate = report.entriesPerSec ? `, ${fmt(report.entriesPerSec)} entries/s` : '';
  if (report.pass) {
    out.push(`VERIFIED: ${passed}/${ran.length} checks passed${skipNote}. ${fmt(report.entries)} entries in ${report.totalMs.toFixed(1)} ms${rate}`);
  } else {
    const first = report.checks.find((c) => c.pass === false);
    out.push(`NOT VERIFIED: ${passed}/${ran.length} checks passed${skipNote}. First failure: check ${report.checks.indexOf(first) + 1} ` +
      `(${first.title})${first.brokenAt ? ` at entry ${first.brokenAt}` : ''}. ` +
      `${fmt(report.entries)} entries in ${report.totalMs.toFixed(1)} ms${rate}`);
  }
  process.stdout.write(out.join('\n') + '\n');
  return report.pass ? 0 : 1;
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; },
  (e) => { process.stderr.write(`cascade-verify: ${e.stack || e}\n`); process.exitCode = 2; });
