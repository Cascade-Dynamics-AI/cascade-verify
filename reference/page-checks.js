'use strict';
// Runs the browser verifier's own check function under Node, so the tests can
// confirm the CLI and https://cascadedynamics.ai/verify.html agree.
//
// page-runChecks.txt and page-helpers.txt are verbatim excerpts of that page's
// inline script (function runChecks, plus the b64ToBytes and sha256hex
// helpers), snapshotted 2026-10-19; runChecks re-snapshotted 2026-10-20 from the
// format-v2 page and 2026-10-23 from the session-key and anchor page.
// scripts/check-page-drift.js compares the snapshot with the live page; it is
// the only part of this repo that uses the network, and it is never run by the
// tests.

const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');

const helpers = fs.readFileSync(path.join(__dirname, 'page-helpers.txt'), 'utf8');
const runChecksSrc = fs.readFileSync(path.join(__dirname, 'page-runChecks.txt'), 'utf8');

// The page's production root pin (ROOT_B64 in verify.html).
const PAGE_ROOT_B64 = 'MCowBQYDK2VwAyEAulsbuhPp9+zChbyASphQrkm1+TWGrO0Cd8GMQFYWCXw=';
const offline = async () => { throw new Error('offline'); };

// keyB64: base64 SPKI of the plain key to pin (the page's ACTIVE_KEY_B64).
// opts.rootB64: the root pin (default: the page's). opts.fetch: what the page's
// anchor-log comparison calls (default: offline, so check 5 SKIPs after its
// offline checks pass). opts.anchorLog: the log base (default '/anchors/').
async function pageRunChecks(bundle, keyB64, opts = {}) {
  const factory = new Function('crypto', 'performance', 'atob', 'fetch', 'ACTIVE_KEY_B64', 'ROOT_B64', 'ANCHOR_LOG',
    `const enc=new TextEncoder();
     ${helpers}
     const KEY_SRC='USER';
     const keyCache=new Map();
     const importKeyB64=(b64)=>{ if(!keyCache.has(b64)) keyCache.set(b64,crypto.subtle.importKey('spki',b64ToBytes(b64),{name:'Ed25519'},false,['verify']).catch(()=>null)); return keyCache.get(b64); };
     const activeKey=()=>importKeyB64(ACTIVE_KEY_B64);
     ${runChecksSrc}
     return runChecks;`);
  const runChecks = factory(webcrypto, performance, atob, opts.fetch || offline, keyB64,
    opts.rootB64 || PAGE_ROOT_B64, opts.anchorLog || '/anchors/');
  return runChecks(bundle);
}

module.exports = { pageRunChecks, runChecksSrc, PAGE_ROOT_B64 };
