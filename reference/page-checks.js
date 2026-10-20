'use strict';
// Runs the browser verifier's own check function under Node, so the tests can
// confirm the CLI and https://cascadedynamics.ai/verify.html agree.
//
// page-runChecks.txt and page-helpers.txt are verbatim excerpts of that page's
// inline script (function runChecks, plus the b64ToBytes and sha256hex
// helpers), snapshotted 2026-10-19; runChecks re-snapshotted 2026-10-20 from the
// format-v2 page (branch chain-v2 of the site repo, not yet deployed). scripts/check-page-drift.js compares the
// snapshot with the live page; it is the only part of this repo that uses the
// network, and it is never run by the tests.

const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');

const helpers = fs.readFileSync(path.join(__dirname, 'page-helpers.txt'), 'utf8');
const runChecksSrc = fs.readFileSync(path.join(__dirname, 'page-runChecks.txt'), 'utf8');

// keyB64: base64 SPKI of the key to pin (the page's ACTIVE_KEY_B64).
async function pageRunChecks(bundle, keyB64) {
  const factory = new Function('crypto', 'performance', 'atob', 'ACTIVE_KEY_B64',
    `const enc=new TextEncoder();
     ${helpers}
     const KEY_SRC='USER';
     const activeKey=()=>crypto.subtle.importKey('spki',b64ToBytes(ACTIVE_KEY_B64),{name:'Ed25519'},false,['verify']).catch(()=>null);
     ${runChecksSrc}
     return runChecks;`);
  const runChecks = factory(webcrypto, performance, atob, keyB64);
  return runChecks(bundle);
}

module.exports = { pageRunChecks, runChecksSrc };
