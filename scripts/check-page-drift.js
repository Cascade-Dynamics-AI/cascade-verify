#!/usr/bin/env node
'use strict';
// Maintainer tool (uses the network; the CLI and the tests never do).
// Fetches the live browser verifier and reports whether its runChecks
// function still matches the snapshot in reference/page-runChecks.txt.
// Exit 0 = identical, 1 = drifted, 2 = could not fetch or locate it.
// Usage: node scripts/check-page-drift.js [saved-verify.html]
// (pass a saved copy of the page to compare it without fetching)

const fs = require('node:fs');
const path = require('node:path');

const URL = 'https://cascadedynamics.ai/verify.html';
const snapshot = fs.readFileSync(path.join(__dirname, '..', 'reference', 'page-runChecks.txt'), 'utf8');

(async () => {
  let html;
  const src = process.argv[2] || URL;
  try {
    if (process.argv[2]) {
      html = fs.readFileSync(src, 'utf8');
    } else {
      const res = await fetch(URL);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      html = await res.text();
    }
  } catch (e) {
    console.error(`could not read ${src}: ${e.message}`);
    process.exit(2);
  }
  const lines = html.split(/\r?\n/);
  const start = lines.findIndex((l) => l.startsWith('async function runChecks('));
  const end = start < 0 ? -1 : lines.findIndex((l, i) => i > start && l === '}');
  if (start < 0 || end < 0) {
    console.error('runChecks not found on the live page');
    process.exit(2);
  }
  const live = lines.slice(start, end + 1).join('\n');
  if (live === snapshot) {
    console.log('live runChecks matches the snapshot');
    process.exit(0);
  }
  console.log('live runChecks DIFFERS from the snapshot; review the change, update');
  console.log('reference/page-runChecks.txt, and re-run npm test.');
  process.exit(1);
})();
