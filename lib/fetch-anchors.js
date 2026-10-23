'use strict';
// The one online step (cascade-verify --fetch-anchors): compare each anchor a
// bundle carries with the copy in the public anchor log (SPEC.md §8). The CLI
// loads this module only when that flag is given; lib/verify.js never goes
// online.

// The public log file for an anchor: its time with ':' and '.' made URL- and
// filesystem-safe.
const anchorFile = (at) => String(at).replace(/[:.]/g, '-') + '.json';
const ANCHOR_FIELDS = ['format', 'at', 'count', 'merkle_root', 'cutover', 'root', 'sig'];

// Updates check 5 of `report` in place. Does nothing unless check 5 passed
// offline (a skip or a failure stands as it is).
async function fetchAnchors(bundle, report, base, userAgent) {
  const check = report.checks.find((c) => c.id === 'anchored');
  if (!check || check.pass !== true) return;
  const t0 = Date.now();
  for (const a of bundle.anchors) {
    const url = base.replace(/\/?$/, '/') + anchorFile(a.doc.at);
    let published;
    try {
      const res = await fetch(url, { headers: { 'User-Agent': userAgent } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      published = await res.json();
    } catch (e) {
      Object.assign(check, { pass: false, detail: `anchor ${a.doc.at} could not be fetched from the public log: ${url} (${e.message})` });
      report.pass = false;
      return;
    }
    const differs = ANCHOR_FIELDS.find((f) => JSON.stringify(published[f]) !== JSON.stringify(a.doc[f]));
    if (differs) {
      Object.assign(check, { pass: false, detail: `anchor ${a.doc.at} differs from the public log copy at ${url} (field ${differs})` });
      report.pass = false;
      return;
    }
  }
  check.detail += `; all ${bundle.anchors.length} match the public log`;
  check.ms += Date.now() - t0;
}

module.exports = { fetchAnchors, anchorFile, ANCHOR_FIELDS };
