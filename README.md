# cascade-verify

Check a Cascade receipt bundle on your own machine, offline, without trusting
Cascade.

Cascade is a coordination API: agents ask it for a resource (a "cell") and it
grants, queues or releases. Every decision is appended to a hash chain and
signed with Ed25519. A run can be exported as one JSON **receipt bundle**.
`cascade-verify` re-checks that bundle with nothing but Node's built-in crypto.
It has no dependencies and makes no network calls (unless you ask it to fetch
the public anchor log with `--fetch-anchors`).

```
npx cascade-verify bundle.json
```

```
cascade-verify 0.3.0: run 31676d43, 2,252 entries
key: Cascade production (built in) — the pre-KMS production key, retired
     MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8=  (sha256 4704:83ca:00aa:208e)
format: v1
note: no seal: entries dropped from the end of a v1 bundle would not be detected

  PASS  1. Chain integrity  2252 links walked from genesis; head 1b6e0eb98c2bc2c5  (14.3 ms)
  PASS  2. Signatures       2252 of 2252 signatures verified  (275.5 ms)
  PASS  3. Exclusivity      0 duplicate grants across 982 ASSIGNs  (0.3 ms)
  PASS  4. Zero tokens      no entry records model tokens or names a model  (0.2 ms)
  SKIP  5. Anchored         the bundle carries no anchors (anchoring is hourly)  (0.0 ms)

VERIFIED: 4/4 checks passed (1 skipped). 2,252 entries in 291.3 ms, 7,730 entries/s
```

## Install

Requires Node.js 18 or later.

```
npm install -g cascade-verify      # or run it once with npx
```

Or with no package manager at all: copy `bin/` and `lib/` and run
`node bin/cascade-verify.js`.

## Usage

```
cascade-verify <bundle.json> [--key <k>] [--root <k>] [--fetch-anchors] [--json]
```

| Option | Meaning |
|--------|---------|
| (none) | Check against Cascade's published production keys, built into this tool. |
| `--key <k>` | Pin a key for entries signed directly (no session key), e.g. an on-prem deployment's own key: a file path, a PEM block, base64 SPKI, or a base64 raw 32-byte key. |
| `--root <k>` | Pin a root key for session-key certificates and anchors. Repeatable. |
| `--fetch-anchors` | Download each anchor from the public anchor log and require it to match the bundle's copy. The only option that uses the network. |
| `--anchor-log <url>` | Base URL of the anchor log (default `https://cascadedynamics.ai/anchors/`). |
| `--embedded-key` | Use the key embedded in the bundle. Prints a warning: this detects nothing a forger could not redo. |
| `--json` | Machine-readable result on stdout. |
| `-` as the bundle | Read the bundle from stdin. |

Exit codes: **0** every check passes (a skipped check is not a failure),
**1** at least one check failed, **2** bad input (unreadable file, invalid
JSON, not a bundle, empty chain, bad key).

When a check fails, the output names the first broken entry (numbered from 1).

## The keys

A signature check is only as good as the key it trusts. A key that travels with
the bundle can be swapped by whoever edits the bundle, so this tool **pins
Cascade's production keys itself**, as published at
<https://cascadedynamics.ai/verify.html>:

```
root   MCowBQYDK2VwAyEAulsbuhPp9+zChbyASphQrkm1+TWGrO0Cd8GMQFYWCXw=   (from 2026-10-23)
legacy MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8=   (2026-10-19 to 2026-10-23, retired)
```

* The **root key** was generated inside AWS KMS and cannot be exported, by
  Cascade or anyone else. It never signs entries: it certifies short-lived
  **session keys**, which live only in the server's memory, are replaced every
  hour, and sign the entries. Each bundle carries the certificates for the
  session keys it uses.
* The **legacy key** signed entries directly before production moved to session
  keys. It signs nothing new. A chain may start with legacy-signed entries, but
  once it is session-signed, a legacy-signed entry after that fails.

For an on-prem deployment, pin its own key with `--key`.

## Anchors

Every hour, Cascade publishes a root-signed Merkle root over the head of every
chain to a write-once log (S3 Object Lock, compliance mode, seven years: nobody
can overwrite or delete an anchor, Cascade included). A bundle carries its run's
anchors with inclusion proofs, and check 5 verifies them. With
`--fetch-anchors`, the tool also compares each one with the log's copy. Once a
head is anchored, a history rewritten before it cannot match both the log and
the chain. The first anchor after the move to session keys (`cutover`) covers
every chain head the legacy key signed.

## The five checks

1. **Chain integrity.** Every entry re-hashes to its recorded hash, and each
   entry points at the previous entry's hash, starting from `genesis`. Any
   edited byte, inserted, removed or reordered entry breaks the chain.
2. **Signatures.** Every entry carries an Ed25519 signature over its hash:
   by a certified session key (named by `kid`), or, for legacy entries, by the
   pinned key. An entry with no signature fails.
3. **Exclusivity.** Replaying the grants and releases, no cell was granted to
   one agent while another agent held it.
4. **Zero tokens.** No entry records model tokens (`tokens_used > 0`) or names
   a model.
5. **Anchored.** Every anchor in the bundle is signed by the root, its proof
   leads to this run's head at that point, and the chain has that head. SKIP
   when the bundle carries no anchors.

The exact format and algorithms are in [SPEC.md](SPEC.md).
## What a passing result proves, and what it doesn't

A pass, with keys pinned independently (the built-in ones, or your own), shows that:

* the holder of those signing keys recorded exactly these decisions, in this
  order, and the record has not been edited since;
* with anchors that match the public log, that the record up to the anchored
  head is the one that existed when it was anchored;
* according to the record, no resource was granted to two agents at once;
* according to the record, no decision entry used a language model.

It does **not** show that:

* **any action succeeded.** A receipt proves the decision and the record of
  it, not what happened next. If an agent was granted a cell, the receipt says
  it was granted; it says nothing about whether the agent then did its job;
* the signer was honest when it made the decisions. The checks show the record
  is intact and internally consistent, not that the coordinator ran correct
  code;
* for a **v1** bundle, that it is complete at the end. Entries dropped from the
  end of a v1 chain leave a shorter chain that still verifies. Format v2 closes
  this: a v2 bundle carries a signed seal over its entry count and head, and a
  bundle cut short fails check 1 naming the first missing entry. Even in v2 the
  seal shows completeness as of the time it was signed (printed with the
  result), and cannot stop the signer itself from sealing a shorter history;
  keep the `entry_hash` receipts the API returns if that matters to you;
* anything about time. Timestamps are not checked;
* that the key you pinned is the right one. That is your part: get it from a
  source you trust, ahead of time.

## Formats v1 and v2

Bundle format v1 truncates each SHA-256 hash to 16 hex characters (64 bits),
and the signatures cover those truncated hashes. That is weaker than a
long-lived audit record should be; SPEC.md §5 gives the numbers.

Format v2 (SPEC.md §6) uses the full 256-bit hash, signed in full, records each
entry's position and a run header inside the signed body, and adds the signed
seal described above. This tool verifies both, entry by entry: v1 bundles
verify exactly as before, a v1 chain that continues in v2 is checked across
the boundary, and a chain may never go back from v2 to v1. The output names
the format, the seal, and whether the bundle is a segment of a longer chain.

## Development

```
npm test                                   # node --test, offline
node scripts/check-page-drift.js           # maintainers: compare with the live browser verifier
```

The test suite runs the CLI against the public sample run
(`test/fixtures/proof-sample.json`, 2,252 entries) and against forged copies:
a changed byte, stripped and rebuilt signatures, a wrong key, an injected
double grant re-signed with a throwaway key, an added token count, and
malformed input. For format v2 it uses fixtures written by Cascade's own
writer with a throwaway key (`test/fixtures/v2-*.json`: a v2 run, a v1 run
rolled over to v2, and a segment) and forged copies: a tampered entry,
stripped signatures, a cut-short tail with and without its seal, an edited
seal, a wrong key, a downgrade, a wrong position, a missing header, a short
hash, a forged rollover and a lost segment anchor. It also runs the browser
verifier's own `runChecks` function (a verbatim excerpt in `reference/`) on
the same copies and asserts both reach the same verdicts.

## License

MIT. See [LICENSE](LICENSE).
