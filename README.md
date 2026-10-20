# cascade-verify

Check a Cascade receipt bundle on your own machine, offline, without trusting
Cascade.

Cascade is a coordination API: agents ask it for a resource (a "cell") and it
grants, queues or releases. Every decision is appended to a hash chain and
signed with Ed25519. A run can be exported as one JSON **receipt bundle**.
`cascade-verify` re-checks that bundle with nothing but Node's built-in crypto.
It has no dependencies and makes no network calls.

```
npx cascade-verify bundle.json --key MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8=
```

```
cascade-verify 0.1.0: run 31676d43, 2,252 entries
key: pinned with --key
     MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8=  (sha256 4704:83ca:00aa:208e)

  PASS  1. Chain integrity  2252 links walked from genesis; head 1b6e0eb98c2bc2c5  (9.8 ms)
  PASS  2. Signatures       2252 of 2252 signatures verified  (272.8 ms)
  PASS  3. Exclusivity      0 duplicate grants across 982 ASSIGNs  (0.3 ms)
  PASS  4. Zero tokens      no entry records model tokens or names a model  (0.2 ms)

VERIFIED: 4/4 checks passed. 2,252 entries in 283.5 ms, 7,942 entries/s
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
cascade-verify <bundle.json> [--key <PEM|base64 file or string>] [--json]
```

| Option | Meaning |
|--------|---------|
| `--key <k>` | The Ed25519 public key to verify signatures against: a file path, a PEM block, base64 SPKI, or a base64 raw 32-byte key. |
| `--json` | Machine-readable result on stdout. |
| `-` as the bundle | Read the bundle from stdin. |

Exit codes: **0** all four checks pass, **1** at least one check failed,
**2** bad input (unreadable file, invalid JSON, not a bundle, empty chain, bad key).

When a check fails, the output names the first broken entry (numbered from 1).

## Pin the key

Without `--key`, signatures are checked against the public key embedded in the
bundle, and the tool prints a warning. That catches accidental damage and naive
edits, but not a deliberate forgery: whoever edits a bundle can re-sign it with
their own key and embed that key instead. **Keep your own copy of the signer's
public key, obtained before you receive the bundle, and always pass it with
`--key`.** A re-signed bundle then fails check 2.

Cascade's production signing key, as published at
<https://cascadedynamics.ai/verify.html> on 2026-10-19:

```
MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8=
```

## The four checks

1. **Chain integrity.** Every entry re-hashes to its recorded hash, and each
   entry points at the previous entry's hash, starting from `genesis`. Any
   edited byte, inserted, removed or reordered entry breaks the chain.
2. **Signatures.** Every entry carries an Ed25519 signature over its hash that
   verifies under the pinned key. An entry with no signature fails.
3. **Exclusivity.** Replaying the grants and releases, no cell was granted to
   one agent while another agent held it.
4. **Zero tokens.** No entry records model tokens (`tokens_used > 0`) or names
   a model.

The exact format and algorithms are in [SPEC.md](SPEC.md).

## What a passing result proves, and what it doesn't

A pass, with a key you pinned independently, shows that:

* the holder of that signing key recorded exactly these decisions, in this
  order, and the record has not been edited since;
* according to the record, no resource was granted to two agents at once;
* according to the record, no decision entry used a language model.

It does **not** show that:

* **any action succeeded.** A receipt proves the decision and the record of
  it, not what happened next. If an agent was granted a cell, the receipt says
  it was granted; it says nothing about whether the agent then did its job;
* the signer was honest when it made the decisions. The checks show the record
  is intact and internally consistent, not that the coordinator ran correct
  code;
* the bundle is complete at the end. Entries dropped from the end of a chain
  leave a shorter chain that still verifies. Compare the head hash and entry
  count with values you recorded separately if that matters to you;
* anything about time. Timestamps are not checked;
* that the key you pinned is the right one. That is your part: get it from a
  source you trust, ahead of time.

## Known limitation: 64-bit hashes

Bundle format v1 truncates each SHA-256 hash to 16 hex characters (64 bits),
and the signatures cover those truncated hashes. That is weaker than a
long-lived audit record should be; SPEC.md §5 gives the numbers. A format v2
with full-length hashes is planned; this tool verifies format v1 only.

## Development

```
npm test                                   # node --test, offline
node scripts/check-page-drift.js           # maintainers: compare with the live browser verifier
```

The test suite runs the CLI against the public sample run
(`test/fixtures/proof-sample.json`, 2,252 entries) and against forged copies:
a changed byte, stripped and rebuilt signatures, a wrong key, an injected
double grant re-signed with a throwaway key, an added token count, and
malformed input. It also runs the browser verifier's own `runChecks` function
(a verbatim excerpt in `reference/`) on the same copies and asserts both reach
the same verdicts.

## License

MIT. See [LICENSE](LICENSE).
