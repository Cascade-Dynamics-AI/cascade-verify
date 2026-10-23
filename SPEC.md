# Cascade receipt bundle: formats v1 and v2, session keys, anchors, and the verification checks

This document describes the receipt bundle Cascade exports for a run and the
five checks `cascade-verify` performs on it. It is written so that anyone can
build an independent verifier from it. The reference implementation is
`lib/verify.js`. Sections 1–5 describe format v1; section 6 describes what
format v2 changes; section 7 describes session keys (entries signed by
short-lived keys that a root key certifies); section 8 describes the public
anchor log. A verifier applies the v1 rules to every entry without a `v` field
and the v2 rules to every entry with `"v": 2`.

## 1. Bundle

A bundle is one UTF-8 JSON object:

```json
{
  "run": "31676d43",
  "chain": [ /* entries, oldest first */ ],
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

| Field        | Required | Meaning |
|--------------|----------|---------|
| `chain`      | yes      | Array of entry objects, in the order they were recorded. `entries` is accepted as an alias. |
| `public_key` | no       | The signer's Ed25519 public key, as a PEM `PUBLIC KEY` block or base64 SPKI DER. `publicKey` is accepted as an alias. It is a convenience only; see §4. |
| `run`        | no       | Run identifier, for display. `run_id` is accepted as an alias. |
| `seal`       | v2: yes  | Signed entry count and head (§6.4). Required when the last entry is v2; checked when present on a v1 bundle. |
| `anchor`     | no       | `{seq, hash}` of the entry just before the first one in the bundle, when the bundle is a segment of a longer v2 chain (§6.5). |
| `certs`      | with session keys | Array of session-key certificates (§7.1): every one an entry or the seal names by `kid`. |
| `anchors`    | no       | Array of log anchors with inclusion proofs for this run (§8). Not to be confused with the segment `anchor` above. |
| `format`     | no       | `1` or `2`, informational. Verifiers decide per entry, never from this field. |

A bundle whose chain is missing, empty, or contains a non-object element is
malformed. A verifier must report malformed input separately from a failed
check (`cascade-verify` exits 2 for malformed input, 1 for a failed check).

## 2. Entry

Each entry is a JSON object. Two fields are reserved for the chain:

| Field  | Meaning |
|--------|---------|
| `hash` | 16 lowercase hex characters: the entry's chain hash (§3.1). |
| `sig`  | Base64 Ed25519 signature (64 bytes) over the ASCII bytes of `hash`. |

Every other field is the entry body, and all of it is covered by the hash,
including `prev`:

| Field         | Meaning |
|---------------|---------|
| `prev`        | The previous entry's `hash`, or the string `"genesis"` for the first entry. |
| `verb`        | The decision: `ASSIGN` (cell granted to agent), `RELEASE` (cell freed), `HOLD` (agent queued behind the holder). Other verbs may appear; the checks below ignore them. |
| `cell`        | The resource the decision is about. |
| `agent`       | The agent the decision is about. |
| `entry`, `t`, `detail`, `behind`, ... | Descriptive fields. Verifiers must hash them exactly as they appear and must not interpret them. |

Example (from the public sample):

```json
{"t":null,"verb":"ASSIGN","cell":"maze/0-0","agent":"unit-01","entry":1,
 "detail":"unit-01 → maze/0-0 · reserve","prev":"genesis",
 "hash":"78da235b415400f0","sig":"mNhqw971...rUKqAQ=="}
```

## 3. Checks

Entries are numbered from 1 in chain order. Each check reports pass or fail;
a failing check names its first failing entry. All five checks always run.
Check 5, Anchored (§8.3), may also report SKIP, when the bundle carries no
anchors; a skip does not fail the bundle.

### 3.1 Chain integrity

```
prev := "genesis"
for each entry e, in order:
    rest := e without the keys "hash" and "sig"
    require rest.prev == prev
    require e.hash == hex(SHA-256(prev ‖ JSON.stringify(rest)))[0:16]
    prev := e.hash
```

* `‖` is string concatenation; the result is hashed as UTF-8.
* `JSON.stringify(rest)` is the ECMAScript serialization with no whitespace
  and with keys in the order they appear in the parsed entry (ECMAScript
  `JSON.parse` order: integer-like keys first in ascending order, then other
  keys in source order). The public sample contains no integer-like keys. A verifier in
  another language must reproduce this serialization byte for byte, including
  ECMAScript's string escaping and number formatting.
* A changed byte anywhere in an entry body, an inserted entry, a removed entry,
  or reordered entries changes a hash and breaks the chain at that point.

**What it proves on its own:** nothing against a forger. Anyone can recompute
every hash after an edit. Integrity only becomes meaningful together with 3.2.

### 3.2 Signatures

```
for each entry e, in order:
    require e.sig is a non-empty string            # missing => FAIL
    require Ed25519.verify(pinned_key, message = UTF-8(e.hash), signature = base64decode(e.sig))
```

This is the rule for an entry signed directly by a pinned key (no `kid`).
An entry with `kid` is signed by a session key instead; see §7.2.

**Every entry must carry a valid signature. A missing signature is a failure,
never a skip.** A verifier that skipped unsigned entries could be defeated by
stripping all signatures, editing entries, and rebuilding the hash links. (The
browser verifier had this bug until 2026-10-19.)

Because each signature covers a hash, and each hash covers the entry body and
the previous hash, a valid signature on entry *n* together with check 3.1
commits the signer to entries 1..*n*.

### 3.3 Exclusivity

```
held := {}                       # cell -> agent
for each entry e, in order:
    if e.verb == "ASSIGN":
        if held[e.cell] exists and held[e.cell] != e.agent: duplicate
        held[e.cell] := e.agent
    if e.verb == "RELEASE":
        delete held[e.cell]
```

The check fails if there is at least one duplicate: a cell granted to one agent
while the record shows a different agent still holding it.

Limits, stated plainly: a `RELEASE` frees the cell whichever agent it names;
re-granting a cell to its current holder is not a duplicate; `HOLD` and other
verbs are ignored. Leases that expire by time are not modelled; the record is
expected to contain an explicit `RELEASE`.

### 3.4 Zero tokens

The check fails if any entry has `tokens_used` greater than 0 or carries a
non-empty `model` field. This tests what the record says: decisions were made
without a language model. It cannot prove that no model was involved anywhere
else in a client's system.

The browser verifier at cascadedynamics.ai/verify.html only flags `model`
values matching common model-family names; `cascade-verify` flags any non-empty
`model`, so it is slightly stricter. They agree on every bundle Cascade emits.

## 4. Key pinning

Check 3.2 is only as strong as the keys it uses. The key embedded in a bundle
travels with the bundle, so someone who edits a bundle can re-sign it with their
own key and embed that key. **To detect a re-signed bundle, verify against keys
you obtained independently and in advance.** A verifier pins two kinds of key:

* **Root keys** certify session keys (§7) and sign anchors (§8). They never sign
  entries.
* **Plain keys** sign entries directly, with no `kid`: a legacy production key,
  or an on-prem deployment's own key.

`cascade-verify` has Cascade's production keys built in and uses them unless told
otherwise: `--key <k>` pins a different plain key (e.g. an on-prem key),
`--root <k>` a different root. `--embedded-key` uses the bundle's own key and
prints a warning; it detects nothing a forger could not redo.

Cascade's production keys, as published on cascadedynamics.ai/verify.html:

```
root   MCowBQYDK2VwAyEAulsbuhPp9+zChbyASphQrkm1+TWGrO0Cd8GMQFYWCXw=   (from 2026-10-23)
legacy MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8=   (2026-10-19 to 2026-10-23, retired)
```

The root key was generated inside AWS KMS (key spec `ECC_NIST_EDWARDS25519`)
and cannot be exported. The legacy key signed entries directly until production
moved to session keys; it signs nothing new, and the cutover anchor (§8.4)
commits to every chain head it signed.

## 5. Known limitations of format v1

Both are closed by format v2 (§6) for chains written in v2.

* **Hashes are truncated to 64 bits** (16 hex characters of SHA-256). That is
  short of what a long-lived audit record should have. Forging a body that
  matches an existing signed hash costs about 2^64 SHA-256 evaluations, which
  is within reach of a well-resourced attacker; a party who can influence what
  gets recorded (for example, the text of a field it supplies) can search for
  two bodies with the same hash at about 2^32 work, and one signature then
  covers both. Signatures do not fix this, because they sign the truncated hash.
  v1 bundles remain verifiable as v1, with this limit.
* The signature is over the hash string, not over the entry body directly.
* There is no signed run header. Check 3.1 detects removal of entries from the
  start or middle of a chain, but a chain cut short at the end (the last
  entries dropped) still verifies, since every remaining entry is signed. A v1
  bundle exported with a seal (§6.4) does detect it; an old v1 bundle without
  one does not. Compare the head hash and entry count with a value you recorded
  separately if truncation matters to you.
* Timestamps (`t`) may be null and are not checked.

## 6. Format v2

### 6.1 Entry

A v2 entry has two more reserved fields, both inside the hashed body:

| Field | Meaning |
|-------|---------|
| `v`   | The number `2`. |
| `seq` | The entry's 1-based position in the whole chain (v1 entries before a rollover included). Entry *n* has `seq` *n*. |
| `hdr` | The run header, on the first v2 entry only (§6.3). |

`hash` is 64 lowercase hex characters: the full SHA-256, not truncated.
`sig` is Ed25519 over the UTF-8 bytes of all 64 characters.

```
rest := e without the keys "hash" and "sig"
require e.hash == hex(SHA-256(prev ‖ JSON.stringify(rest)))          # all 64 chars
```

### 6.2 Format order

Entries without `v` are v1; entries with `"v": 2` are v2; any other `v` is a
failure. Within a chain the format may change at most once, from v1 to v2. A
v1 entry after a v2 entry fails check 1 (a downgrade). For a v2 entry, check 1
also requires `seq` to equal its position.

### 6.3 Run header

The first v2 entry in a chain carries `hdr`:

```json
"hdr": {"format": "cascade-chain/2", "run": "…", "key": "<base64 SPKI>|null",
        "rollover": {"from_format": 1, "entries": 12, "head": "<v1 hash>",
                     "prefix_sha256": "<64 hex>"}}
```

* `hdr.format` must be `"cascade-chain/2"`. A later v2 entry with `hdr` fails.
* If the first v2 entry has `seq` 1, `rollover` must be absent.
* If its `seq` is *k* > 1 (a v1 chain that continues in v2), `rollover` must have
  `from_format` 1, `entries` *k*−1, `head` equal to the entry's `prev`, and
  `prefix_sha256` equal to SHA-256 over `JSON.stringify(e) + "\n"` for each of
  entries 1…*k*−1 in order, each re-serialized as parsed, `hash` and `sig`
  included. This binds the v1 prefix at full strength.
* `hdr.key` is informational. Signatures are always checked against the key
  you pin. Verifiers must ignore header fields they do not know.

### 6.4 Seal

```json
"seal": {"format": "cascade-seal/2", "run": "…", "seq": 120, "head": "<hash of entry 120>",
         "at": "<ISO-8601>", "sig": "<base64>"}
```

The signature is Ed25519 over the UTF-8 bytes of
`JSON.stringify({format, run, seq, head, at})`, with exactly those five keys in
that order (rebuild it from the fields; do not re-serialize the parsed object).

With *N* the position of the bundle's last entry:

* No seal and the last entry is v2: check 1 fails.
* `format` is not `"cascade-seal/2"`, or `seq`/`head` are malformed: check 1 fails.
* `seal.run` differs from the run header's `run` (when both are present): check 1 fails.
* `seal.seq` > *N*: entries *N*+1 … `seal.seq` are missing. Check 1 fails and
  names entry *N*+1.
* Otherwise the entry at position `seal.seq` must have hash `seal.head`, or
  check 1 fails naming it. If `seal.seq` < *N* the seal is older than the last
  entries; completeness is shown up to `seal.seq` only (a note is printed).
* The seal's signature must verify under the pinned key: check 2.

What a seal does not prove: it stops anyone other than the signer from
dropping the end of a bundle. It cannot stop the signer from sealing a shorter
history, or someone from presenting an older genuine seal with the matching
older prefix. `cascade-verify` prints the seal's `at` time. Keep the per-
decision `entry_hash` receipts the API returns to check a later bundle against.

### 6.5 Segments

A bundle of a v2 chain longer than the export cap carries the newest entries
and `anchor: {seq, hash}`. The walk starts from `anchor.hash` instead of
`"genesis"`; the first entry must be v2 with `seq` = `anchor.seq` + 1. The anchor
is covered by the first entry's signature (it is that entry's `prev`). Entries
are named by their `seq`. The run header and any v1 prefix lie before the
segment and are reported as not checked. A bundle whose first entry does not
start at `genesis` and has no matching anchor fails check 1 at entry 1.

## 7. Session keys

A deployment whose root key must never leave a hardware boundary (production
Cascade: AWS KMS) cannot sign every entry with it: signing happens inside the
decision's critical section and must be synchronous. Instead the root
certifies a short-lived **session key**, generated in the server's memory and
never written anywhere, and the session key signs entries and seals.

### 7.1 Certificate

```json
{"format": "cascade-key-cert/1", "kid": "3f1c…", "key": "<base64 SPKI>", "root": "9a2b…",
 "not_before": "<ISO-8601>", "not_after": "<ISO-8601>", "root_sig": "<base64>"}
```

* `kid`: the session key's id, the first 16 hex characters of SHA-256 over its
  SPKI DER. A verifier recomputes it from `key` and requires a match.
* `root`: the certifying root key's id, computed the same way.
* `root_sig`: Ed25519 by the root over the UTF-8 bytes of
  `JSON.stringify({format, kid, key, root, not_before, not_after})`, exactly
  those six keys in that order.
* A certificate is valid when `format` is `"cascade-key-cert/1"`, `kid` matches
  `key`, `root` names a pinned root key, `root_sig` verifies under it, and
  `not_before` < `not_after`. Production certificates are valid for 25 hours and
  replaced every hour.
* A bundle carries every certificate its entries and seal name, in `certs`.
  Every certificate in `certs` is checked, whether or not anything uses it; an
  invalid one fails check 2.

### 7.2 Entries signed by a session key

* The entry carries `kid` in its body, so the hash (and therefore the
  signature) covers it. `kid` may appear on v2 entries only; a `kid` on a v1
  entry fails check 1.
* Check 2 looks up `certs[kid]` (no certificate: fail) and verifies `sig` over
  the entry hash under that certificate's `key`.
* **Session keys only move forward.** Walking the chain, an entry signed by a
  session key whose `not_before` is earlier than that of a session key used
  before it fails check 2.
* **Once session-signed, never plain again.** An entry without `kid` after any
  entry with one fails check 2. Plain-key entries (§3.2) are valid only as a
  prefix: the legacy history before the chain moved to session keys.

### 7.3 Seal

A seal by a session key has `"format": "cascade-seal/3"` and a `kid`; its
signature covers `JSON.stringify({format, run, seq, head, at, kid})`, exactly
those six keys in that order. Its completeness rules are those of §6.4. For
check 2: the seal's certificate must be in `certs`, `at` must lie within its
`not_before`…`not_after`, its `not_before` must not be earlier than that of the
last session key that signed an entry, and the signature must verify under it.
A `cascade-seal/2` (no `kid`, signed by a plain key) on a chain with
session-signed entries fails check 2.

### 7.4 Time

**Verification never consults the verifier's own clock.** Every time rule
compares times inside the bundle with each other (an expired certificate does
not make an old record fail), so a bundle verifies the same today and in ten
years. The writer guarantees the rules can always hold for a genuine record,
whatever its clocks do:

* `not_before` is strictly increasing across every certificate the deployment
  ever issued (all processes, all restarts), and is set a few minutes before the
  issuing time to absorb small clock steps.
* A seal's `at` is never earlier than the previous seal's, and is kept inside
  its certificate's window.
* Anchor `at` times are strictly increasing, so no two anchors share a log file,
  and a published log file is never written a second time.

### 7.5 What session keys change, and what they do not

The root key cannot be extracted: it exists only in AWS KMS, which signs with it
on request and has no operation that exports it. A session key does exist in
the server's memory for up to 25 hours; someone who read it out of memory could
sign entries with it during that time. Anchors (§8) bound what such a key, or
the operator, can do afterwards: once a head is anchored, a different history
before it no longer matches the public log.

## 8. Anchors

Every hour, the server builds a Merkle tree over the current head of every
chain, has the root key sign the tree's root, and writes the signed document to
a public, write-once log. The leaves are never published; each run receives its
own inclusion proof.

### 8.1 Merkle tree

```
leaf(run, seq, head) = hex(SHA-256(UTF-8("leaf:" ‖ JSON.stringify({run, seq, head}))))
node(left, right)    = hex(SHA-256(UTF-8("node:" ‖ left ‖ right)))
```

Leaves are hashed level by level, pairing neighbours left to right; an odd node
at the end of a level is carried up unchanged. The prefixes keep a leaf from
ever being read as a node.

### 8.2 Anchor document and log

```json
{"format": "cascade-anchor/1", "at": "<ISO-8601>", "count": 812, "merkle_root": "<hex>",
 "cutover": false, "root": "<root key id>", "sig": "<base64>"}
```

`sig` is Ed25519 by the root key named by `root` over
`JSON.stringify({format, at, count, merkle_root, cutover})`, exactly those five
keys in that order (`cutover` is `true` or `false`). The document is published at
`https://cascadedynamics.ai/anchors/<at with ':' and '.' replaced by '-'>.json`,
in an S3 bucket under Object Lock in compliance mode with seven years'
retention: no one, including Cascade and the AWS account's root user, can
overwrite or delete a published anchor during that time.

A bundle carries anchors for its run as

```json
"anchors": [{"doc": { /* the published document */ }, "leaf": {"run": "…", "seq": 120, "head": "…"},
             "proof": [{"side": "L" | "R", "hash": "<hex>"}, …], "url": "…"}]
```

`proof` runs from the leaf to the root: at each step the running hash is
combined with `hash`, which sits on the given `side`.

### 8.3 Check 5: Anchored

For each anchor in the bundle: the document is well formed; `root` names a
pinned root key and `sig` verifies under it; `leaf.run` is the bundle's run;
the proof leads from `leaf(run, seq, head)` to `merkle_root`; and the bundle's
entry at `leaf.seq` exists and has hash `leaf.head`. Any failure fails check 5.
No anchors in the bundle: check 5 reports SKIP.

The offline check proves the root signed this anchor. That it is the anchor the
public log holds for that time is a separate, online step: `cascade-verify
--fetch-anchors` downloads each document from the log and requires every field
to match, and cascadedynamics.ai/verify.html always does. A history rewritten
after it was anchored cannot match both the signed anchor in the log and the
chain.

### 8.4 Cutover anchor

When production moved from the legacy key to session keys, the first anchor
(`"cutover": true`) was written before any session-signed entry, over the head
of every chain at that moment. It commits to everything the legacy key signed.
