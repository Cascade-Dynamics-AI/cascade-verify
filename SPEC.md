# Cascade receipt bundle: formats v1 and v2, and the verification checks

This document describes the receipt bundle Cascade exports for a run and the
four checks `cascade-verify` performs on it. It is written so that anyone can
build an independent verifier from it. The reference implementation is
`lib/verify.js`. Sections 1–5 describe format v1; section 6 describes what
format v2 changes. A verifier applies the v1 rules to every entry without a
`v` field and the v2 rules to every entry with `"v": 2`.

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
a failing check names its first failing entry. All four checks always run.

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

Check 3.2 is only as strong as the key it uses. The key embedded in a bundle
travels with the bundle, so someone who edits a bundle can re-sign it with their
own key and embed that key. **To detect a re-signed bundle, verify against a copy
of the signer's public key you obtained independently and in advance**
(`cascade-verify bundle.json --key <key>`). Without `--key`, `cascade-verify`
uses the embedded key and prints a warning.

The Cascade production signing key, as published on cascadedynamics.ai/verify.html
on 2026-10-19:

```
MCowBQYDK2VwAyEAuJIhdAZ1VQqAs+7rx1c/t3GH9MC9p+PcZfri+mvXTZ8=
```

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
