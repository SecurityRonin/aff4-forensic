# `aff4-forensic` — Implementation Handoff

> **ARCHIVED — implemented 2026-06-30.** All four gaps (§1 hash verification, §2
> symbolic/"allocated" maps, §3 AFF4-L, §4 encryption detect-and-refuse) are
> done via strict RED→GREEN TDD, plus a foundational bevy-index fix (the index is
> 12-byte `(offset, length)`, not 4-byte cumulative ends — the reader mis-read
> every real image before it). Tier-1 validated against pyaff4 + Evimetry's stored
> hashes. Current-state docs: [`core/docs/corpus-validation.md`](../../core/docs/corpus-validation.md)
> and [`forensic/docs/validation.md`](../../forensic/docs/validation.md). Kept for
> historical reference; the sections below describe the original (pre-implementation)
> plan and its starting assumptions, some of which the implementation corrected.

**Status: RESTRUCTURED + SCAFFOLDED.** The published `aff4` reader was moved here
and split into the fleet `core/` + `forensic/` shape (like `ewf-forensic`). The
reader (`core/`, package `aff4`, published 0.1.2) is complete for the common case;
the analyzer (`forensic/`, package `aff4-forensic` 0.1.0) is a **stub**. This doc
is the strict-TDD plan to close the four documented gaps. A future session should
read it top-to-bottom, then build per the plan. **Verify every byte-offset / RDF
predicate / digest against the cited spec + `pyaff4`, not against this doc's
recollection** (Research-First).

---

## 0. Current state — read first

```
aff4-forensic/
├── Cargo.toml            # workspace: members = [core, forensic]; version NOT hoisted
├── core/                 # crate `aff4` (0.1.2, PUBLISHED) — the read-only reader
│   ├── src/{lib.rs,map.rs,meta.rs,error.rs,testutil.rs}
│   └── tests/{corpus.rs, data/*.aff4}   ← the AFF4 reference corpus (the ORACLES)
├── forensic/             # crate `aff4-forensic` (0.1.0) — the analyzer  [SCAFFOLD]
│   ├── Cargo.toml         # deps: aff4 + forensicnomicon + md-5/sha1/sha2/blake2
│   └── src/lib.rs         # Aff4Anomaly enum + audit_image() STUB
├── fuzz/                 # cargo-fuzz (aff4-fuzz), excluded from the workspace
└── HANDOFF.md            # this file
```
`cargo build --workspace` is green (reader + analyzer scaffold). First task:
`cargo test -p aff4` to confirm the reader's corpus tests still pass after the
move, then start §1.

### What the reader (`core/`, `aff4`) already does
Read-only AFF4 Standard v1.0 disk images (Evimetry / aff4-imager / pyaff4):
`aff4:Map` virtual-address mapping, all four chunk codecs (Null/Deflate/Snappy/LZ4),
sparse zero + 0xFF regions, URL-encoded ZIP entry names, the Scudette legacy bevy
index, `Read + Seek` over the virtual stream. Zero `unsafe`, no C bindings (now incl.
pure-Rust zip via `zip-forensic-core`). Validated against the reference corpus
(`core/tests/corpus.rs`). See `core/docs/implementation-notes.md` for format quirks.

---

## 1. Spec, prior art, and the oracle (do this BEFORE coding — Research-First)

- **Authoritative spec:** the **AFF4 Standard v1.0** — Schatz, *"AFF4-L: A Scalable
  Open Logical Evidence Container"* + the base AFF4 Standard. Primary sources:
  - AFF4 Standard repo: <https://github.com/aff4/Standard> (RDF predicates, stream
    types, hash properties).
  - **Reference corpus:** <https://github.com/aff4/ReferenceImages> — `Base-Linear`,
    `Base-Linear-AllHashes`, `Base-Allocated`, `Base-ExabyteSparse`, `Base-Linear-ReadError`.
    The relevant ones are already vendored in `core/tests/data/`.
- **Prior art / the Tier-1 ORACLE — `pyaff4`:** <https://github.com/aff4/pyaff4>
  (Google/Velocidex Python reference implementation). It verifies hashes, reads
  allocated maps, AFF4-L, and encrypted volumes. **For every gap, the validation is:
  open the same image with `pyaff4` and reconcile** (hashes, byte ranges, decrypted
  bytes). C++ reference: <https://github.com/aff4/aff4>.
- **Real data + oracle, per gap:**
  - Hash verification → `Base-Linear-AllHashes.aff4` (carries MD5/SHA1/SHA256/SHA512/
    Blake2b) — recompute, compare to the stored `aff4:hash`; cross-check with pyaff4.
  - Allocated maps → `Base-Allocated.aff4`.
  - AFF4-L / Encryption → source the AFF4-L + encrypted reference images from the
    corpus / pyaff4 test data (record provenance in `core/tests/data/README.md`).

---

## 2. The four gaps — which layer, and the strict-TDD plan

**Strict TDD is mandatory: a RED commit (failing test only) then a GREEN commit
(impl) for every step. The RED commit is the proof TDD happened.** Panic-free
(`unwrap_used`/`expect_used = deny`; bounds-check every length/offset from the
image before use). Validate against the reference image + pyaff4 (Tier-1), never a
fixture you authored alone (Doer-Checker / the LZNT1 trap).

### §1 — Hash verification → `forensic/` (the analyzer's headline)
This is an **integrity audit**, so it belongs in `aff4-forensic`, not the reader:
the reader returns bytes; the analyzer recomputes the declared `aff4:hash`(es) over
the virtual stream and emits a **finding** on mismatch (tamper / corruption signal).
- **Scope:** parse the `aff4:hash` / block-hash properties from `information.turtle`
  (and any per-bevy hash); recompute with the RustCrypto digests already declared
  (`md-5`/`sha1`/`sha2`/`blake2`); compare. Per the fleet principle, the analyzer
  MAY read the turtle itself (lower-level) rather than wait for a reader API — but
  prefer adding a small `aff4::stored_hashes()` accessor to `core/` if cleaner.
- **Codes:** `AFF4-HASH-MISMATCH` (stored ≠ recomputed — tamper signal),
  `AFF4-HASH-UNREADABLE` (a read-error region prevented hashing — see
  `Base-Linear-ReadError.aff4`). Emit `forensicnomicon::report::Finding` via
  `impl Observation for Aff4Anomaly` (stub the enum is in `forensic/src/lib.rs`).
- **TDD:** RED — `audit_image(Base-Linear-AllHashes.aff4)` returns **zero**
  mismatches (clean image); a second RED feeds a byte-flipped copy and expects one
  `AFF4-HASH-MISMATCH`. GREEN — implement recompute+compare. Findings are
  observations, never verdicts ("hash mismatch — consistent with tampering or
  media error", not "proves tampering").

### §2 — Allocated maps → `core/` (the reader)
`Base-Allocated.aff4` uses a map that marks **allocated vs unallocated** regions
(sparse imaging of only-allocated blocks). The reader's `map.rs` currently parses
the linear/symbolic map but not the allocated form.
- **Scope:** extend `map.rs` to resolve allocated-map entries (unallocated ranges
  read as zero-fill; allocated ranges resolve to the image stream). Verify the spec's
  map-entry layout against pyaff4's `aff4_map`.
- **TDD:** RED — read a known offset from `Base-Allocated.aff4` and assert the bytes
  match a pyaff4 extraction (currently fails — "allocated map parsing not yet
  implemented"). GREEN — implement.

### §3 — AFF4-L (AFF4-Logical, file-level container) → `core/` (reader, new capability)
AFF4-L stores **logical files** (paths + metadata + content), not a disk image —
a different stream/type family (`aff4:FileImage`, logical path properties). The
reader explicitly does not support it (`implementation-notes.md`). This is the
largest gap and integrates differently downstream: an AFF4-L container is a
**collection** of files (like a zip/UAC), so in issen it would feed an
`issen_unpack::CollectionProvider`, NOT the disk pipeline. (Mirror the AD1 plan:
AD1 is also a logical container — see `~/src/ad1-forensic`.)
- **Scope:** detect the AFF4-L profile in the turtle; enumerate logical entries
  (path, size, timestamps, content stream); expose a file-tree + positioned reads.
- **TDD:** RED — open an AFF4-L reference image, assert the file tree + one file's
  bytes match pyaff4. GREEN — implement. Source the AFF4-L sample from pyaff4 test
  data; record provenance.

### §4 — Encryption → `core/` (reader)
AFF4 encrypted volumes (password/key-based, AES) — `pyaff4` supports them via a
`aff4:encrypted`-profile turtle + a key-derivation block. Out of scope until a
real encrypted reference image + the exact KDF/cipher params are confirmed from the
spec + pyaff4.
- **Scope:** detect the encrypted profile; derive the key (RustCrypto — NEVER a
  hand-rolled cipher/KDF; if no mature crate fits a step, **refuse** loudly, never
  emit plausible-but-wrong bytes); decrypt-on-read. Detect-and-refuse is the v1
  floor; full decryption is a later epic.
- **TDD:** RED — opening an encrypted image without a key yields a named
  `Unsupported`/`encrypted`-error (no garbage); with the test key, a known plaintext
  range matches pyaff4. GREEN — implement detect→refuse first, then decrypt.

---

## 3. Fleet standards (binding — from issen CLAUDE.md)

- **Crate shape:** `aff4-forensic` repo = `core/` (reader, package `aff4`) +
  `forensic/` (analyzer, `aff4-forensic`), versioned independently. The bare `aff4`
  import path is kept (the crate is published as `aff4`).
- **`-forensic` is NOT required to depend on `-core`** — it may parse lower-level
  (the turtle, the raw ZIP) when the reader's clean API hides what an audit needs.
  For §1, depending on `core/`'s `Aff4Reader` for the data + reading the turtle for
  the stored hashes is fine; add a `core/` accessor only if it's cleaner.
- **Paranoid Gatekeeper:** untrusted attacker-controllable images → panic-free
  (bounds-checked integer reads → 0 on OOB; range-check every length/offset/count
  BEFORE use; cap allocations). `unwrap_used`/`expect_used = deny` (already set).
  **One fuzz target per parsed structure** + a `fuzz_forensic` driving open→audit;
  `fuzz.yml` builds + smoke-runs them. **Never hand-roll crypto** (§4) — RustCrypto only.
- **Tier-1 validation, documented** (`forensic/docs/validation.md` +
  `core/docs/corpus-validation.md`): reconcile against **pyaff4** on the real
  reference corpus; explain any divergence. Findings are observations ("consistent
  with"), never legal conclusions.
- **100% line coverage** (`cargo llvm-cov --lib`, `// cov:unreachable` for
  provably-dead defensive arms). README two-row badges = guarantees enforced;
  MkDocs docs site; footer Privacy/Terms; `deny.toml` (Apache-2.0 + permissive);
  `release.yml` (library → `crate` job; core + forensic published independently).
- **Report model:** `Aff4Anomaly` keeps its typed variants; convert to
  `forensicnomicon::report::Finding` via `impl Observation` (codes are a published
  contract: scheme-prefixed SCREAMING-KEBAB, never changed once shipped).

## 4. First commits (suggested)
1. `chore: restructure aff4 → aff4-forensic (core + forensic)` — this scaffold.
2. `test(aff4-forensic): RED — Base-Linear-AllHashes audits clean` → `feat: GREEN — recompute + compare aff4:hash`.
3. `test(aff4-forensic): RED — byte-flipped image yields AFF4-HASH-MISMATCH` → GREEN.
4. `test(aff4 core): RED — Base-Allocated read vs pyaff4` → GREEN (allocated maps).
5. Then AFF4-L (§3) and encryption-detect (§4), each RED→GREEN, validated vs pyaff4.
