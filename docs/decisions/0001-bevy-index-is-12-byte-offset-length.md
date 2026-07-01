# 1. Bevy index is a 12-byte `(offset, length)` array

Status: accepted (2026-07-01)

## Context

The published `aff4` reader (≤ 0.1.2) decoded each bevy `.index` as a 4-byte
`u32` array of cumulative *end* offsets, with a branch for a supposed
"Scudette/aff4-imager start-offset" variant. Its own corpus "reference" helper
encoded the same 4-byte assumption, so the test suite was green while the reader
returned zeros or garbage for every real image (e.g. `Base-Linear` sector 0 read
as zeros instead of its MBR) — a shared-fixture (LZNT1-style) trap.

## Decision

The AFF4 Standard v1.0 bevy index is a packed array of **12-byte little-endian
entries `(u64 byte_offset, u32 length)`**, one per chunk. A zero-length entry
marks a sparse chunk; a stored length equal to `chunkSize` means the chunk was
written uncompressed. The 4-byte formats and the `test_aff4_scudette` fixture are
removed.

This was established by an **independent oracle**, not by re-reading the spec
from memory: decoding `Base-Linear-AllHashes` under the 12-byte layout and
hashing the reconstructed ImageStream reproduces Evimetry's stored
MD5/SHA1/SHA256/SHA512/Blake2b exactly. No other layout does.

## Consequences

- The reader now returns correct bytes for the whole reference corpus (verified
  by a whole-image SHA-256 cross-check against a pyaff4-semantics reconstruction).
- Correctness tests must reconcile against an external oracle (Evimetry hashes,
  pyaff4), never a fixture we authored alone.
- The handoff that specified the 4-byte format was wrong; the doc directive
  "verify every offset against the spec + pyaff4, not this doc's recollection"
  is why the error was caught.
