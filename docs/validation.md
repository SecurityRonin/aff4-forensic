# Validation (Tier-1)

`aff4-forensic` recomputes the integrity claims an AFF4 image makes about itself
and reconciles them against independent ground truth — Evimetry's own stored
`aff4:hash` digests on the reference corpus — not fixtures authored here alone.

## Hash verification (`AFF4-HASH-MISMATCH`)

`audit_image` recomputes every declared ImageStream `aff4:hash` (MD5, SHA1,
SHA256, SHA512, Blake2b — vetted RustCrypto digests) over the decompressed
ImageStream content in one streaming pass and emits an `AFF4-HASH-MISMATCH`
finding per divergence.

- **Clean image:** `Base-Linear-AllHashes.aff4` reconciles all five
  Evimetry-authored digests → zero mismatches.
- **Tamper:** flipping the first byte of the first stored-uncompressed chunk
  (derived from the 12-byte bevy index, not a magic offset) yields
  `AFF4-HASH-MISMATCH`.

The digests cover the ImageStream content (`aff4:size` bytes), not the
map-expanded virtual disk; no stored digest covers the full reconstructed disk,
so none is claimed.

## Unreadable regions (`AFF4-HASH-UNREADABLE`)

`Base-Linear-ReadError.aff4` carries 32 `aff4:UnreadableData` regions (2 MiB)
that could not be acquired. The audit emits one `AFF4-HASH-UNREADABLE` per region
(with its offset and length) while reporting **zero** `AFF4-HASH-MISMATCH` — the
intact ImageStream content still reconciles (stored MD5 `b2a8abd1…` matches), so
unreadable regions are reported as an integrity caveat, not as tampering.

## Epistemic framing

Findings are observations, never verdicts: a mismatch note reads "consistent with
tampering or media corruption", and an unreadable note states the caveat as a
property of the evidence ("whole-disk integrity cannot be fully established over
that region"). `Aff4Anomaly` maps to `forensicnomicon::report::Finding` via
`impl Observation` in the Integrity category. Finding codes
(`AFF4-HASH-MISMATCH`, `AFF4-HASH-UNREADABLE`) are a published contract.

## Reader corpus validation (Tier-1)

The sections above cover the **audit** (integrity findings). This section covers
the **reader** — the decode path validated against independent ground truth: the
AFF4 reference corpus authored by Evimetry 3.0 and pyaff4, plus the digests those
tools recorded, never a fixture authored here alone.

### Bevy index format

The AFF4 Standard v1.0 bevy index (`<bevy>.index`) is a packed array of **12-byte
little-endian entries `(u64 byte_offset, u32 length)`**, one per chunk — the
chunk's position and stored (possibly compressed) size within the bevy segment. A
zero-length entry marks a sparse (all-zero) chunk.

This was confirmed by **reproducing Evimetry's own stored `aff4:hash` digests**:
decompressing `Base-Linear-AllHashes.aff4`'s ImageStream chunk-by-chunk under the
12-byte layout and hashing the result yields, byte-for-byte, the stored MD5
(`d5825dc1…`), SHA1 (`fbac22cc…`), SHA256 (`ab2a6061…`), SHA512 (`647e8757…`) and
Blake2b-512 (`042ab10e…`). No other index layout reproduces them.

A chunk whose stored size equals `chunkSize` was written uncompressed; it is
copied out verbatim regardless of the stream's `compressionMethod`.

### Compression

The `compressionMethod` predicate selects the codec: `NullCompressor` (raw),
`DeflateCompressor` (zlib, RFC 1950 — `flate2::read::ZlibDecoder`), Snappy
(`<http://code.google.com/p/snappy/>`, raw `snap::raw::Decoder`), and LZ4 frame
(aff4-imager). All five reference images use Snappy.

### Map resolution and symbolic streams

`aff4:Map` virtual addresses resolve to an ImageStream region or a symbolic
stream. Symbolic fills follow pyaff4 (`stream_factory.py`):

| Target | Fill |
|---|---|
| `aff4:Zero` | `0x00` |
| `aff4:SymbolicStreamFF`, `aff4:SymbolicStream{XX}` | constant byte `0xXX` |
| `aff4:UnknownData` | tile `UNKNOWN`, `byte(p)=seed[(p % 1 MiB) % 7]` |
| `aff4:UnreadableData` | tile `UNREADABLEDATA`, `byte(p)=seed[(p % 1 MiB) % 14]` |

`p = target_offset + offset_within_region`. The 1 MiB modulus produces a seam at
each 1 MiB boundary (1 MiB is not a multiple of the seed length).

**Whole-image check:** reading the first 32 MiB of `Base-Allocated.aff4` and
`Base-Linear.aff4` through the reader reproduces, byte-for-byte (SHA-256), an
independent pyaff4-semantics reconstruction in Python — exercising ImageStream
data, every symbolic fill, and the UnknownData seam together. Concretely,
`Base-Linear` virtual sector 0 reads its real MBR (boot signature `0x55AA`), not
zeros.

### AFF4-Logical (AFF4-L)

`LogicalContainer` is validated against pyaff4's `dream.aff4`
(`test_images/AFF4-L`): the single logical file `./test_images/AFF4-L/dream.txt`
(8688 bytes) is enumerated with its `aff4:size` and stored MD5
(`75d83773f8d431a3ca91bfb8859e486d`), and its content read from the ZIP segment
recomputes to that MD5. Env-gated via `AFF4L_DREAM` (see
`core/tests/data/README.md`).

### Encryption

`aff4:EncryptedStream` decryption is implemented (all RustCrypto, never
hand-rolled): `LogicalContainer::open_encrypted(path, password)` derives the key
`PBKDF2-HMAC-SHA256 → RFC 3394 AES key-unwrap`, then AES-128-XTS-decrypts each
512-byte chunk (little-endian chunk-index tweak) and opens the inner AFF4 volume.
The passwordless `Aff4Reader::open` still refuses encrypted images by design
(secure-by-default); decryption is the deliberate, key-bearing opt-in.

Tier-2 validated against `encrypted-linear-password.aff4`: decryption reproduces
the oracle plaintext MD5 (`fedd7baa1fdf87bb8c12b18ad59ba738`), and the RFC 3394
integrity check makes a wrong password fail loudly (`Aff4Error::Encrypted`)
rather than yield garbage. The oracle was minted with pyaff4 and cross-checked by
an independent from-scratch decrypt (see `tests/data/README.md`). Public-key
(certificate) keybags are detected and refused as unsupported.

### Reproducing

```sh
git clone --depth=1 https://github.com/aff4/ReferenceImages /tmp/aff4-ref
# copy the five AFF4Std/Errata images into core/tests/data/ (see tests/data/README.md)
cargo test -p aff4
```
