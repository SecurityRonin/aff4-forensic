# AFF4 Implementation Notes

Format quirks and empirically verified behaviour, for contributors. Every byte-level
claim here is reconciled against the AFF4 reference corpus and pyaff4 (see
[Corpus Validation](corpus-validation.md)).

---

## 1. AFF4 is a ZIP container with RDF/Turtle metadata

AFF4 stores forensic images as standard ZIP archives. The reader reads through
`zip-forensic-core` (our read-only forensic ZIP reader); the third-party `zip` crate
is a test-only fixture writer (see
`docs/decisions/0005-read-via-zip-forensic-core-writer-is-test-only.md`). The metadata
is an RDF/Turtle document named `information.turtle` inside the ZIP. Disk-image data
is stored as "bevy" segments:

```
{base}/{segment_idx:08x}         ← chunk data for this bevy
{base}/{segment_idx:08x}.index   ← chunk index for this bevy
```

`{base}` derives from the stream ARN with the `aff4://` scheme stripped. Real
Evimetry / aff4-imager images **URL-encode** the IRI as `aff4%3A%2F%2F{uuid}/…`;
synthetic fixtures use the bare path. The reader detects which form the ZIP uses.

---

## 2. Bevy index: 12-byte `(offset, length)` entries

The `.index` file is a packed array of **12-byte little-endian entries**, one per
chunk: `(u64 byte_offset, u32 length)` — the chunk's position and stored (possibly
compressed) size within the bevy segment.

```rust
let base   = chunk_in_seg * 12;
let offset = u64::from_le_bytes(index[base..base + 8]) as usize;
let length = u32::from_le_bytes(index[base + 8..base + 12]) as usize;
let (start, end) = (offset, offset + length);
```

A **zero-length** entry marks a sparse (all-zero) chunk. A chunk whose stored
`length` equals `aff4:chunkSize` was written **uncompressed** — copy it verbatim,
regardless of the stream's `compressionMethod`.

This 12-byte layout is verified by reproducing Evimetry's stored `aff4:hash`
digests; a 4-byte cumulative-end interpretation reproduces none of them and mis-reads
every real image (it reads `Base-Linear` sector 0 as zeros instead of its MBR).

---

## 3. Compression

`aff4:compressionMethod` selects the codec:

- `aff4:NullCompressor` (or absent) → raw bytes
- `aff4:DeflateCompressor` → zlib (RFC 1950, 2-byte header + Adler-32) —
  `flate2::read::ZlibDecoder`, **not** raw DEFLATE
- `<http://code.google.com/p/snappy/>` → raw Snappy — `snap::raw::Decoder`
- `<https://github.com/lz4/lz4>` → LZ4 frame (aff4-imager) — `lz4_flex::frame`

All five AFF4 Standard reference images use Snappy.

---

## 4. RDF/Turtle parsing is intentionally minimal

Rather than a full Turtle parser: normalize whitespace and `;` to spaces, split on
`" . "` (the RDF node delimiter), find the relevant block, and extract the IRI
(`<…>`) and predicate-value pairs by token scanning. This handles aff4-cpp,
aff4-imager, and pyaff4 output. One real-world quirk it must absorb: pyaff4 writes a
trailing comma attached to a hash datatype (`…"^^aff4:MD5,`), so the datatype token
is trimmed of trailing non-alphanumerics.

---

## 5. Geometry validation is mandatory before opening

`aff4:chunkSize` and `aff4:chunksInSegment` feed division in `read_chunk`; a value
of 0 would divide-by-zero. Both are rejected at parse time with a `BadFormat` error.
This is a consequence of the reader's arithmetic, not stated in the spec.

---

## 6. Map streams and symbolic fills

Evimetry images use an `aff4:Map` as the top-level stream: a binary `/map` of
28-byte entries `(map_offset, length, target_offset, target_id)` plus an `/idx`
list of target URIs. A virtual address resolves to an ImageStream region or a
**symbolic stream**:

| Target | Fill |
|---|---|
| `aff4:Zero` | `0x00` |
| `aff4:SymbolicStreamFF` / `aff4:SymbolicStream{XX}` | constant byte `0xXX` |
| `aff4:UnknownData` | tile `UNKNOWN` |
| `aff4:UnreadableData` | tile `UNREADABLEDATA` |

Tile fills follow pyaff4: `byte(p) = seed[(p % 1_048_576) % seed.len()]` with
`p = target_offset + offset_within_region`. The 1 MiB modulus introduces a seam at
each 1 MiB boundary. `Base-Allocated` fills unallocated regions with `UnknownData`;
this is the substance behind the corpus's "allocated" maps.

---

## 7. AFF4-Logical (AFF4-L)

An AFF4-L container stores logical files as named ZIP segments described by
`aff4:FileImage` nodes (path, `aff4:size`, `aff4:hash`, timestamps). It has no
virtual disk and no bevy/chunk/map machinery — `LogicalContainer` reads each file's
content straight from its ZIP segment. Validated against pyaff4's `dream.aff4`.

---

## 8. Encryption: refuse by default, decrypt with a key

`aff4:EncryptedStream` (AES-XTS, password-wrapped keybag) is **decrypted** with a
password via `LogicalContainer::open_encrypted` — PBKDF2-HMAC-SHA256 → RFC 3394 key
unwrap → AES-128-XTS. The passwordless `Aff4Reader::open` still refuses with
`Aff4Error::Encrypted` (secure-by-default), never decoding ciphertext as plaintext,
and certificate/public-key keybags are refused as unsupported. See
`docs/decisions/0002-encrypted-streams-secure-by-default-decryption.md`.

## 9. Container-kind detection

`aff4::container_kind(&Path) -> ContainerKind {Disk, Logical, Encrypted}` classifies
a container from its `information.turtle` alone (no full reader open), so a consumer
can dispatch without reaching into the RDF or try/catching openers. See
`docs/decisions/0004-container-kind-detection-probe.md`.
