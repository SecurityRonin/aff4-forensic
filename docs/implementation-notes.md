# AFF4 Implementation Notes

Developer notes capturing format quirks, spec contradictions, and empirically verified
behaviour. Intended for future contributors and as a basis for upstream spec clarifications.

---

## 1. AFF4 is a ZIP container with RDF/Turtle metadata

AFF4 (Advanced Forensic Format 4) stores forensic images as standard ZIP archives.
The metadata is an RDF/Turtle document named `information.turtle` inside the ZIP.

### ZIP entry naming

The data is stored as "bevy" segments named:
```
{uuid}/{segment_idx:08x}         ← sector data for this bevy
{uuid}/{segment_idx:08x}.index   ← chunk index for this bevy
```

where `{uuid}` is the AFF4 ARN (Archival Resource Name) with the `aff4://` prefix
stripped. The segment index is zero-padded to 8 lowercase hex digits.

**Common pitfall:** forgetting to strip `aff4://` from the ARN before constructing
ZIP entry names. The ZIP archive does not contain the `aff4://` scheme prefix.

```rust
let zip_base = meta.stream_arn
    .strip_prefix("aff4://")
    .unwrap_or(&meta.stream_arn)
    .to_string();
```

---

## 2. Bevy index: cumulative end-offsets, not start-offsets

The `.index` file for each bevy is an array of **`u32` little-endian cumulative
end-byte offsets** (one per chunk). The start offset of chunk `i` is the end offset
of chunk `i-1` (or 0 for the first chunk).

```
Index file layout:
  [0..4]  = end byte of chunk 0 (= length of chunk 0)
  [4..8]  = end byte of chunk 1 (= end of chunk 0 + length of chunk 1)
  ...
  [n*4..(n+1)*4] = end byte of chunk n
```

To compute the file range `[start, end)` for chunk `i`:

```rust
let end   = u32::from_le_bytes(index[i*4..i*4+4]) as usize;
let start = if i == 0 { 0 } else { u32::from_le_bytes(index[(i-1)*4..i*4]) as usize };
```

**Common pitfall:** treating index values as start offsets. This mis-interprets all
chunks after the first — the first chunk reads correctly but subsequent chunks are
offset by one entry.

---

## 3. Compression: zlib (with header), not raw DEFLATE

AFF4's `DeflateCompressor` uses **zlib framing** (RFC 1950: 2-byte header + Adler-32
trailer), unlike QCOW2 which uses raw DEFLATE (no header, `windowBits = -15`).

Use `flate2::read::ZlibDecoder`, **not** `DeflateDecoder`:

```rust
Compression::Deflate => {
    let mut dec = flate2::read::ZlibDecoder::new(compressed);
    dec.read_to_end(&mut out)?;
}
```

The compression type is identified in `information.turtle`:
- `aff4:NullCompressor` (or absent) → no compression; read bytes directly
- `aff4:DeflateCompressor` → zlib
- `aff4:SnappyCompressor` → Snappy (not supported in this implementation)

---

## 4. RDF/Turtle parsing is intentionally minimal

`information.turtle` is a valid Turtle/N3 document but implementing a full Turtle
parser is out of scope. Our approach:

1. Normalize all whitespace variants (`\n`, `\r`, `\t`) and `;` to spaces
2. Split the normalized text on `" . "` (dot separates RDF subjects)
3. Find the block containing `"ImageStream"`
4. Extract the IRI (`<...>`) as the stream ARN
5. Extract predicate-value pairs by token-window scanning

This works for AFF4 images produced by aff4-cpp, aff4-imager, and pyaff4. It will
fail on Turtle with unusual formatting (e.g., multi-line IRIs, prefixed names for
predicates we expect as full URIs).

**Upstream tools that produce valid AFF4:** aff4-imager, Rekall imager, AVML (Linux).
**Not supported:** AFF4-L (AFF4-Logical, file-level container) — this implementation
handles AFF4 disk images (physical/raw sector images) only.

---

## 5. Geometry validation is mandatory before opening

`aff4:chunkSize` and `aff4:chunksInSegment` feed directly into division arithmetic
in `read_chunk`. If either is 0, the reader panics with divide-by-zero. Validate
at parse time:

```rust
if chunk_size == 0 {
    return Err(Aff4Error::BadFormat("aff4:chunkSize must be > 0".into()));
}
if chunks_per_segment == 0 {
    return Err(Aff4Error::BadFormat("aff4:chunksInSegment must be > 0".into()));
}
```

This is not mentioned explicitly in the AFF4 specification; it is a consequence of
the reader's implementation requiring valid division operands.

---

## 6. ExabyteSparse streams (not supported)

AFF4-L (logical) and some physical images use `aff4:ExabyteSparseMap` to record
which regions of the virtual address space are present vs. absent (sparse). This
implementation assumes all chunks are present (no sparse map). Reading an
ExabyteSparse image without honouring the map returns zeros for absent regions
silently.

---

## Upstream PR candidates

| Project | File | Suggested change |
|---------|------|-----------------|
| aff4 spec | §5.3 (bevy index) | Explicitly state that index entries are cumulative end-byte offsets, not start offsets; add a worked example |
| aff4 spec | §5.4 (compression) | Clarify that `DeflateCompressor` uses RFC 1950 zlib framing (2-byte header + Adler-32), not raw DEFLATE |
| pyaff4 | `aff4/aff4_image.py` | Add docstring explaining the cumulative-end-offset index format |
