# AFF4 Corpus Validation

Functional corpus tests against the official AFF4 Standard v1.0 reference images
produced by Evimetry 3.0 (the reference implementation). These tests caught three
critical bugs not detectable through synthetic test fixtures.

## Test Environment

| Component | Version |
|-----------|---------|
| OS | macOS (Apple Silicon) |
| Rust | (see `rust-toolchain.toml`) |
| snap crate | 1.x (`snap::raw::Decoder` for Snappy decompression) |

Note: `qemu-img` does not support AFF4 format. Differential validation uses
`snap::raw::Decoder` directly on ZIP-extracted bytes as the independent
reference (see `tests/corpus.rs`).

## Corpus Files

All 5 images from https://github.com/aff4/ReferenceImages (official AFF4 Standard
reference repository). Produced by Evimetry 3.0, the standard's reference
implementation.

| File | Virtual size | Compression | Notes |
|------|-------------|-------------|-------|
| `Base-Linear.aff4` | 3,964,928 bytes | Snappy | Primary test target |
| `Base-Linear-AllHashes.aff4` | 3,964,928 bytes | Snappy | Same image, all hash types |
| `Base-Linear-ReadError.aff4` | ~2.8 MiB nominal | Snappy | Deliberate read error region |
| `Base-Allocated.aff4` | ~2.8 MiB nominal | Snappy | Sparse with explicit allocated maps |
| `Base-ExabyteSparse.aff4` | exabyte-scale nominal | Snappy | Exabyte virtual size claim |

All use URL-encoded ZIP entry names (`aff4%3A%2F%2F{uuid}/00000000`).

## Test Results

### `corpus_base_linear_virtual_disk_size`

Opens `Base-Linear.aff4` and verifies `virtual_disk_size()` == 3,964,928 bytes
(as declared in `aff4:size` in `information.turtle`). **PASS**.

### `corpus_base_linear_sector0_reads_ok`

Reads sector 0 (bytes 0–511) from `Base-Linear.aff4`. Chunks 0–1 are sparse
(0-byte bevy index entries) so all 512 bytes must be zero. **PASS**.

### `corpus_base_linear_snappy_chunk_matches_reference`

Seeks to virtual offset 65,536 (chunk 2, first non-sparse chunk) and reads 512
bytes. Compares against an independent reference: direct ZIP extraction of chunk
2 + `snap::raw::Decoder` decompression. **PASS**.

## Bugs Discovered via Corpus Testing

These three bugs were invisible to the synthetic unit test suite — all unit tests
passed while the reader silently returned wrong data on real images:

### 1. URL-encoded ZIP entry names

Real AFF4 images produced by Evimetry name ZIP entries as
`aff4%3A%2F%2F{uuid}/00000000`. The reader constructed `{uuid}/00000000` and
received "file not found" on every real image.

**Fix**: scan `archive.file_names()` for the URL-encoded prefix; use it if found,
fall back to bare UUID for synthetic test fixtures.

### 2. Snappy compression silently treated as NullCompressor

All 5 reference images use `aff4:compressionMethod <http://code.google.com/p/snappy/>`.
The parser only detected `DeflateCompressor` and defaulted to `Null` for everything
else — returning raw Snappy-compressed bytes as disk data (no error, wrong output).

**Fix**: detect `"snappy"` substring in compressionMethod; dispatch to
`snap::raw::Decoder` for decompression.

### 3. Sparse chunks returning empty Vec

Chunks 0 and 1 of `Base-Linear.aff4` are sparse: their bevy index entries have
`start == end == 0`. The reader called `read_exact` on an empty Vec, causing
`UnexpectedEof` rather than returning `chunk_size` zeros.

**Fix**: early-return `vec![0u8; chunk_size]` when `chunk_start == chunk_end`,
before attempting to read the bevy segment.

## Validation Coverage

| Feature | Covered | Notes |
|---------|---------|-------|
| URL-encoded ZIP entry names | Yes | `Base-Linear.aff4` |
| Snappy decompression | Yes | all reference images use Snappy |
| Sparse chunk zero-fill | Yes | chunks 0-1 of Base-Linear |
| DeflateCompressor (zlib) | Indirect | unit tests; no corpus file |
| NullCompressor | Indirect | unit tests only |
| LZ4 frame compression | Yes | `test_aff4_lz4` unit test (aff4-imager URI) |
| Scudette bevy index format | Yes | `test_aff4_scudette` unit test (start-offset array) |
| ExabyteSparse images | Open-only | `Base-ExabyteSparse.aff4` opens; full read not tested |
| Hash verification | No | AFF4 hash streams not yet implemented |
| Map streams (Base-Allocated) | No | allocated map parsing not yet implemented |

## Reproducing

```sh
# Download reference images
git clone --depth=1 https://github.com/aff4/ReferenceImages /tmp/aff4-ref
cp /tmp/aff4-ref/AFF4Std/Base-Linear.aff4 aff4/tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Linear-AllHashes.aff4 aff4/tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Linear-ReadError.aff4 aff4/tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Allocated.aff4 aff4/tests/data/
cp /tmp/aff4-ref/Errata/Base-ExabyteSparse.aff4 aff4/tests/data/

# Run corpus tests
cargo test --test corpus
```
