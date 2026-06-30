# tests/data — AFF4 Real-Image Corpus

Integration test fixtures and fuzz seed corpus.
`fuzz/corpus/fuzz_open/` symlinks here; files are not duplicated.

## Files

All images from the official AFF4 reference image repository:
https://github.com/aff4/ReferenceImages — produced by Evimetry 3.0,
the reference implementation of the AFF4 Standard v1.0.

| File | Virtual size | Notes |
|------|-------------|-------|
| `Base-Linear.aff4` | ~3.8 MiB | Standard linear image, NullCompressor |
| `Base-Linear-AllHashes.aff4` | ~3.8 MiB | Same image with all hash types populated |
| `Base-Linear-ReadError.aff4` | ~2.8 MiB | Image with a deliberate read error region |
| `Base-Allocated.aff4` | ~2.8 MiB | Allocated-only image; unallocated regions are `aff4:UnknownData` fills |
| `Base-ExabyteSparse.aff4` | ~4.5 MiB nominal | Sparse image claiming exabyte virtual size |

All five open and read correctly with `Aff4Reader::open`; see
the repo's `docs/corpus-validation.md` for the Tier-1 reconciliation against Evimetry's
stored hashes.

## Regenerating

```sh
git clone --depth=1 https://github.com/aff4/ReferenceImages /tmp/aff4-ref
cp /tmp/aff4-ref/AFF4Std/Base-Linear.aff4 tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Linear-ReadError.aff4 tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Linear-AllHashes.aff4 tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Allocated.aff4 tests/data/
cp /tmp/aff4-ref/Errata/Base-ExabyteSparse.aff4 tests/data/
```

## AFF4-Logical (env-gated, not committed)

The AFF4-L test (`corpus.rs::aff4l_dream_lists_and_reads_against_pyaff4`) runs
against pyaff4's `dream.aff4` reference container. It is **not committed** — the
container embeds the Martin Luther King Jr. "I Have a Dream" speech text, whose
redistribution is restricted. Download it from the pyaff4 repository and point
`AFF4L_DREAM` at it:

```sh
curl -fsSLO https://raw.githubusercontent.com/aff4/pyaff4/master/test_images/AFF4-L/dream.aff4
AFF4L_DREAM=$PWD/dream.aff4 cargo test -p aff4 --test corpus aff4l_dream
```

- **Source:** pyaff4 reference implementation (Apache-2.0), `test_images/AFF4-L/`.
- **Ground truth:** one logical file `./test_images/AFF4-L/dream.txt`, 8688 bytes,
  MD5 `75d83773f8d431a3ca91bfb8859e486d`.
- **Use case:** Tier-1 validation of `LogicalContainer` enumeration + content read.

The test skips cleanly when `AFF4L_DREAM` is unset.

