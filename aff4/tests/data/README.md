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
| `Base-Allocated.aff4` | ~2.8 MiB | Sparse image with explicit allocated maps |
| `Base-ExabyteSparse.aff4` | ~4.5 MiB nominal | Sparse image claiming exabyte virtual size |

All five open successfully with `Aff4Reader::open`.

## Regenerating

```sh
git clone --depth=1 https://github.com/aff4/ReferenceImages /tmp/aff4-ref
cp /tmp/aff4-ref/AFF4Std/Base-Linear.aff4 tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Linear-ReadError.aff4 tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Linear-AllHashes.aff4 tests/data/
cp /tmp/aff4-ref/AFF4Std/Base-Allocated.aff4 tests/data/
cp /tmp/aff4-ref/Errata/Base-ExabyteSparse.aff4 tests/data/
```
