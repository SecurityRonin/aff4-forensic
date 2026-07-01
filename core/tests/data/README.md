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

## Encrypted AFF4 (AES-XTS password-wrapped keybag)

`encrypted-linear-password.aff4` — a minted encrypted logical container used as the
Tier-2 oracle for the AES-XTS decrypt path (`aff4:EncryptedStream`).

- **Source:** minted with pyaff4 0.34 (Apache-2.0, the reference implementation),
  `container.Container.createURN(..., encryption=True)` +
  `keybag.PasswordWrappedKeyBag`. No pre-made encrypted reference image ships in
  any public AFF4 corpus (encrypted containers are user-generated), so this one is
  generated deterministically-shaped from a known password + known plaintext.
- **Password:** `password`
- **Plaintext (`hello.txt`, 8192 bytes):** repeated ASCII pattern
  `AFF4-ORACLE-PLAINTEXT page=NNNN ` packed 64 bytes/line;
  MD5 `fedd7baa1fdf87bb8c12b18ad59ba738`,
  SHA-256 `89a031c7328f5d20bd98ebb7076e96e84d5778d049a849b4e8066a5409a904ed`.
- **Container size:** 10,974 bytes; container MD5 `7900ca1fcc6b78c3142f6ec11dcc8091`.
- **Keybag parameters (verbatim from the embedded `information.turtle`):**
  PBKDF2-HMAC-SHA256, `iterations 147256`, `keySizeInBytes 32`,
  `salt a1d8a5a9d81b3a9010ab4e60ee1b3b83` (16 bytes),
  `wrappedKey 334f04929581baa280c53a8666826796114f34c625162fc0c1721d83e337b720debb3bdcdacb4fea`
  (RFC 3394 AES key-wrap, default IV `0xA6A6A6A6A6A6A6A6`),
  `chunkSize 512`, `chunksInSegment 2048`.
- **Structure:** the outer `aff4:EncryptedStream` plaintext is *itself* an inner
  AFF4 ZIP volume; `hello.txt` lives inside that inner volume. Decrypting the
  EncryptedStream bevy yields the inner ZIP.
- **XTS:** VEK (32 bytes) = full XTS key `key1||key2` (each 16 bytes → AES-128-XTS);
  per-512-byte-chunk tweak = `struct.pack("<Q", chunk_id) + b"\x00"*8` where
  `chunk_id = bevy_index * chunks_per_segment + chunk_index`.
- **Use case:** Tier-2 validation of the Rust AES-XTS EncryptedStream decrypt.
  Round-trip confirmed with pyaff4, and independently cross-checked with a
  from-scratch decrypt (PBKDF2 → RFC 3394 unwrap → AES-XTS via the `cryptography`
  library, not pyaff4's own code path) reproducing the exact `hello.txt` bytes.

