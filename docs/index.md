# aff4-forensic

Pure-Rust, read-only **AFF4** (Advanced Forensic Format 4) tooling:

- **`aff4`** (the reader) — opens AFF4 Standard v1.0 disk images: `aff4:Map`
  virtual addressing, all four chunk codecs (Null / Deflate / Snappy / LZ4),
  symbolic-stream fills (Zero / FF / `SymbolicStream{XX}` / UnknownData /
  UnreadableData), URL-encoded ZIP entry names, and AFF4-Logical (AFF4-L) file
  containers. `Read + Seek` over the virtual stream. Zero `unsafe`, no C bindings.
- **`aff4-forensic`** (the analyzer) — recomputes the integrity claims an image
  makes about itself: `AFF4-HASH-MISMATCH` (a stored `aff4:hash` does not match
  the recomputed digest) and `AFF4-HASH-UNREADABLE` (a region could not be
  acquired).

## Quick start

```rust
use aff4::Aff4Reader;
use std::io::Read;

let mut reader = Aff4Reader::open("image.aff4".as_ref())?;
let mut buf = vec![0u8; 512];
reader.read_exact(&mut buf)?; // virtual sector 0
# Ok::<(), aff4::Aff4Error>(())
```

```rust
use aff4_forensic::audit_image;

for finding in audit_image("image.aff4".as_ref())? {
    println!("{}: {}", finding.code, finding.note);
}
# Ok::<(), aff4::Aff4Error>(())
```

## Trust

Every byte-level claim is reconciled against the AFF4 reference corpus (Evimetry
3.0) and pyaff4 — see [Reader Validation](corpus-validation.md) and
[Audit Validation](validation.md). Findings are observations ("consistent with
tampering or media corruption"), never verdicts — see [Finding Codes](finding-codes.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
