[![Crates.io](https://img.shields.io/crates/v/aff4.svg)](https://crates.io/crates/aff4)
[![Docs.rs](https://img.shields.io/docsrs/aff4)](https://docs.rs/aff4)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/aff4-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/aff4-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust read-only AFF4 reader (`aff4`) + integrity analyzer (`aff4-forensic`) — Map streams, Snappy/LZ4/Deflate, symbolic fills, AFF4-Logical, and self-hash verification.**

Decodes AFF4 (Advanced Forensic Format 4) Standard v1.0 containers produced by Evimetry, aff4-imager, and pyaff4: `aff4:Map` virtual address mapping, all four chunk codecs, symbolic-stream fills (Zero / `0xFF` / `SymbolicStream{XX}` / UnknownData / UnreadableData), URL-encoded ZIP entry names, and AFF4-Logical (AFF4-L) file containers. Exposes a `Read + Seek` interface over the virtual sector stream. Zero unsafe code, no C bindings. The analyzer recomputes each declared `aff4:hash` and reports tampering / unreadable regions.

```toml
[dependencies]
aff4 = "0.2"            # the reader
aff4-forensic = "0.1"   # the integrity analyzer (optional)
```

---

## Usage

### Open an AFF4 image and read sectors

```rust
use aff4::Aff4Reader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = Aff4Reader::open("disk.aff4".as_ref())?;

println!("Virtual disk size: {} bytes", reader.virtual_disk_size());

// Read the first sector
let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek anywhere
reader.seek(SeekFrom::Start(1_048_576))?;
# Ok::<(), aff4::Aff4Error>(())
```

`Aff4Reader` implements `Read + Seek`, so it drops directly into any crate that accepts a reader (e.g. a filesystem parser).

### Audit an image's integrity

```rust
use aff4_forensic::audit_image;

for finding in audit_image("disk.aff4".as_ref())? {
    // AFF4-HASH-MISMATCH (stored hash ≠ recomputed) or
    // AFF4-HASH-UNREADABLE (a region could not be acquired)
    println!("{}: {}", finding.code, finding.note);
}
# Ok::<(), aff4::Aff4Error>(())
```

### Read logical files (AFF4-L)

```rust
use aff4::LogicalContainer;

let mut container = LogicalContainer::open("logical.aff4".as_ref())?;
for entry in container.files().to_vec() {
    let bytes = container.read_file(&entry)?;
    println!("{} ({} bytes)", entry.original_file_name, bytes.len());
}
# Ok::<(), aff4::Aff4Error>(())
```

### Decrypt an encrypted container (AES-XTS)

`Aff4Reader::open` refuses encrypted images by design; decryption is the explicit,
key-bearing path (a wrong password errors, never yields garbage):

```rust
use aff4::LogicalContainer;

let mut container = LogicalContainer::open_encrypted("secret.aff4".as_ref(), "password")?;
let files = container.files().to_vec();
let bytes = container.read_file(&files[0])?;
# Ok::<(), aff4::Aff4Error>(())
```

---

## Supported features

| Feature | Status |
|---------|:------:|
| AFF4 v1 Standard (Evimetry 3.0 reference images) | ✓ |
| 12-byte bevy index (`(offset, length)` per chunk) | ✓ |
| `aff4:Map` virtual address mapping | ✓ |
| Symbolic `aff4:Zero` / `SymbolicStreamFF` / `SymbolicStream{XX}` | ✓ |
| `aff4:UnknownData` / `UnreadableData` tile fills (pyaff4-exact) | ✓ |
| ExabyteSparse images (≤ 9.2 EiB virtual size) | ✓ |
| Snappy / LZ4 frame / Deflate (zlib) / Null codecs | ✓ |
| URL-encoded ZIP entry names (`aff4%3A%2F%2F…`) | ✓ |
| AFF4-Logical (AFF4-L) file containers | ✓ |
| `aff4:hash` verification → `AFF4-HASH-MISMATCH` / `-UNREADABLE` | ✓ |
| Encrypted volumes (`aff4:EncryptedStream`, AES-XTS + password keybag) | decrypt |

Read-only. Validated Tier-1 against the AFF4 reference corpus and pyaff4 — see the [reader](https://securityronin.github.io/aff4-forensic/corpus-validation/) and [audit](https://securityronin.github.io/aff4-forensic/validation/) validation docs.

---

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf-forensic) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`vmdk`](https://github.com/SecurityRonin/vmdk-forensic) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/aff4-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/aff4-forensic/terms/) · © 2026 Security Ronin Ltd
