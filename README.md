[![Crates.io](https://img.shields.io/crates/v/aff4.svg)](https://crates.io/crates/aff4)
[![Docs.rs](https://img.shields.io/docsrs/aff4)](https://docs.rs/aff4)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/aff4/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/aff4/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust read-only AFF4 v1 disk image reader — Map streams, Snappy/LZ4/Deflate, and ExabyteSparse support.**

Decodes AFF4 (Advanced Forensic Format 4) Standard v1.0 containers produced by Evimetry, aff4-imager, and pyaff4. Handles `aff4:Map` virtual address mapping, sparse zero and 0xFF regions, all three compression codecs, and the URL-encoded ZIP entry names used by the reference implementation. Exposes a `Read + Seek` interface over the virtual sector stream. Zero unsafe code, no C bindings.

```toml
[dependencies]
aff4 = "0.1"
```

---

## Usage

### Open an AFF4 image and read sectors

```rust
use aff4::Aff4Reader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = Aff4Reader::open("disk.aff4")?;

println!("Virtual disk size: {} bytes", reader.virtual_disk_size());

// Read the first sector
let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek anywhere
reader.seek(SeekFrom::Start(1_048_576))?;
```

### Pass to a filesystem crate

`Aff4Reader` implements `Read + Seek`, so it drops directly into any crate that accepts a reader:

```rust
use aff4::Aff4Reader;

let reader = Aff4Reader::open("disk.aff4")?;
// e.g. ext4fs_forensic::Filesystem::open(reader)?;
```

---

## Supported features

| Feature | Status |
|---------|:------:|
| AFF4 v1 Standard (Evimetry 3.0 reference images) | ✓ |
| Scudette / aff4-imager start-offset index format | ✓ |
| `aff4:Map` virtual address mapping | ✓ |
| Sparse Zero regions (`aff4:Zero`) | ✓ |
| Sparse 0xFF regions (`aff4:SymbolicStreamFF`) | ✓ |
| ExabyteSparse images (≤ 9.2 EiB virtual size) | ✓ |
| Snappy decompression | ✓ |
| LZ4 frame decompression | ✓ |
| Deflate / zlib decompression | ✓ |
| Null (uncompressed) chunks | ✓ |
| URL-encoded ZIP entry names (`aff4%3A%2F%2F…`) | ✓ |

Read-only. `aff4:Map` is required for all Evimetry images and most production AFF4 captures.

---

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 fixed and dynamic disk images |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`iso`](https://github.com/SecurityRonin/iso) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |
| [`dar`](https://github.com/SecurityRonin/dar) | DAR archive | Disk ARchiver archives with catalog index and CRC32 validation |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/aff4/privacy/) · [Terms of Service](https://securityronin.github.io/aff4/terms/) · © 2026 Security Ronin Ltd
