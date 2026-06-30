//! Integrity-audit integration tests against the AFF4 reference corpus.
//!
//! Ground truth is Evimetry's own stored `aff4:hash` digests (an independent
//! Tier-1 oracle): the clean image must reconcile, and a single flipped content
//! byte must surface an `AFF4-HASH-MISMATCH`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use aff4_forensic::audit_image;

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../core/tests/data")
        .join(name)
}

/// Rewrite `src` into a fresh temp file, flipping the first byte of the first
/// stored-uncompressed (`length == chunk_size`) ImageStream chunk. Derived from
/// the 12-byte bevy index — no hard-coded offsets — so the change alters the
/// reconstructed content while leaving the image fully readable.
fn flip_first_raw_chunk_byte(src: &Path) -> tempfile::NamedTempFile {
    let chunk_size = 32768usize;
    let file = std::fs::File::open(src).unwrap();
    let mut zin = zip::ZipArchive::new(file).unwrap();

    let names: Vec<String> = zin.file_names().map(String::from).collect();
    // The ImageStream bevy: an entry ending in "/00000000" with no extension.
    let bevy = names
        .iter()
        .find(|n| n.ends_with("/00000000") && !n.contains('.'))
        .expect("ImageStream bevy")
        .clone();
    let index = format!("{bevy}.index");

    let index_bytes = read_entry(&mut zin, &index);
    // First chunk whose stored length == chunk_size is raw; flip its first byte.
    let mut flip_at = None;
    for i in 0..index_bytes.len() / 12 {
        let off = u64::from_le_bytes(index_bytes[i * 12..i * 12 + 8].try_into().unwrap()) as usize;
        let len =
            u32::from_le_bytes(index_bytes[i * 12 + 8..i * 12 + 12].try_into().unwrap()) as usize;
        if len == chunk_size {
            flip_at = Some(off);
            break;
        }
    }
    let flip_at = flip_at.expect("at least one stored-uncompressed chunk");

    let out = tempfile::NamedTempFile::new().unwrap();
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    {
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for name in &names {
            let mut data = read_entry(&mut zin, name);
            if name == &bevy {
                data[flip_at] ^= 0xFF;
            }
            zw.start_file(name, opts).unwrap();
            zw.write_all(&data).unwrap();
        }
        zw.finish().unwrap();
    }
    std::fs::write(out.path(), buf.into_inner()).unwrap();
    out
}

fn read_entry(zin: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Vec<u8> {
    let mut e = zin.by_name(name).unwrap();
    let mut v = Vec::new();
    e.read_to_end(&mut v).unwrap();
    v
}

#[test]
fn clean_allhashes_has_no_mismatch() {
    let p = corpus("Base-Linear-AllHashes.aff4");
    if !p.exists() {
        return;
    }
    let findings = audit_image(&p).expect("audit clean image");
    let mismatches = findings
        .iter()
        .filter(|f| f.code == "AFF4-HASH-MISMATCH")
        .count();
    assert_eq!(
        mismatches, 0,
        "the unmodified reference image must reconcile against its stored hashes"
    );
}

#[test]
fn tampered_content_yields_hash_mismatch() {
    let p = corpus("Base-Linear-AllHashes.aff4");
    if !p.exists() {
        return;
    }
    let tampered = flip_first_raw_chunk_byte(&p);
    let findings = audit_image(tampered.path()).expect("audit tampered image");
    let mismatches = findings
        .iter()
        .filter(|f| f.code == "AFF4-HASH-MISMATCH")
        .count();
    assert!(
        mismatches >= 1,
        "a flipped ImageStream content byte must surface an AFF4-HASH-MISMATCH; \
         got {} findings",
        findings.len()
    );
}

#[test]
fn read_error_image_flags_unreadable_not_mismatch() {
    let p = corpus("Base-Linear-ReadError.aff4");
    if !p.exists() {
        return;
    }
    let findings = audit_image(&p).expect("audit read-error image");
    let unreadable = findings
        .iter()
        .filter(|f| f.code == "AFF4-HASH-UNREADABLE")
        .count();
    let mismatches = findings
        .iter()
        .filter(|f| f.code == "AFF4-HASH-MISMATCH")
        .count();
    // The image carries 32 aff4:UnreadableData regions; its ImageStream content
    // hash still reconciles (the imaged bytes are intact). So the audit reports
    // the unreadable caveat, NOT a tamper mismatch.
    assert!(
        unreadable >= 1,
        "a read-error image must surface at least one AFF4-HASH-UNREADABLE"
    );
    assert_eq!(
        mismatches, 0,
        "the intact ImageStream content must not be reported as a mismatch"
    );
}
