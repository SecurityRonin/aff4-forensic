/// Corpus integration tests for real AFF4 reference images.
///
/// All five images are from https://github.com/aff4/ReferenceImages —
/// produced by Evimetry 3.0, the reference implementation of the AFF4 Standard v1.0.
///
/// These tests verify that our reader correctly handles:
/// - URL-encoded ZIP entry names (`aff4%3A%2F%2F{uuid}/00000000`)
/// - Snappy-compressed chunks (all reference images use Snappy)
/// - Sparse chunks (index entries with 0 bytes = virtual zeros)
use aff4::Aff4Reader;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// Open Base-Linear.aff4 and verify the virtual disk size matches the Map's declared size.
///
/// All Evimetry reference images use `aff4:Map` as the top-level data stream.
/// The Map declares `aff4:size 268435456` (256 MiB — the actual virtual disk size).
/// The inner `aff4:ImageStream` declares `aff4:size 3964928` (physical data size).
/// `virtual_disk_size()` must return the Map's size.
#[test]
fn corpus_base_linear_virtual_disk_size() {
    let path = corpus("Base-Linear.aff4");
    if !path.exists() {
        return;
    }
    let reader = Aff4Reader::open(&path).expect("open Base-Linear.aff4");
    assert_eq!(
        reader.virtual_disk_size(),
        268_435_456_u64,
        "virtual_disk_size must come from the aff4:Map block (268435456 = 256 MiB)"
    );
}

/// Read sector 0 from Base-Linear.aff4 — it is a real MBR, not zeros.
///
/// External ground truth: the Map routes virtual offset 0 → ImageStream offset 0
/// (map entry `map_off=0, len=32768, tgt_off=0, tgt_id=0`), and ImageStream chunk 0
/// decompresses to a 512-byte MBR ending in the boot signature `0x55 0xAA` at
/// offset 510. A reader that mis-parses the bevy index treats chunk 0 as sparse
/// and returns all zeros — this test catches that.
#[test]
fn corpus_base_linear_sector0_is_mbr() {
    let path = corpus("Base-Linear.aff4");
    if !path.exists() {
        return;
    }
    let mut reader = Aff4Reader::open(&path).expect("open");
    let mut buf = [0u8; 512];
    reader
        .read_exact(&mut buf)
        .expect("sector 0 must be readable");
    assert_eq!(
        (buf[510], buf[511]),
        (0x55, 0xAA),
        "virtual sector 0 maps to ImageStream chunk 0 (a real MBR); the boot \
         signature 0x55AA must appear at offset 510, not zeros"
    );
    assert_ne!(
        buf, [0u8; 512],
        "sector 0 is an MBR, not a sparse zero region"
    );
}

/// Read a Snappy-compressed chunk from Base-Linear.aff4 and verify bytes match
/// the reference: direct ZIP extraction + Snappy decompression using the snap crate.
///
/// Base-Linear uses an aff4:Map. The first two virtual chunks (0–65535) are sparse
/// (Zero targets). Virtual offset 98304 is the first Map entry that targets the
/// ImageStream, specifically ImageStream offset 65536 (chunk 2 = the first real data).
/// The reference helper reads ImageStream chunk 2 at ImageStream offset 65536 directly.
#[test]
fn corpus_base_linear_snappy_chunk_matches_reference() {
    let path = corpus("Base-Linear.aff4");
    if !path.exists() {
        return;
    }

    // Reference: extract ImageStream chunk 2 (at ImageStream offset 65536) directly.
    let reference = reference_bytes_via_zip_snap(&path, 65536, 512);

    let mut reader = Aff4Reader::open(&path).expect("open");
    // Virtual offset 98304 maps via the Map to ImageStream offset 65536 (chunk 2).
    reader
        .seek(SeekFrom::Start(98304))
        .expect("seek to first non-sparse virtual region");
    let mut buf = vec![0u8; 512];
    reader
        .read_exact(&mut buf)
        .expect("first non-sparse Snappy chunk must be readable");

    assert_eq!(
        &buf,
        &reference[..],
        "bytes at virtual offset 98304 must match Snappy-decompressed ImageStream chunk 2"
    );
}

/// Compute `len` bytes at `offset` in the virtual stream by extracting the
/// chunk directly from the ZIP and decompressing with Snappy (raw format).
///
/// This is the independent reference — it does NOT use `Aff4Reader`.
fn reference_bytes_via_zip_snap(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    use zip::ZipArchive;

    let file = std::fs::File::open(path).expect("open");
    let mut archive = ZipArchive::new(file).expect("zip");

    // Find the segment 0 bevy: any entry ending in "/00000000" (no extension).
    let segment0_suffix = format!("/{:08x}", 0u32);
    let bevy_name = archive
        .file_names()
        .filter(|n| n.ends_with(&segment0_suffix) && !n.contains('.'))
        .next()
        .expect("no segment 0 bevy found")
        .to_string();
    let index_name = format!("{}.index", bevy_name);

    let index_bytes = read_zip_entry(&mut archive, &index_name);
    let bevy_bytes = read_zip_entry(&mut archive, &bevy_name);

    let chunk_size = 32768usize;
    let chunk_idx = (offset as usize) / chunk_size;
    let offset_in_chunk = (offset as usize) % chunk_size;

    // AFF4 Standard v1.0 bevy index: 12-byte entries `(u64 byte_offset, u32 length)`
    // per chunk — the chunk's position and compressed size within the bevy segment.
    // (Verified by reproducing Evimetry's stored aff4:hash MD5/SHA1/SHA256/SHA512
    // over the reconstructed ImageStream content.)
    let entry_size = 12usize;
    let base = chunk_idx * entry_size;
    let start = u64::from_le_bytes(index_bytes[base..base + 8].try_into().unwrap()) as usize;
    let length = u32::from_le_bytes(index_bytes[base + 8..base + 12].try_into().unwrap()) as usize;
    let end = start + length;

    let compressed = &bevy_bytes[start..end];
    let mut dec = snap::raw::Decoder::new();
    let decompressed = dec
        .decompress_vec(compressed)
        .expect("snap::raw decompress failed");

    decompressed[offset_in_chunk..offset_in_chunk + len].to_vec()
}

fn read_zip_entry(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Vec<u8> {
    let mut entry = archive.by_name(name).expect("zip entry not found");
    let mut data = Vec::new();
    entry.read_to_end(&mut data).expect("read zip entry");
    data
}

// ── Map stream corpus tests ───────────────────────────────────────────────────
//
// Base-ExabyteSparse.aff4 and Base-Allocated.aff4 both use aff4:Map as the top-
// level data stream. Without Map support the reader opens the inner ImageStream
// and returns wrong virtual sizes and wrong data.

/// ExabyteSparse: virtual disk size must come from the aff4:Map block (9,223,372,036,854,775,296).
///
/// Without Map support, the reader finds the aff4:ImageStream block instead and
/// reports the ImageStream's physical data size (4,718,592 bytes).
#[test]
fn corpus_exabyte_sparse_virtual_size() {
    let path = corpus("Base-ExabyteSparse.aff4");
    if !path.exists() {
        return;
    }
    let reader = Aff4Reader::open(&path).expect("open Base-ExabyteSparse.aff4");
    assert_eq!(
        reader.virtual_disk_size(),
        9_223_372_036_854_775_296_u64,
        "virtual_disk_size must come from aff4:Map block (size=9223372036854775296), \
         not from the inner ImageStream block (size=4718592)"
    );
}

/// Base-Allocated virtual disk size must come from the aff4:Map block (268,435,456 = 256 MiB),
/// not from the inner aff4:ImageStream block (3,964,928 bytes).
///
/// Without Map support the reader opens the ImageStream directly and reports 3,964,928.
#[test]
fn corpus_base_allocated_virtual_size() {
    let path = corpus("Base-Allocated.aff4");
    if !path.exists() {
        return;
    }
    let reader = Aff4Reader::open(&path).expect("open Base-Allocated.aff4");
    assert_eq!(
        reader.virtual_disk_size(),
        268_435_456_u64,
        "virtual_disk_size must come from aff4:Map block (268435456), \
         not from the inner ImageStream block (3964928)"
    );
}

// ── ImageStream content hashes (the integrity-audit surface) ──────────────────
//
// The recomputable aff4:hash digests live on the ImageStream node and cover the
// decompressed ImageStream content (aff4:size bytes), NOT the map-expanded
// virtual disk. Evimetry authored these digests, so they are an independent
// Tier-1 oracle for the analyzer's recompute-and-compare.

/// `stored_image_hashes()` parses every `aff4:hash` declared on the ImageStream.
#[test]
fn corpus_allhashes_stored_image_hashes_parsed() {
    let path = corpus("Base-Linear-AllHashes.aff4");
    if !path.exists() {
        return;
    }
    let reader = Aff4Reader::open(&path).expect("open");
    let hashes = reader.stored_image_hashes();
    let algos: std::collections::BTreeSet<String> = hashes
        .iter()
        .map(|h| h.algorithm.to_ascii_uppercase())
        .collect();
    for a in ["MD5", "SHA1", "SHA256", "SHA512", "BLAKE2B"] {
        assert!(algos.contains(a), "missing stored {a}; got {algos:?}");
    }
    let md5 = hashes
        .iter()
        .find(|h| h.algorithm.eq_ignore_ascii_case("MD5"))
        .expect("MD5 present");
    assert_eq!(
        md5.hex, "d5825dc1152a42958c8219ff11ed01a3",
        "stored MD5 (Evimetry-authored) must be parsed verbatim"
    );
}

/// `read_image_stream_content()` yields the decompressed ImageStream bytes
/// (length == aff4:size) and begins with the real MBR.
#[test]
fn corpus_allhashes_image_stream_content_is_real() {
    let path = corpus("Base-Linear-AllHashes.aff4");
    if !path.exists() {
        return;
    }
    let mut reader = Aff4Reader::open(&path).expect("open");
    assert_eq!(reader.image_stream_size(), 3_964_928);
    let mut total = 0u64;
    let mut head: Vec<u8> = Vec::new();
    reader
        .read_image_stream_content(|c| {
            if head.len() < 512 {
                let want = 512 - head.len();
                head.extend_from_slice(&c[..c.len().min(want)]);
            }
            total += c.len() as u64;
        })
        .expect("read ImageStream content");
    assert_eq!(
        total, 3_964_928,
        "ImageStream content length must equal aff4:size"
    );
    assert_eq!(
        (head[510], head[511]),
        (0x55, 0xAA),
        "ImageStream content begins with the MBR (boot signature at 510)"
    );
}
