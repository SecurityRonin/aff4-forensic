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

/// Read sector 0 from Base-Linear.aff4.
///
/// Chunks 0 and 1 are sparse (0-byte index entries), so virtual bytes 0–65535
/// should read as zeros. Currently fails due to:
/// 1. URL-encoded ZIP entry name not found
/// 2. Sparse chunk returning empty Vec instead of chunk_size zeros
/// 3. Snappy compression not supported
#[test]
fn corpus_base_linear_sector0_reads_ok() {
    let path = corpus("Base-Linear.aff4");
    if !path.exists() {
        return;
    }
    let mut reader = Aff4Reader::open(&path).expect("open");
    let mut buf = [0u8; 512];
    reader.read_exact(&mut buf).expect("sector 0 must be readable");
    // Chunks 0 and 1 are sparse — sector 0 must be all zeros.
    assert_eq!(
        buf,
        [0u8; 512],
        "sparse region (chunks 0-1) must read as zeros"
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
    reader.seek(SeekFrom::Start(98304)).expect("seek to first non-sparse virtual region");
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

    let entry_size = 4usize;
    let end =
        u32::from_le_bytes(index_bytes[chunk_idx * entry_size..(chunk_idx + 1) * entry_size]
            .try_into()
            .unwrap()) as usize;
    let start = if chunk_idx == 0 {
        0
    } else {
        u32::from_le_bytes(
            index_bytes[(chunk_idx - 1) * entry_size..chunk_idx * entry_size]
                .try_into()
                .unwrap(),
        ) as usize
    };

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
