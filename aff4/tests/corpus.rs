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

/// Open Base-Linear.aff4 and verify the virtual disk size matches the turtle metadata.
/// This passes even without chunk reads (metadata-only path).
#[test]
fn corpus_base_linear_virtual_disk_size() {
    let path = corpus("Base-Linear.aff4");
    if !path.exists() {
        return;
    }
    let reader = Aff4Reader::open(&path).expect("open Base-Linear.aff4");
    // aff4:size in information.turtle for the ImageStream is 3,964,928 bytes.
    assert_eq!(
        reader.virtual_disk_size(),
        3_964_928,
        "virtual_disk_size must match aff4:size from turtle"
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
/// Chunk 2 (virtual offset 65536) is the first non-sparse chunk.
#[test]
fn corpus_base_linear_snappy_chunk_matches_reference() {
    let path = corpus("Base-Linear.aff4");
    if !path.exists() {
        return;
    }

    // Compute reference bytes: extract chunk 2 directly from ZIP + snap-decompress.
    let reference = reference_bytes_via_zip_snap(&path, 65536, 512);

    let mut reader = Aff4Reader::open(&path).expect("open");
    reader.seek(SeekFrom::Start(65536)).expect("seek to chunk 2");
    let mut buf = vec![0u8; 512];
    reader
        .read_exact(&mut buf)
        .expect("chunk 2 (first Snappy chunk) must be readable");

    assert_eq!(
        &buf,
        &reference[..],
        "bytes at offset 65536 must match Snappy-decompressed ZIP reference"
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
