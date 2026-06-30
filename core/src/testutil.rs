//! Test fixture builder for minimal AFF4 images.

use std::io::Write as _;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

/// Virtual chunk size used in test fixtures.
pub const CHUNK_SIZE: usize = 512;

/// Encode one AFF4 Standard v1.0 bevy-index entry: `(u64 byte_offset, u32 length)`
/// little-endian — the chunk's position and stored size within the bevy segment.
fn index_entry(offset: u64, length: u32) -> [u8; 12] {
    let mut e = [0u8; 12];
    e[0..8].copy_from_slice(&offset.to_le_bytes());
    e[8..12].copy_from_slice(&length.to_le_bytes());
    e
}

const STREAM_ARN: &str = "aff4://issen-test-stream";
const MAP_ARN: &str = "aff4://issen-test-map";
const IMAGE_STREAM_ARN: &str = "aff4://issen-test-image-stream";
const MAP_ZIP_BASE: &str = "issen-test-map";
const IMAGE_ZIP_BASE: &str = "issen-test-image-stream";
const ZIP_BASE: &str = "issen-test-stream";

/// Build a minimal AFF4 image with explicit chunk geometry (for negative tests).
///
/// Only the turtle metadata is written; bevy entries use dummy 512-byte data.
/// Pass zero for `chunk_size` or `chunks_per_segment` to test rejection.
pub fn test_aff4_with_geometry(chunk_size: u64, chunks_per_segment: u64) -> Vec<u8> {
    let turtle = format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix aff4: <http://aff4.org/Schema#> .\n\
         <{STREAM_ARN}> rdf:type aff4:ImageStream ; \
         aff4:size 512 ; \
         aff4:chunkSize {chunk_size} ; \
         aff4:chunksInSegment {chunks_per_segment} ; \
         aff4:compressionMethod aff4:NullCompressor .\n"
    );

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    zw.start_file("information.turtle", opts)
        .expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    zw.start_file(format!("{ZIP_BASE}/00000000").as_str(), opts)
        .expect("start bevy");
    zw.write_all(&[0u8; 512]).expect("write bevy");

    zw.start_file(format!("{ZIP_BASE}/00000000.index").as_str(), opts)
        .expect("start index");
    zw.write_all(&index_entry(0, 512)).expect("write index");

    zw.finish().expect("finish zip").into_inner()
}

/// Build a minimal AFF4 image containing one 512-byte chunk (NullCompressor).
///
/// `data` is padded or truncated to [`CHUNK_SIZE`] bytes.
pub fn test_aff4(data: &[u8]) -> Vec<u8> {
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let n = data.len().min(CHUNK_SIZE);
    chunk[..n].copy_from_slice(&data[..n]);

    let turtle = format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix aff4: <http://aff4.org/Schema#> .\n\
         <{STREAM_ARN}> rdf:type aff4:ImageStream ; \
         aff4:size {CHUNK_SIZE} ; \
         aff4:chunkSize {CHUNK_SIZE} ; \
         aff4:chunksInSegment 1 ; \
         aff4:compressionMethod aff4:NullCompressor .\n"
    );

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    zw.start_file("information.turtle", opts)
        .expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    let bevy_name = format!("{ZIP_BASE}/00000000");
    zw.start_file(bevy_name.as_str(), opts).expect("start bevy");
    zw.write_all(&chunk).expect("write bevy");

    let index_name = format!("{ZIP_BASE}/00000000.index");
    zw.start_file(index_name.as_str(), opts)
        .expect("start index");
    zw.write_all(&index_entry(0, CHUNK_SIZE as u32))
        .expect("write index");

    zw.finish().expect("finish zip").into_inner()
}

/// Build a minimal AFF4 image with LZ4-frame-compressed chunks (aff4-imager style).
///
/// Uses the `lz4_flex` crate (dev-dep only) to compress `data` into an LZ4 frame.
/// The turtle specifies `aff4:compressionMethod <https://github.com/lz4/lz4>` (aff4-imager URI).
#[cfg(test)]
pub fn test_aff4_lz4(data: &[u8]) -> Vec<u8> {
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let n = data.len().min(CHUNK_SIZE);
    chunk[..n].copy_from_slice(&data[..n]);

    let mut compressed = Vec::new();
    {
        use std::io::Write as _;
        let mut enc = lz4_flex::frame::FrameEncoder::new(&mut compressed);
        enc.write_all(&chunk).expect("lz4 compress");
        enc.finish().expect("lz4 finish");
    }

    let turtle = format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix aff4: <http://aff4.org/Schema#> .\n\
         <{STREAM_ARN}> rdf:type aff4:ImageStream ; \
         aff4:size {CHUNK_SIZE} ; \
         aff4:chunkSize {CHUNK_SIZE} ; \
         aff4:chunksInSegment 1 ; \
         aff4:compressionMethod <https://github.com/lz4/lz4> .\n"
    );

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    zw.start_file("information.turtle", opts)
        .expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    let bevy_name = format!("{ZIP_BASE}/00000000");
    zw.start_file(bevy_name.as_str(), opts).expect("start bevy");
    zw.write_all(&compressed).expect("write bevy");

    let index_name = format!("{ZIP_BASE}/00000000.index");
    zw.start_file(index_name.as_str(), opts)
        .expect("start index");
    zw.write_all(&index_entry(0, compressed.len() as u32))
        .expect("write index");

    zw.finish().expect("finish zip").into_inner()
}

/// Build a minimal AFF4 image backed by an `aff4:Map` stream with a zero-gap prefix.
///
/// Layout:
/// - Virtual bytes 0..511  : gap (mapGapDefaultStream = aff4:Zero → returns zeros)
/// - Virtual bytes 512..1023: mapped to the ImageStream at target offset 0 (= `data`)
///
/// This layout means that WITHOUT Map support the reader either:
///   (a) returns ImageStream data at virtual offset 0 (fails the gap-is-zeros check), or
///   (b) fails the read at virtual offset 512 (ImageStream.size=512, so offset 512 is past end).
pub fn test_aff4_map(data: &[u8]) -> Vec<u8> {
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let n = data.len().min(CHUNK_SIZE);
    chunk[..n].copy_from_slice(&data[..n]);

    // Virtual size 1024: gap at [0,512), data at [512,1024).
    let virtual_size: u64 = 1024;

    let turtle = format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix aff4: <http://aff4.org/Schema#> .\n\
         <{IMAGE_STREAM_ARN}> rdf:type aff4:ImageStream ; \
         aff4:size {CHUNK_SIZE} ; \
         aff4:chunkSize {CHUNK_SIZE} ; \
         aff4:chunksInSegment 1 ; \
         aff4:compressionMethod aff4:NullCompressor .\n\
         <{MAP_ARN}> rdf:type aff4:Map ; \
         aff4:size {virtual_size} ; \
         aff4:dependentStream <{IMAGE_STREAM_ARN}> ; \
         aff4:mapGapDefaultStream aff4:Zero .\n"
    );

    // Map binary: one entry, map_off=512, length=512, tgt_off=0, tgt_id=0
    // Layout: map_offset(u64) + length(u64) + target_offset(u64) + target_id(u32) = 28 bytes
    let mut map_bin = Vec::with_capacity(28);
    map_bin.extend_from_slice(&512u64.to_le_bytes()); // map_offset
    map_bin.extend_from_slice(&512u64.to_le_bytes()); // length
    map_bin.extend_from_slice(&0u64.to_le_bytes()); // target_offset
    map_bin.extend_from_slice(&0u32.to_le_bytes()); // target_id (index into idx file)

    let idx = format!("{IMAGE_STREAM_ARN}\n");

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    zw.start_file("information.turtle", opts)
        .expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    zw.start_file(format!("{IMAGE_ZIP_BASE}/00000000").as_str(), opts)
        .expect("start bevy");
    zw.write_all(&chunk).expect("write bevy");

    zw.start_file(format!("{IMAGE_ZIP_BASE}/00000000.index").as_str(), opts)
        .expect("start index");
    zw.write_all(&index_entry(0, CHUNK_SIZE as u32))
        .expect("write index");

    zw.start_file(format!("{MAP_ZIP_BASE}/map").as_str(), opts)
        .expect("start map");
    zw.write_all(&map_bin).expect("write map");

    zw.start_file(format!("{MAP_ZIP_BASE}/idx").as_str(), opts)
        .expect("start idx");
    zw.write_all(idx.as_bytes()).expect("write idx");

    zw.finish().expect("finish zip").into_inner()
}

/// Build a minimal AFF4 container whose data stream is an `aff4:EncryptedStream`
/// (password-wrapped keybag, AES-XTS), mirroring pyaff4's encrypted profile.
///
/// The reader must DETECT this profile and refuse loudly — never emit
/// plausible-but-wrong plaintext. Only the metadata markers needed for detection
/// are written.
pub fn test_aff4_encrypted() -> Vec<u8> {
    let turtle = format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix aff4: <http://aff4.org/Schema#> .\n\
         <{STREAM_ARN}> rdf:type aff4:EncryptedStream ; \
         aff4:size 4096 ; \
         aff4:chunkSize {CHUNK_SIZE} ; \
         aff4:chunksInSegment 1 ; \
         aff4:keyBag <{STREAM_ARN}/keybag> ; \
         aff4:compressionMethod aff4:NullCompressor .\n\
         <{STREAM_ARN}/keybag> rdf:type aff4:PasswordWrappedKeyBag ; \
         aff4:keySizeInBytes 32 ; \
         aff4:salt \"00112233445566778899aabbccddeeff\" ; \
         aff4:wrappedKey \"deadbeef\" .\n"
    );

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zw.start_file("information.turtle", opts)
        .expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");
    zw.finish().expect("finish zip").into_inner()
}

/// Build a minimal AFF4-Logical (AFF4-L) container: one `aff4:FileImage` stored
/// directly as a named ZIP segment, with `originalFileName`, `aff4:size`, and an
/// `aff4:hash` (MD5), mirroring pyaff4's `dream.aff4` shape.
///
/// `segment` is the ZIP entry name (also the path tail of the FileImage ARN);
/// `content` is its bytes; `md5_hex` is the stored MD5 digest.
pub fn test_aff4_logical(segment: &str, content: &[u8], md5_hex: &str) -> Vec<u8> {
    let vol = "aff4://issen-test-logical-volume";
    let turtle = format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix aff4: <http://aff4.org/Schema#> .\n\
         @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\
         <{vol}/{segment}> rdf:type aff4:FileImage , aff4:Image , aff4:zip_segment ; \
         aff4:originalFileName \"./{segment}\"^^xsd:string ; \
         aff4:size {} ; \
         aff4:lastWritten \"2018-09-17T13:42:20+10:00\"^^xsd:datetime ; \
         aff4:hash \"{md5_hex}\"^^aff4:MD5 ; \
         aff4:stored <{vol}> .\n",
        content.len()
    );

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zw.start_file("information.turtle", opts)
        .expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");
    zw.start_file(segment, opts).expect("start segment");
    zw.write_all(content).expect("write segment");
    zw.start_file("version.txt", opts).expect("start version");
    zw.write_all(b"major=1\nminor=1\ntool=issen-test\n")
        .expect("write version");
    zw.finish().expect("finish zip").into_inner()
}
