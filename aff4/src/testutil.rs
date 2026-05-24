//! Test fixture builder for minimal AFF4 images.

use std::io::Write as _;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

/// Virtual chunk size used in test fixtures.
pub const CHUNK_SIZE: usize = 512;

const STREAM_ARN: &str = "aff4://issen-test-stream";
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

    zw.start_file("information.turtle", opts).expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    zw.start_file(format!("{ZIP_BASE}/00000000").as_str(), opts)
        .expect("start bevy");
    zw.write_all(&[0u8; 512]).expect("write bevy");

    zw.start_file(format!("{ZIP_BASE}/00000000.index").as_str(), opts)
        .expect("start index");
    zw.write_all(&512u32.to_le_bytes()).expect("write index");

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

    zw.start_file("information.turtle", opts).expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    let bevy_name = format!("{ZIP_BASE}/00000000");
    zw.start_file(bevy_name.as_str(), opts).expect("start bevy");
    zw.write_all(&chunk).expect("write bevy");

    let index_name = format!("{ZIP_BASE}/00000000.index");
    zw.start_file(index_name.as_str(), opts).expect("start index");
    let end_offset: u32 = CHUNK_SIZE as u32;
    zw.write_all(&end_offset.to_le_bytes()).expect("write index");

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

    zw.start_file("information.turtle", opts).expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    let bevy_name = format!("{ZIP_BASE}/00000000");
    zw.start_file(bevy_name.as_str(), opts).expect("start bevy");
    zw.write_all(&compressed).expect("write bevy");

    let index_name = format!("{ZIP_BASE}/00000000.index");
    zw.start_file(index_name.as_str(), opts).expect("start index");
    zw.write_all(&(compressed.len() as u32).to_le_bytes()).expect("write index");

    zw.finish().expect("finish zip").into_inner()
}

/// Build a minimal AFF4 image using the Scudette/aff4-imager start-offset index format.
///
/// Unlike the Evimetry format (cumulative end-offsets, `index[0] != 0`), the
/// Scudette format stores START offsets: `index[i]` = byte start of chunk i, and
/// `index[chunks_per_segment]` = total bevy size. This means `index[0] == 0` always.
pub fn test_aff4_scudette(data: &[u8]) -> Vec<u8> {
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

    zw.start_file("information.turtle", opts).expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");

    let bevy_name = format!("{ZIP_BASE}/00000000");
    zw.start_file(bevy_name.as_str(), opts).expect("start bevy");
    zw.write_all(&chunk).expect("write bevy");

    // Scudette index: [start_0, end_0] = [0, CHUNK_SIZE]
    let index_name = format!("{ZIP_BASE}/00000000.index");
    zw.start_file(index_name.as_str(), opts).expect("start index");
    zw.write_all(&0u32.to_le_bytes()).expect("write index start");
    zw.write_all(&(CHUNK_SIZE as u32).to_le_bytes()).expect("write index end");

    zw.finish().expect("finish zip").into_inner()
}
