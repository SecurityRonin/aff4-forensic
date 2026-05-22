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
