//! AFF4 (Advanced Forensic Format 4) read-only disk image reader.
//!
//! AFF4 is a ZIP-based container format with RDF/Turtle metadata. Disk images
//! are stored as chunked "bevies" (ZIP segments). This crate supports
//! `NullCompressor` and `DeflateCompressor` chunk compression.

mod error;
mod meta;

#[cfg(any(test, feature = "test-helpers"))]
pub mod testutil;

pub use error::Aff4Error;
use meta::{Compression, StreamMeta};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use zip::ZipArchive;

/// A read-only AFF4 disk image reader.
///
/// Implements [`Read`] and [`Seek`] over the virtual disk address space.
pub struct Aff4Reader {
    archive: ZipArchive<File>,
    zip_base: String,
    virtual_size: u64,
    chunk_size: u64,
    chunks_per_segment: u64,
    compression: Compression,
    pos: u64,
}

impl std::fmt::Debug for Aff4Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aff4Reader")
            .field("virtual_size", &self.virtual_size)
            .field("chunk_size", &self.chunk_size)
            .finish()
    }
}

impl Aff4Reader {
    /// Open an AFF4 image file.
    ///
    /// Reads `information.turtle` from the ZIP container to locate the primary
    /// `aff4:ImageStream` and its geometry (size, chunk size, compression).
    pub fn open(path: &Path) -> Result<Self, Aff4Error> {
        todo!()
    }

    /// Virtual disk size in bytes (as declared in `aff4:size`).
    pub fn virtual_disk_size(&self) -> u64 {
        todo!()
    }

    fn read_chunk(&mut self, _chunk_idx: u64) -> Result<Vec<u8>, Aff4Error> {
        todo!()
    }

    fn read_zip_entry_bytes(&mut self, _name: &str) -> Result<Vec<u8>, Aff4Error> {
        todo!()
    }
}

impl Read for Aff4Reader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

impl Seek for Aff4Reader {
    fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
        todo!()
    }
}

fn stream_arn_to_zip_base(arn: &str) -> String {
    arn.strip_prefix("aff4://").unwrap_or(arn).to_string()
}

fn chunk_bounds_from_index(index: &[u8], chunk_in_seg: u64) -> Result<(usize, usize), Aff4Error> {
    let idx = chunk_in_seg as usize;
    let entry_size = 4usize;

    if (idx + 1) * entry_size > index.len() {
        return Err(Aff4Error::BadFormat(format!(
            "bevy index too small for chunk {idx}"
        )));
    }

    fn read_u32(data: &[u8], byte_offset: usize) -> u32 {
        u32::from_le_bytes([
            data[byte_offset],
            data[byte_offset + 1],
            data[byte_offset + 2],
            data[byte_offset + 3],
        ])
    }

    let end = read_u32(index, idx * entry_size) as usize;
    let start = if idx == 0 {
        0
    } else {
        read_u32(index, (idx - 1) * entry_size) as usize
    };

    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Write as _;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(data).expect("write");
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(Aff4Reader::open(Path::new("/tmp/nope_aff4_issen.aff4")).is_err());
    }

    #[test]
    fn open_non_zip_returns_err() {
        let f = write_tmp(&[0u8; 1024]);
        assert!(Aff4Reader::open(f.path()).is_err());
    }

    #[test]
    fn open_zip_without_turtle_returns_err() {
        let cursor = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(cursor);
        zw.start_file("dummy.txt", SimpleFileOptions::default())
            .expect("start");
        let data = zw.finish().expect("finish").into_inner();
        let f = write_tmp(&data);
        assert!(Aff4Reader::open(f.path()).is_err());
    }

    #[test]
    fn virtual_disk_size_matches_metadata() {
        let img = testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let reader = Aff4Reader::open(f.path()).expect("open");
        assert_eq!(reader.virtual_disk_size(), testutil::CHUNK_SIZE as u64);
    }

    #[test]
    fn read_returns_correct_bytes() {
        let mut data = [0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = testutil::test_aff4(&data);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        reader.seek(SeekFrom::Start(10)).expect("seek");
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn seek_from_end_works() {
        let img = testutil::test_aff4(&[0xAB; 512]);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        let pos = reader.seek(SeekFrom::End(-1)).expect("seek end");
        assert_eq!(pos, 511);
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf[0], 0xAB);
    }

    #[test]
    fn read_past_end_returns_zero_bytes() {
        let img = testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        reader.seek(SeekFrom::Start(512)).expect("seek");
        let mut buf = [0u8; 4];
        let n = reader.read(&mut buf).expect("read");
        assert_eq!(n, 0);
    }

    #[test]
    fn aff4_reader_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Aff4Reader>();
    }

    #[test]
    fn chunk_bounds_from_index_single_chunk() {
        let end_offset: u32 = 512;
        let index = end_offset.to_le_bytes().to_vec();
        let (start, end) = chunk_bounds_from_index(&index, 0).expect("bounds");
        assert_eq!((start, end), (0, 512));
    }

    #[test]
    fn chunk_bounds_from_index_second_chunk() {
        let index: Vec<u8> = [100u32, 220u32]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let (start, end) = chunk_bounds_from_index(&index, 1).expect("bounds");
        assert_eq!((start, end), (100, 220));
    }
}
