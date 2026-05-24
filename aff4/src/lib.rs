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
use meta::{Compression, parse_turtle};
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
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        let turtle = {
            let mut entry = archive.by_name("information.turtle")?;
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            content
        };

        let meta = parse_turtle(&turtle)?;

        // Detect the actual ZIP entry prefix. Real AFF4 images from Evimetry and
        // aff4-imager URL-encode the IRI in entry names: aff4%3A%2F%2F{uuid}/…
        // Synthetic test fixtures use the bare UUID. Try encoded form first.
        let stripped_arn = meta.stream_arn
            .strip_prefix("aff4://")
            .unwrap_or(&meta.stream_arn);
        let encoded_prefix = format!("aff4%3A%2F%2F{stripped_arn}");
        let zip_base = if archive.file_names().any(|n| n.starts_with(&encoded_prefix)) {
            encoded_prefix
        } else {
            stripped_arn.to_string()
        };

        Ok(Self {
            archive,
            zip_base,
            virtual_size: meta.virtual_size,
            chunk_size: meta.chunk_size,
            chunks_per_segment: meta.chunks_per_segment,
            compression: meta.compression,
            pos: 0,
        })
    }

    /// Virtual disk size in bytes (as declared in `aff4:size`).
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_size
    }

    /// Read a single chunk by its absolute index across all bevies.
    fn read_chunk(&mut self, chunk_idx: u64) -> Result<Vec<u8>, Aff4Error> {
        let segment_idx = chunk_idx / self.chunks_per_segment;
        let chunk_in_seg = chunk_idx % self.chunks_per_segment;

        let segment_name = format!("{}/{:08x}", self.zip_base, segment_idx);
        let index_name = format!("{}.index", segment_name);

        // Bevy index: format-dependent (see chunk_bounds_from_index).
        let index_data = self.read_zip_entry_bytes(&index_name)?;
        let (chunk_start, chunk_end) =
            chunk_bounds_from_index(&index_data, chunk_in_seg, self.chunks_per_segment)?;

        // Sparse chunk: 0-byte index entry means virtual zeros.
        if chunk_start == chunk_end {
            return Ok(vec![0u8; self.chunk_size as usize]);
        }

        let bevy_data = self.read_zip_entry_bytes(&segment_name)?;

        if chunk_end > bevy_data.len() {
            return Err(Aff4Error::BadFormat(format!(
                "chunk bounds ({chunk_start}..{chunk_end}) exceed bevy size ({})",
                bevy_data.len()
            )));
        }

        let compressed = &bevy_data[chunk_start..chunk_end];

        match &self.compression {
            Compression::Null => Ok(compressed.to_vec()),
            Compression::Deflate => {
                let mut dec = flate2::read::ZlibDecoder::new(compressed);
                let mut out = Vec::with_capacity(self.chunk_size as usize);
                dec.read_to_end(&mut out)
                    .map_err(|e| Aff4Error::BadFormat(format!("deflate decode: {e}")))?;
                Ok(out)
            }
            Compression::Snappy => {
                let mut dec = snap::raw::Decoder::new();
                dec.decompress_vec(compressed)
                    .map_err(|e| Aff4Error::BadFormat(format!("snappy decode: {e}")))
            }
            Compression::Lz4 => {
                let mut dec = lz4_flex::frame::FrameDecoder::new(compressed);
                let mut out = Vec::with_capacity(self.chunk_size as usize);
                dec.read_to_end(&mut out)
                    .map_err(|e| Aff4Error::BadFormat(format!("lz4 decode: {e}")))?;
                Ok(out)
            }
        }
    }

    fn read_zip_entry_bytes(&mut self, name: &str) -> Result<Vec<u8>, Aff4Error> {
        let mut entry = self.archive.by_name(name)?;
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        Ok(data)
    }
}

impl Read for Aff4Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.pos >= self.virtual_size {
            return Ok(0);
        }

        let remaining = (self.virtual_size - self.pos) as usize;
        let to_read = buf.len().min(remaining);

        let chunk_idx = self.pos / self.chunk_size;
        let offset_in_chunk = (self.pos % self.chunk_size) as usize;

        let chunk = self
            .read_chunk(chunk_idx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let available = chunk.len().saturating_sub(offset_in_chunk);
        let n = to_read.min(available);

        if n == 0 {
            return Ok(0);
        }

        buf[..n].copy_from_slice(&chunk[offset_in_chunk..offset_in_chunk + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Aff4Reader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => self.virtual_size as i64 + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of stream",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

/// Decode chunk byte bounds from a bevy index.
///
/// Two index formats exist:
/// - **Evimetry** (AFF4 Standard v1.0): `index[i]` = cumulative END byte of chunk i.
///   Array length = `chunks_per_segment × 4` bytes.
/// - **Scudette / aff4-imager**: `index[i]` = START byte of chunk i;
///   `index[chunks_per_segment]` = total bevy size.
///   Array length = `(chunks_per_segment + 1) × 4` bytes.
///
/// The length discriminator is reliable: the two formats differ by exactly one entry.
fn chunk_bounds_from_index(
    index: &[u8],
    chunk_in_seg: u64,
    chunks_per_segment: u64,
) -> Result<(usize, usize), Aff4Error> {
    let idx = chunk_in_seg as usize;
    let n = chunks_per_segment as usize;
    let entry_size = 4usize;

    fn read_u32(data: &[u8], byte_offset: usize) -> u32 {
        u32::from_le_bytes([
            data[byte_offset],
            data[byte_offset + 1],
            data[byte_offset + 2],
            data[byte_offset + 3],
        ])
    }

    // Scudette: (n+1) entries; Evimetry: n entries.
    let scudette = index.len() == (n + 1) * entry_size;

    if scudette {
        if (idx + 2) * entry_size > index.len() {
            return Err(Aff4Error::BadFormat(format!(
                "bevy index (Scudette) too small for chunk {idx}"
            )));
        }
        let start = read_u32(index, idx * entry_size) as usize;
        let end = read_u32(index, (idx + 1) * entry_size) as usize;
        Ok((start, end))
    } else {
        // Evimetry: need entry [idx].
        if (idx + 1) * entry_size > index.len() {
            return Err(Aff4Error::BadFormat(format!(
                "bevy index too small for chunk {idx}"
            )));
        }
        let end = read_u32(index, idx * entry_size) as usize;
        let start = if idx == 0 {
            0
        } else {
            read_u32(index, (idx - 1) * entry_size) as usize
        };
        Ok((start, end))
    }
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

    // ── Panic regression tests (RED until meta.rs validates chunk geometry) ───

    #[test]
    fn chunk_size_zero_rejected() {
        // chunk_size=0 in turtle causes div-by-zero on `self.pos / self.chunk_size`
        // (lib.rs Read::read). Currently open() succeeds; after fix, open() returns Err.
        let img = testutil::test_aff4_with_geometry(0, 1);
        let f = write_tmp(&img);
        assert!(Aff4Reader::open(f.path()).is_err());
    }

    #[test]
    fn chunks_per_segment_zero_rejected() {
        // chunks_per_segment=0 causes div-by-zero on `chunk_idx / self.chunks_per_segment`
        // (lib.rs read_chunk). Currently open() succeeds; after fix, open() returns Err.
        let img = testutil::test_aff4_with_geometry(512, 0);
        let f = write_tmp(&img);
        assert!(Aff4Reader::open(f.path()).is_err());
    }

    // ── LZ4 frame compression (aff4-imager) ──────────────────────────────────
    //
    // aff4-imager uses LZ4 frame compression (magic 0x04224D18) with the URI
    // <https://github.com/lz4/lz4>. Without LZ4 detection, the turtle falls
    // through to Compression::Null and returns raw compressed bytes as data.
    #[test]
    fn lz4_compressed_chunk_reads_decompressed_data() {
        let img = testutil::test_aff4_lz4(&[0xCCu8; 512]);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open lz4 aff4");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(
            buf, [0xCCu8; 512],
            "LZ4-compressed chunk must be decompressed; without LZ4 support, \
             raw frame bytes are returned instead of [0xCC; 512]"
        );
    }

    // ── Scudette/aff4-imager start-offset bevy index format ──────────────────
    //
    // aff4-imager (Scudette) writes index[i] = START byte of chunk i, with
    // index[n] = total bevy size. This means index[0] == 0 always.
    // Evimetry writes index[i] = END byte (cumulative), so index[0] != 0.
    // Without detection, the Scudette first chunk is misread as sparse (start==end==0).
    #[test]
    fn scudette_index_format_reads_data_not_zeros() {
        let img = testutil::test_aff4_scudette(&[0xBBu8; 512]);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open scudette aff4");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(
            buf, [0xBBu8; 512],
            "Scudette index format (index[0]==0) must be detected and read correctly; \
             without detection, chunk 0 is misidentified as sparse and returns zeros"
        );
    }

    // ── Existing tests ────────────────────────────────────────────────────────

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
        // Evimetry: 1 entry (chunks_per_segment=1), index[0] = end of chunk 0.
        let end_offset: u32 = 512;
        let index = end_offset.to_le_bytes().to_vec();
        let (start, end) = chunk_bounds_from_index(&index, 0, 1).expect("bounds");
        assert_eq!((start, end), (0, 512));
    }

    #[test]
    fn chunk_bounds_from_index_second_chunk() {
        // Evimetry: 2 entries (chunks_per_segment=2).
        let index: Vec<u8> = [100u32, 220u32]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let (start, end) = chunk_bounds_from_index(&index, 1, 2).expect("bounds");
        assert_eq!((start, end), (100, 220));
    }

    // ── Property tests: open() never panics on arbitrary input ────────────────

    proptest::proptest! {
        #[test]
        fn open_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            let f = write_tmp(&bytes);
            let _ = Aff4Reader::open(f.path());
        }
    }
}
