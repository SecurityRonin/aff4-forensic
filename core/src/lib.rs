//! AFF4 (Advanced Forensic Format 4) read-only disk image reader.
//!
//! AFF4 is a ZIP-based container format with RDF/Turtle metadata. Disk images
//! are stored as chunked "bevies" (ZIP segments). This crate supports
//! `NullCompressor`, `DeflateCompressor`, Snappy, and LZ4 frame compression.
//!
//! Images may be direct `aff4:ImageStream`s or `aff4:Map`-backed, where a Map
//! redirects virtual addresses to ImageStream regions, Zero-fill, or SymbolicStreamFF.

mod crypto;
mod error;
mod logical;
mod map;
mod meta;

#[cfg(any(test, feature = "test-helpers"))]
pub mod testutil;

pub use crypto::{decrypt_encrypted_stream, decrypt_reader};
pub use error::Aff4Error;
pub use logical::{LogicalContainer, LogicalEntry};
use map::{parse_idx, parse_map_entries, resolve, LoadedMap, TargetKind};
use meta::{parse_logical_files, parse_turtle, Compression};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use zip_core::ZipArchive;

/// A seekable, thread-safe byte source the AFF4 container ZIP can sit on: a
/// `File`, an in-RAM `Cursor`, or a positioned sub-range of an outer `.zip`.
/// Lets a caller open an AFF4 image straight from a byte source (no temp-file
/// extraction) via [`Aff4Reader::open_reader`], while [`Aff4Reader::open`] keeps
/// the file-path convenience.
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

/// A content digest declared on the ImageStream node (`aff4:hash`).
///
/// `algorithm` is the RDF datatype as written in the turtle, with the `aff4:`
/// prefix stripped — e.g. `"SHA512"`, `"MD5"`, `"SHA1"`, `"SHA256"`, `"Blake2b"`.
/// `hex` is the stored digest, lowercased. These digests cover the decompressed
/// ImageStream content streamed by [`Aff4Reader::read_image_stream_content`], not
/// the map-expanded virtual disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHash {
    /// Hash algorithm datatype (e.g. `"SHA256"`).
    pub algorithm: String,
    /// Stored digest as lowercase hex.
    pub hex: String,
}

/// The kind of AFF4 container, determined from `information.turtle` without
/// fully opening the image — cheap enough for filesystem detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// A disk image (`aff4:ImageStream` / `aff4:Map`) — read via [`Aff4Reader`].
    Disk,
    /// An AFF4-Logical file collection (`aff4:FileImage`) — read via
    /// [`LogicalContainer`].
    Logical,
    /// An encrypted container (`aff4:EncryptedStream`); the inner shape is
    /// hidden behind the ciphertext and needs a password to open.
    Encrypted,
}

/// Classify an AFF4 container by reading its `information.turtle` once.
///
/// A lightweight probe for detection: it loads no streams and decrypts nothing.
/// Returns [`Aff4Error::BadFormat`] if the file is not an AFF4 container (no
/// readable `information.turtle` describing a known shape).
pub fn container_kind(path: &Path) -> Result<ContainerKind, Aff4Error> {
    let mut archive = ZipArchive::new(Box::new(File::open(path)?) as Box<dyn ReadSeekSend>)?;
    let turtle = {
        let mut entry = archive.by_name("information.turtle")?;
        let mut content = String::new();
        entry.read_to_string(&mut content)?;
        content
    };
    // AFF4-Logical is identified by one or more aff4:FileImage nodes.
    if !parse_logical_files(&turtle)?.is_empty() {
        return Ok(ContainerKind::Logical);
    }
    // Otherwise it is a disk image: parse_turtle resolves an aff4:ImageStream /
    // aff4:Map, and returns Aff4Error::Encrypted for an aff4:EncryptedStream.
    match parse_turtle(&turtle) {
        Ok(_) => Ok(ContainerKind::Disk),
        Err(Aff4Error::Encrypted(_)) => Ok(ContainerKind::Encrypted),
        Err(e) => Err(e),
    }
}

/// A read-only AFF4 disk image reader.
///
/// Implements [`Read`] and [`Seek`] over the virtual disk address space.
/// Supports both direct `aff4:ImageStream` images and `aff4:Map`-backed images
/// (e.g., Evimetry `Base-Allocated` and `Base-ExabyteSparse`).
pub struct Aff4Reader {
    archive: ZipArchive<Box<dyn ReadSeekSend>>,
    /// ZIP entry prefix for the `aff4:ImageStream` bevies.
    zip_base: String,
    virtual_size: u64,
    /// Decompressed length of the ImageStream content (its own `aff4:size`).
    image_stream_size: u64,
    chunk_size: u64,
    chunks_per_segment: u64,
    compression: Compression,
    /// Content digests declared on the ImageStream node (`aff4:hash`).
    image_hashes: Vec<StoredHash>,
    pos: u64,
    /// Loaded map for Map-backed images; `None` for direct ImageStreams.
    loaded_map: Option<LoadedMap>,
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
    /// Open an AFF4 image from a file path. See [`Self::open_reader`] for the
    /// byte-source variant (read straight from an outer `.zip`, etc.).
    ///
    /// # Errors
    /// [`Aff4Error`] if the file cannot be opened or is not a valid AFF4 image.
    pub fn open(path: &Path) -> Result<Self, Aff4Error> {
        Self::open_reader(Box::new(File::open(path)?))
    }

    /// Reads `information.turtle` from the ZIP container to locate the primary
    /// data stream (either a direct `aff4:ImageStream` or an `aff4:Map`-backed
    /// image) and its geometry (size, chunk size, compression).
    ///
    /// # Errors
    /// [`Aff4Error`] if `backing` is not a valid AFF4 container or its metadata
    /// cannot be parsed.
    pub fn open_reader(backing: Box<dyn ReadSeekSend>) -> Result<Self, Aff4Error> {
        let mut archive = ZipArchive::new(backing)?;

        let turtle = {
            let mut entry = archive.by_name("information.turtle")?;
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            content
        };

        let meta = parse_turtle(&turtle)?;

        // Detect ZIP entry prefix for the ImageStream.  Real Evimetry/aff4-imager
        // images URL-encode the IRI: aff4%3A%2F%2F{uuid}/…  Synthetic fixtures
        // use the bare UUID.
        let zip_base = detect_zip_base(&archive, &meta.stream_arn);

        // If this is a Map-backed image, load the /map and /idx entries.
        let loaded_map = if let Some(mm) = meta.map_meta {
            let map_zip_base = detect_zip_base(&archive, &mm.map_arn);

            let map_data = {
                let map_entry_name = format!("{map_zip_base}/map");
                let mut entry = archive.by_name(&map_entry_name)?;
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                data
            };
            let idx_data = {
                let idx_entry_name = format!("{map_zip_base}/idx");
                let mut entry = archive.by_name(&idx_entry_name)?;
                let mut content = String::new();
                entry.read_to_string(&mut content)?;
                content
            };

            let entries = parse_map_entries(&map_data);
            let targets = parse_idx(&idx_data, &mm.image_stream_arn);
            let gap_default = if mm.gap_is_symbolic_ff {
                TargetKind::Fill(0xFF)
            } else {
                TargetKind::Fill(0x00)
            };
            Some(LoadedMap {
                entries,
                targets,
                gap_default,
            })
        } else {
            None
        };

        Ok(Self {
            archive,
            zip_base,
            virtual_size: meta.virtual_size,
            image_stream_size: meta.image_stream_size,
            chunk_size: meta.chunk_size,
            chunks_per_segment: meta.chunks_per_segment,
            compression: meta.compression,
            image_hashes: meta.image_hashes,
            pos: 0,
            loaded_map,
        })
    }

    /// Virtual disk size in bytes.
    ///
    /// For Map-backed images this is the Map's declared size, not the inner
    /// ImageStream's physical data size.
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_size
    }

    /// Decompressed length of the underlying `aff4:ImageStream` content.
    ///
    /// This is the ImageStream's own `aff4:size`, distinct from
    /// [`Self::virtual_disk_size`] (the map-expanded virtual disk). It is the
    /// number of bytes the ImageStream `aff4:hash` digests cover.
    pub fn image_stream_size(&self) -> u64 {
        self.image_stream_size
    }

    /// Content digests declared on the ImageStream node (`aff4:hash`).
    ///
    /// Each covers the decompressed ImageStream content (see
    /// [`Self::read_image_stream_content`]). Empty when the turtle declares none.
    pub fn stored_image_hashes(&self) -> &[StoredHash] {
        &self.image_hashes
    }

    /// Virtual `(offset, length)` regions the acquisition could not read
    /// (`aff4:UnreadableData` map targets), in offset order.
    ///
    /// Empty for a fully-imaged image or a direct (non-Map) ImageStream. These
    /// regions read back as the `UNREADABLEDATA` fill, so whole-disk integrity
    /// cannot be fully established over them.
    pub fn unreadable_regions(&self) -> Vec<(u64, u64)> {
        self.loaded_map
            .as_ref()
            .map(LoadedMap::unreadable_regions)
            .unwrap_or_default()
    }

    /// Stream the decompressed `aff4:ImageStream` content, in chunk order, to
    /// `sink` — the exact byte sequence the ImageStream `aff4:hash` digests cover.
    ///
    /// Feeds at most [`Self::image_stream_size`] bytes (the final chunk is
    /// truncated to the declared size). Use this to recompute and verify the
    /// stored content hashes without materialising the whole stream.
    ///
    /// # Errors
    /// [`Aff4Error`] if a chunk cannot be located or decompressed.
    pub fn read_image_stream_content(
        &mut self,
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), Aff4Error> {
        if self.chunk_size == 0 {
            // cov:unreachable: open() rejects chunk_size == 0 (meta.rs); defensive guard.
            return Err(Aff4Error::BadFormat("aff4:chunkSize must be > 0".into()));
        }
        let total = self.image_stream_size;
        let n_chunks = total.div_ceil(self.chunk_size);
        let mut produced = 0u64;
        for idx in 0..n_chunks {
            let chunk = self.read_chunk(idx)?;
            let remaining = total - produced;
            let take = (chunk.len() as u64).min(remaining) as usize;
            sink(&chunk[..take]);
            produced += take as u64;
        }
        Ok(())
    }

    /// Read a single chunk by its absolute index across all bevies.
    fn read_chunk(&mut self, chunk_idx: u64) -> Result<Vec<u8>, Aff4Error> {
        let segment_idx = chunk_idx / self.chunks_per_segment;
        let chunk_in_seg = chunk_idx % self.chunks_per_segment;

        let segment_name = format!("{}/{:08x}", self.zip_base, segment_idx);
        let index_name = format!("{segment_name}.index");

        // Bevy index: 12-byte (offset, length) entries (see chunk_bounds_from_index).
        let index_data = self.read_zip_entry_bytes(&index_name)?;
        let (chunk_start, chunk_end) = chunk_bounds_from_index(&index_data, chunk_in_seg)?;

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

        // AFF4 rule: a chunk whose stored size equals chunk_size was written
        // uncompressed (compression did not shrink it), regardless of the stream's
        // declared compressionMethod. Decompressing it would fail or corrupt.
        if compressed.len() == self.chunk_size as usize {
            return Ok(compressed.to_vec());
        }

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

/// Detect the ZIP entry prefix for an AFF4 ARN.
///
/// Evimetry / aff4-imager URL-encode the IRI: `aff4%3A%2F%2F{uuid}/…`
/// Synthetic test fixtures use the bare path after stripping `aff4://`.
pub(crate) fn detect_zip_base(archive: &ZipArchive<Box<dyn ReadSeekSend>>, arn: &str) -> String {
    let stripped = arn.strip_prefix("aff4://").unwrap_or(arn);
    let encoded = format!("aff4%3A%2F%2F{stripped}");
    // Producers name the bevy entries three ways: URL-encoded IRI
    // (Evimetry/aff4-imager), the literal `aff4://uuid` IRI (pyaff4 encrypted),
    // or the bare path. Prefer whichever the archive actually uses as a `<base>/`
    // segment prefix; fall back to the bare path for synthetic fixtures.
    for cand in [encoded.as_str(), arn, stripped] {
        if archive
            .file_names()
            .any(|n| n.starts_with(cand) && n[cand.len()..].starts_with('/'))
        {
            return cand.to_string();
        }
    }
    // A valid stream's bevies sit under one of the three `<base>/` prefixes above,
    // so the loop returns; this best-effort default only matters for a turtle whose
    // stream ARN matches no ZIP entry (a later read then fails with a clear error).
    // cov:unreachable
    stripped.to_string()
}

impl Read for Aff4Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.pos >= self.virtual_size {
            return Ok(0);
        }

        let remaining = (self.virtual_size - self.pos) as usize;
        let to_read = buf.len().min(remaining);

        // Resolve the current position through the Map (if present).
        // All values are Copy so the immutable borrow on `self.loaded_map` ends here.
        let (target_kind, target_offset, bytes_in_region) = if let Some(ref lm) = self.loaded_map {
            let r = resolve(lm, self.pos, self.virtual_size);
            (r.kind, r.target_offset, r.bytes_in_region)
        } else {
            (TargetKind::ImageStream, self.pos, u64::MAX)
        };

        match target_kind {
            TargetKind::Unknown => {
                let n = to_read.min(bytes_in_region as usize);
                buf[..n].fill(0);
                self.pos += n as u64;
                Ok(n)
            }
            TargetKind::Fill(byte) => {
                let n = to_read.min(bytes_in_region as usize);
                buf[..n].fill(byte);
                self.pos += n as u64;
                Ok(n)
            }
            TargetKind::Tile(tile) => {
                let n = to_read.min(bytes_in_region as usize);
                for (i, slot) in buf[..n].iter_mut().enumerate() {
                    *slot = tile.byte_at(target_offset + i as u64);
                }
                self.pos += n as u64;
                Ok(n)
            }
            TargetKind::ImageStream => {
                let region_limit = bytes_in_region as usize;
                let chunk_idx = target_offset / self.chunk_size;
                let offset_in_chunk = (target_offset % self.chunk_size) as usize;

                let chunk = self
                    .read_chunk(chunk_idx)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                let available = chunk
                    .len()
                    .saturating_sub(offset_in_chunk)
                    .min(region_limit);
                let n = to_read.min(available);

                if n == 0 {
                    // cov:unreachable: region non-empty & offset in-bounds ⇒ n > 0.
                    return Ok(0);
                }

                buf[..n].copy_from_slice(&chunk[offset_in_chunk..offset_in_chunk + n]);
                self.pos += n as u64;
                Ok(n)
            }
        }
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

/// Decode a chunk's `(start, end)` byte bounds within its bevy segment.
///
/// AFF4 Standard v1.0 bevy index (`<bevy>.index`): a packed array of 12-byte
/// little-endian entries, one per chunk in the segment —
/// `(u64 byte_offset, u32 length)` giving the chunk's position and stored
/// (possibly compressed) size inside the bevy. A zero-length entry marks a
/// sparse (all-zero) chunk. Verified by reproducing Evimetry's stored
/// `aff4:hash` digests over the reconstructed ImageStream content.
pub(crate) fn chunk_bounds_from_index(
    index: &[u8],
    chunk_in_seg: u64,
) -> Result<(usize, usize), Aff4Error> {
    const ENTRY_SIZE: usize = 12;
    let base = (chunk_in_seg as usize)
        .checked_mul(ENTRY_SIZE)
        .ok_or_else(|| Aff4Error::BadFormat("bevy index offset overflow".into()))?;
    let entry = index.get(base..base + ENTRY_SIZE).ok_or_else(|| {
        Aff4Error::BadFormat(format!("bevy index too small for chunk {chunk_in_seg}"))
    })?;

    let offset = u64::from_le_bytes(
        entry[0..8]
            .try_into()
            .map_err(|_| Aff4Error::BadFormat("bevy index entry truncated".into()))?,
    ) as usize;
    let length = u32::from_le_bytes(
        entry[8..12]
            .try_into()
            .map_err(|_| Aff4Error::BadFormat("bevy index entry truncated".into()))?,
    ) as usize;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Aff4Error::BadFormat("bevy chunk bounds overflow".into()))?;
    Ok((offset, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::Digest as _;
    use std::io::Cursor;
    use std::io::Write as _;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(data).expect("write");
        f
    }

    #[test]
    fn container_kind_classifies_disk_image() {
        let f = write_tmp(&testutil::test_aff4(&[0u8; 512]));
        assert_eq!(container_kind(f.path()).unwrap(), ContainerKind::Disk);
    }

    #[test]
    fn container_kind_classifies_logical() {
        let content = b"logical file body\n";
        let md5 = format!("{:x}", md5::Md5::digest(content));
        let f = write_tmp(&testutil::test_aff4_logical("dir/a.txt", content, &md5));
        assert_eq!(container_kind(f.path()).unwrap(), ContainerKind::Logical);
    }

    #[test]
    fn container_kind_classifies_encrypted() {
        let f = write_tmp(&testutil::test_aff4_encrypted());
        assert_eq!(container_kind(f.path()).unwrap(), ContainerKind::Encrypted);
    }

    #[test]
    fn container_kind_rejects_non_aff4() {
        // A ZIP with no information.turtle is not an AFF4 container.
        let mut buf = Vec::new();
        {
            let mut zw = ZipWriter::new(std::io::Cursor::new(&mut buf));
            zw.start_file("random.txt", SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"nope").unwrap();
            zw.finish().unwrap();
        }
        let f = write_tmp(&buf);
        assert!(container_kind(f.path()).is_err());
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

    // ── Encrypted volumes: detect and refuse (never emit garbage) ─────────────
    //
    // An aff4:EncryptedStream (AES-XTS, password/cert-wrapped keybag) must be
    // detected and refused with a named, encryption-specific error — not decoded
    // as if it were plaintext. Decryption is a later epic; the v1 floor is a
    // loud refusal (see HANDOFF §4).
    #[test]
    fn encrypted_stream_is_detected_and_refused() {
        let img = testutil::test_aff4_encrypted();
        let f = write_tmp(&img);
        let err = Aff4Reader::open(f.path()).expect_err("encrypted image must be refused");
        assert!(
            matches!(err, Aff4Error::Encrypted(_)),
            "must be a named Aff4Error::Encrypted, got {err:?}"
        );
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("encrypt"),
            "the refusal must name encryption as the cause; got: {err}"
        );
    }

    // ── AFF4-Logical (AFF4-L): a collection of files, not a disk image ────────
    //
    // AFF4-L stores logical files as named ZIP segments described by aff4:FileImage
    // nodes (path, size, hashes, timestamps). Open the container as a logical
    // collection, enumerate its files, and read one file's bytes. Cross-checked
    // against the zip oracle (the `zip` engine) and the stored MD5.
    #[test]
    fn logical_container_lists_and_reads_files() {
        let content = b"I have a Dream, delivered 1963.\n";
        let md5 = format!("{:x}", md5::Md5::digest(content));
        let img = testutil::test_aff4_logical("dir/dream.txt", content, &md5);
        let f = write_tmp(&img);

        let mut container = LogicalContainer::open(f.path()).expect("open AFF4-L container");
        let files = container.files().to_vec();
        assert_eq!(files.len(), 1, "one logical file expected");
        let entry = &files[0];
        assert_eq!(entry.original_file_name, "./dir/dream.txt");
        assert_eq!(entry.size, content.len() as u64);
        assert!(entry
            .hashes
            .iter()
            .any(|h| h.algorithm.eq_ignore_ascii_case("MD5") && h.hex == md5));

        let got = container.read_file(entry).expect("read logical file");
        assert_eq!(
            got, content,
            "logical file bytes must match the stored segment"
        );
    }

    #[test]
    fn virtual_disk_size_matches_metadata() {
        let img = testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let reader = Aff4Reader::open(f.path()).expect("open");
        assert_eq!(reader.virtual_disk_size(), testutil::CHUNK_SIZE as u64);
    }

    #[test]
    fn open_reader_over_cursor_matches_open_path() {
        let mut sector = [0u8; 512];
        sector[10] = 0xCA;
        sector[11] = 0xFE;
        let img = testutil::test_aff4(&sector);

        // Oracle: open(path) and read the whole virtual disk.
        let tmp = write_tmp(&img);
        let mut via_path = Aff4Reader::open(tmp.path()).expect("open path");
        let mut want = Vec::new();
        via_path.read_to_end(&mut want).expect("read path");

        // Under test: open_reader over an in-RAM Cursor of the SAME bytes — the
        // zip-direct backing path.
        let mut via_reader =
            Aff4Reader::open_reader(Box::new(Cursor::new(img.clone()))).expect("open_reader");
        let mut got = Vec::new();
        via_reader.read_to_end(&mut got).expect("read reader");

        assert_eq!(
            got, want,
            "open_reader must read byte-identically to open(path)"
        );
        assert_eq!(via_reader.virtual_disk_size(), via_path.virtual_disk_size());
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

    /// Build a bevy index of 12-byte `(u64 offset, u32 length)` entries.
    fn build_index(entries: &[(u64, u32)]) -> Vec<u8> {
        let mut v = Vec::with_capacity(entries.len() * 12);
        for &(off, len) in entries {
            v.extend_from_slice(&off.to_le_bytes());
            v.extend_from_slice(&len.to_le_bytes());
        }
        v
    }

    #[test]
    fn chunk_bounds_from_index_single_chunk() {
        // One 12-byte entry: chunk 0 at offset 0, length 512.
        let index = build_index(&[(0, 512)]);
        let (start, end) = chunk_bounds_from_index(&index, 0).expect("bounds");
        assert_eq!((start, end), (0, 512));
    }

    #[test]
    fn chunk_bounds_from_index_second_chunk() {
        // Chunk 1 sits at offset 100 with length 120 → bounds (100, 220).
        let index = build_index(&[(0, 100), (100, 120)]);
        let (start, end) = chunk_bounds_from_index(&index, 1).expect("bounds");
        assert_eq!((start, end), (100, 220));
    }

    #[test]
    fn chunk_bounds_from_index_out_of_range_errs() {
        // Index covers one chunk; asking for chunk 5 must error, not panic.
        let index = build_index(&[(0, 512)]);
        assert!(chunk_bounds_from_index(&index, 5).is_err());
    }

    // ── Map stream support ────────────────────────────────────────────────────
    //
    // AFF4 images acquired with Evimetry use aff4:Map as the top-level data
    // stream. The Map maps virtual offsets through a binary `/map` file to either
    // an ImageStream or a symbolic target (Zero, SymbolicStreamFF). Without Map
    // support, the reader opens the raw ImageStream and reports the wrong virtual
    // size; reads from mapped regions return wrong data or errors.

    #[test]
    fn map_virtual_size_from_map_block_not_image_stream() {
        // The Map turtle declares size=1024; the inner ImageStream declares size=512.
        // virtual_disk_size() must return the Map's size (1024), not the ImageStream's (512).
        let img = testutil::test_aff4_map(&[0u8; 512]);
        let f = write_tmp(&img);
        let reader = Aff4Reader::open(f.path()).expect("open map aff4");
        assert_eq!(
            reader.virtual_disk_size(),
            1024,
            "virtual_disk_size() must come from the aff4:Map block, not the ImageStream block"
        );
    }

    #[test]
    fn map_stream_gap_reads_zeros() {
        // Virtual bytes 0..511 are an unmapped gap (mapGapDefaultStream = aff4:Zero).
        // Without Map support, the reader reads ImageStream data (non-zero) instead.
        let img = testutil::test_aff4_map(&[0xDDu8; 512]);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open map aff4");
        let mut buf = [0xFFu8; 512]; // pre-fill non-zero to catch false positives
        reader.read_exact(&mut buf).expect("read gap region");
        assert_eq!(
            buf, [0u8; 512],
            "virtual bytes 0..511 are an unmapped gap and must read as zeros"
        );
    }

    #[test]
    fn map_stream_image_region_reads_correct_data() {
        // Virtual bytes 512..1023 map to the ImageStream at target offset 0.
        // Without Map support, the reader has virtual_size=512, so seeking to 512
        // is past the end and read_exact returns an error.
        let img = testutil::test_aff4_map(&[0xDDu8; 512]);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open map aff4");
        reader
            .seek(SeekFrom::Start(512))
            .expect("seek to mapped region");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read mapped region");
        assert_eq!(
            buf, [0xDDu8; 512],
            "virtual bytes 512..1023 map to the ImageStream and must return ImageStream data"
        );
    }

    /// Build a single-segment image from an explicit turtle, bevy base, bevy bytes
    /// and 12-byte-entry index bytes.
    fn build_image(turtle: &str, base: &str, bevy: &[u8], index: &[u8]) -> Vec<u8> {
        use zip::CompressionMethod;
        let cursor = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zw.start_file("information.turtle", opts).expect("turtle");
        zw.write_all(turtle.as_bytes()).expect("write turtle");
        zw.start_file(format!("{base}/00000000").as_str(), opts)
            .expect("bevy");
        zw.write_all(bevy).expect("write bevy");
        zw.start_file(format!("{base}/00000000.index").as_str(), opts)
            .expect("index");
        zw.write_all(index).expect("write index");
        zw.finish().expect("finish").into_inner()
    }

    fn index12(offset: u64, length: u32) -> Vec<u8> {
        let mut v = offset.to_le_bytes().to_vec();
        v.extend_from_slice(&length.to_le_bytes());
        v
    }

    #[test]
    fn debug_impl_renders() {
        let img = testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let reader = Aff4Reader::open(f.path()).expect("open");
        assert!(format!("{reader:?}").contains("Aff4Reader"));
    }

    #[test]
    fn seek_before_start_is_err() {
        let img = testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        assert!(reader.seek(SeekFrom::Current(-1)).is_err());
    }

    #[test]
    fn deflate_chunk_reads_decompressed() {
        let chunk = [0x7Au8; 512];
        let mut compressed = Vec::new();
        {
            let mut enc =
                flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
            enc.write_all(&chunk).expect("zlib");
            enc.finish().expect("finish");
        }
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <aff4://s> rdf:type aff4:ImageStream ; aff4:size 512 ; aff4:chunkSize 512 ; \
             aff4:chunksInSegment 1 ; aff4:compressionMethod aff4:DeflateCompressor .\n";
        let img = build_image(
            turtle,
            "s",
            &compressed,
            &index12(0, compressed.len() as u32),
        );
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open deflate");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0x7Au8; 512]);
    }

    #[test]
    fn map_gap_symbolic_ff_reads_0xff() {
        // A Map whose gap default is SymbolicStreamFF: the [0,512) gap reads 0xFF.
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <aff4://img> rdf:type aff4:ImageStream ; aff4:size 512 ; aff4:chunkSize 512 ; \
             aff4:chunksInSegment 1 ; aff4:compressionMethod aff4:NullCompressor .\n\
             <aff4://map> rdf:type aff4:Map ; aff4:size 1024 ; \
             aff4:dependentStream <aff4://img> ; \
             aff4:mapGapDefaultStream aff4:SymbolicStreamFF .\n";
        // Reuse build_image for the image stream, then add the map/idx entries.
        use zip::CompressionMethod;
        let cursor = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zw.start_file("information.turtle", opts).expect("turtle");
        zw.write_all(turtle.as_bytes()).expect("w");
        zw.start_file("img/00000000", opts).expect("bevy");
        zw.write_all(&[0xDDu8; 512]).expect("w");
        zw.start_file("img/00000000.index", opts).expect("idx");
        zw.write_all(&index12(0, 512)).expect("w");
        // Map entry: virtual [512,1024) -> image offset 0, target_id 0.
        let mut map_bin = 512u64.to_le_bytes().to_vec();
        map_bin.extend_from_slice(&512u64.to_le_bytes());
        map_bin.extend_from_slice(&0u64.to_le_bytes());
        map_bin.extend_from_slice(&0u32.to_le_bytes());
        zw.start_file("map/map", opts).expect("map");
        zw.write_all(&map_bin).expect("w");
        zw.start_file("map/idx", opts).expect("idxf");
        zw.write_all(b"aff4://img\n").expect("w");
        let img = zw.finish().expect("finish").into_inner();

        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open map-ff");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read gap");
        assert_eq!(buf, [0xFFu8; 512], "SymbolicStreamFF gap must read 0xFF");
    }

    #[test]
    fn chunk_bounds_exceeding_bevy_is_err() {
        // Index claims a chunk longer than the bevy segment → BadFormat on read.
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <aff4://s> rdf:type aff4:ImageStream ; aff4:size 512 ; aff4:chunkSize 512 ; \
             aff4:chunksInSegment 1 ; aff4:compressionMethod aff4:NullCompressor .\n";
        let img = build_image(turtle, "s", &[0u8; 512], &index12(0, 999_999));
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        let mut buf = [0u8; 512];
        assert!(reader.read_exact(&mut buf).is_err());
    }

    #[test]
    fn sparse_chunk_reads_zeros() {
        // A zero-length index entry marks a sparse chunk → chunk_size zeros.
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <aff4://s> rdf:type aff4:ImageStream ; aff4:size 512 ; aff4:chunkSize 512 ; \
             aff4:chunksInSegment 1 ; aff4:compressionMethod aff4:NullCompressor .\n";
        let img = build_image(turtle, "s", &[], &index12(0, 0));
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        let mut buf = [0xABu8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0u8; 512]);
    }

    #[test]
    fn null_partial_chunk_reads_stored_bytes() {
        // A Null chunk whose stored size differs from chunk_size takes the
        // Compression::Null match arm (not the stored-uncompressed fast path).
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <aff4://s> rdf:type aff4:ImageStream ; aff4:size 100 ; aff4:chunkSize 512 ; \
             aff4:chunksInSegment 1 ; aff4:compressionMethod aff4:NullCompressor .\n";
        let img = build_image(turtle, "s", &[0x5Au8; 100], &index12(0, 100));
        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        let mut buf = [0u8; 100];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0x5Au8; 100]);
    }

    #[test]
    fn unknown_map_target_reads_zeros() {
        // A map entry pointing at an unrecognised aff4:// stream reads as zeros.
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <aff4://img> rdf:type aff4:ImageStream ; aff4:size 512 ; aff4:chunkSize 512 ; \
             aff4:chunksInSegment 1 ; aff4:compressionMethod aff4:NullCompressor .\n\
             <aff4://map> rdf:type aff4:Map ; aff4:size 512 ; \
             aff4:dependentStream <aff4://img> ; aff4:mapGapDefaultStream aff4:Zero .\n";
        use zip::CompressionMethod;
        let cursor = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zw.start_file("information.turtle", opts).expect("t");
        zw.write_all(turtle.as_bytes()).expect("w");
        zw.start_file("img/00000000", opts).expect("b");
        zw.write_all(&[0xDDu8; 512]).expect("w");
        zw.start_file("img/00000000.index", opts).expect("i");
        zw.write_all(&index12(0, 512)).expect("w");
        // Map entry [0,512) → target_id 0, which the idx maps to an unknown stream.
        let mut map_bin = 0u64.to_le_bytes().to_vec();
        map_bin.extend_from_slice(&512u64.to_le_bytes());
        map_bin.extend_from_slice(&0u64.to_le_bytes());
        map_bin.extend_from_slice(&0u32.to_le_bytes());
        zw.start_file("map/map", opts).expect("m");
        zw.write_all(&map_bin).expect("w");
        zw.start_file("map/idx", opts).expect("x");
        zw.write_all(b"aff4://an-unknown-stream\n").expect("w");
        let img = zw.finish().expect("finish").into_inner();

        let f = write_tmp(&img);
        let mut reader = Aff4Reader::open(f.path()).expect("open");
        let mut buf = [0xFFu8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0u8; 512], "unknown map target must read as zeros");
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
