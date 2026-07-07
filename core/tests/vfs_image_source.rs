#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration test: `Aff4Reader` composes as an `Arc<dyn forensic_vfs::ImageSource>`.
//!
//! Oracle tier: **Tier-1** — `Base-Linear.aff4` is the official AFF4 Standard
//! v1.0 reference image produced by Evimetry 3.0 (independent third-party
//! authorship).  Source: <https://github.com/aff4/ReferenceImages>.
//!
//! Ground truth asserted here (all from the Evimetry-authored image):
//! - `src.len() == 268_435_456` (256 MiB — the `aff4:Map` virtual disk size,
//!   declared in `information.turtle` by Evimetry, independent of our reader)
//! - `sector[510] == 0x55, sector[511] == 0xAA` — the MBR boot signature at
//!   the end of virtual sector 0 (stored in the Evimetry corpus; our reader
//!   must decompress Snappy chunk 0 and route through the Map to reach it)
//! - A read request starting at `src.len()` (EOF) returns 0 bytes
//!
//! The `aff4` crate carries NO production dependency on `forensic-vfs`; this
//! test adds it as a **dev-dependency only** (the published registry crate).
//! `SeekPoolSource` is not in the published `forensic-vfs 0.1.0`, so the reader
//! is wrapped in the local [`DynWrapper`] below — the same mutex-over-`Read+Seek`
//! technique `SeekPoolSource::single` uses in the engine — to prove the
//! `Arc<dyn ImageSource>` composition portably against the registry crate.

use aff4::Aff4Reader;
use forensic_vfs::{ImageSource, SourceId};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

/// Wraps a `Read + Seek` reader as an [`ImageSource`] using a mutex — the same
/// technique `SeekPoolSource::single` uses in the forensic-vfs engine. Kept
/// local because `SeekPoolSource` is not in the published `forensic-vfs 0.1.0`.
struct DynWrapper<R: Read + Seek + Send> {
    inner: Mutex<R>,
    len: u64,
}

impl<R: Read + Seek + Send> DynWrapper<R> {
    fn new(mut reader: R, len: u64) -> Self {
        reader.seek(SeekFrom::Start(0)).unwrap();
        Self {
            inner: Mutex::new(reader),
            len,
        }
    }
}

impl<R: Read + Seek + Send + 'static> ImageSource for DynWrapper<R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> forensic_vfs::VfsResult<usize> {
        let io_err = |op: &'static str| {
            move |source: std::io::Error| forensic_vfs::VfsError::Io { op, source }
        };
        let avail = self.len.saturating_sub(offset);
        if avail == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(avail) as usize;
        let mut g = self.inner.lock().unwrap();
        g.seek(SeekFrom::Start(offset)).map_err(io_err("seek"))?;
        let mut total = 0;
        while total < want {
            match g.read(&mut buf[total..want]).map_err(io_err("read"))? {
                0 => break,
                n => total += n,
            }
        }
        Ok(total)
    }

    fn source_id(&self) -> SourceId {
        SourceId::ROOT
    }
}

/// The canonical Evimetry 3.0 reference image, committed as a corpus fixture.
/// Source: https://github.com/aff4/ReferenceImages
/// SHA-256 of the .aff4 container file:
///   bcde3297ae95cd9df214bfb79821334628dad08f21ef38374a2c091481e391c0
/// Virtual disk size (from Evimetry turtle): 268,435,456 bytes (256 MiB)
static BASE_LINEAR_AFF4: &[u8] = include_bytes!("data/Base-Linear.aff4");

/// The virtual disk size declared by Evimetry in `information.turtle`:
///   `<aff4://fcbfdce7…> aff4:size 268435456`
const VIRTUAL_DISK_SIZE: u64 = 268_435_456;

/// Wrap `Aff4Reader` as an `Arc<dyn ImageSource>` and verify it presents the
/// correct size and content.
#[test]
fn aff4_reader_composes_as_image_source() {
    // Open via open_reader over an in-RAM Cursor of the corpus bytes.
    // This exercises the same path as the forensic-vfs engine would use
    // (feeding a SourceCursor wrapping the outer container bytes).
    let reader = Aff4Reader::open_reader(Box::new(Cursor::new(BASE_LINEAR_AFF4)))
        .expect("Aff4Reader::open_reader must succeed on Base-Linear.aff4");

    let vsize = reader.virtual_disk_size();
    assert_eq!(
        vsize, VIRTUAL_DISK_SIZE,
        "virtual_disk_size() must return the Evimetry Map size (268435456 = 256 MiB)"
    );

    // Wrap in DynWrapper — the same mutex-over-Read+Seek technique the engine's
    // SeekPoolSource::single uses (identical composition to VhdDecoder /
    // Qcow2Decoder in engine/src/lib.rs, proven against the registry crate).
    let src: Arc<dyn ImageSource> = Arc::new(DynWrapper::new(reader, vsize));

    // ── src.len() reflects the virtual disk size ──────────────────────────────
    assert_eq!(
        src.len(),
        VIRTUAL_DISK_SIZE,
        "ImageSource::len() must equal the virtual disk size"
    );

    // ── Sector 0: MBR boot signature at offset 510 ────────────────────────────
    // Ground truth: Evimetry stores a real MBR as the first Snappy-compressed
    // chunk.  Virtual offset 0 → ImageStream chunk 0 → MBR bytes.
    // Offset 510 = 0x55, offset 511 = 0xAA (the x86 boot signature).
    let mut sector = vec![0u8; 512];
    let n = src.read_at(0, &mut sector).expect("read_at sector 0");
    assert_eq!(n, 512, "sector 0 read must return exactly 512 bytes");
    assert_eq!(
        (sector[510], sector[511]),
        (0x55, 0xAA),
        "MBR boot signature 0x55AA must be at virtual offset 510–511 \
         (Evimetry corpus ground truth)"
    );
    assert_ne!(
        sector.as_slice(),
        [0u8; 512].as_slice(),
        "sector 0 is a real MBR, not a sparse zero region"
    );

    // ── Read past EOF returns 0 bytes ─────────────────────────────────────────
    let mut buf = [0u8; 16];
    let n_eof = src
        .read_at(VIRTUAL_DISK_SIZE, &mut buf)
        .expect("read_at EOF must not error");
    assert_eq!(
        n_eof, 0,
        "a read starting exactly at EOF must return 0 bytes"
    );
}
