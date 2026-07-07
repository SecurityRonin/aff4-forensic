#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration test: `Aff4Reader` composes as a `forensic_vfs::ImageSource`
//! via `SeekPoolSource::single`.
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
//! The `aff4` crate carries NO production dependency on `forensic-vfs`.
//! This test adds it as a **dev-dependency only** (GREEN commit).

use aff4::Aff4Reader;
use forensic_vfs::{adapters::SeekPoolSource, ImageSource};
use std::io::Cursor;
use std::sync::Arc;

/// The canonical Evimetry 3.0 reference image, committed as a corpus fixture.
/// Source: https://github.com/aff4/ReferenceImages
/// SHA-256 of the .aff4 container file:
///   bcde3297ae95cd9df214bfb79821334628dad08f21ef38374a2c091481e391c0
/// Virtual disk size (from Evimetry turtle): 268,435,456 bytes (256 MiB)
static BASE_LINEAR_AFF4: &[u8] = include_bytes!("data/Base-Linear.aff4");

/// The virtual disk size declared by Evimetry in `information.turtle`:
///   `<aff4://fcbfdce7…> aff4:size 268435456`
const VIRTUAL_DISK_SIZE: u64 = 268_435_456;

/// Wrap `Aff4Reader` in `SeekPoolSource::single` and verify the resulting
/// `Arc<dyn ImageSource>` presents the correct size and content.
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

    // Wrap in SeekPoolSource — this is the composition the forensic-vfs engine
    // uses (identical to VhdDecoder / Qcow2Decoder in engine/src/lib.rs).
    let src: Arc<dyn ImageSource> = Arc::new(SeekPoolSource::single(reader, vsize));

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
