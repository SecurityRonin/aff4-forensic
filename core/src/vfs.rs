//! `forensic-vfs` integration: a decoded AFF4 as an [`ImageSource`].
//!
//! A decoded AFF4 is a read-only, randomly-addressable byte stream — the
//! `ImageSource` contract. [`Aff4Reader`] maps virtual addresses through the
//! `aff4:Map` to compressed ImageStream chunks via a `Read + Seek` cursor (the
//! read advances an internal position, so it needs `&mut self`). It is therefore
//! wrapped here: [`Aff4Source`] holds the reader behind a poison-recovering
//! `Mutex` and serves `read_at` by seeking then reading under the lock — the same
//! technique the sibling VHD/VHDX/VMDK adapters use. Behind the `vfs` feature.

use std::sync::Mutex;

use forensic_vfs::{ImageSource, VfsResult};

use crate::Aff4Reader;

/// A decoded [`Aff4Reader`] presented as a read-only [`ImageSource`].
///
/// Construction records the virtual disk size once; `read_at` locks the reader,
/// seeks, and fills the buffer. Because an AFF4 read advances an internal cursor
/// (`&mut self`), reads **serialize through the mutex** — correct and
/// `Send + Sync`, at the cost of no intra-source read parallelism. The lock is
/// poison-recovering, so one panicking reader does not wedge the source.
pub struct Aff4Source {
    inner: Mutex<Aff4Reader>,
    len: u64,
}

impl Aff4Source {
    /// Wrap an open [`Aff4Reader`], recording its virtual disk size as the source
    /// length.
    pub fn new(reader: Aff4Reader) -> Self {
        let len = reader.virtual_disk_size();
        Self {
            inner: Mutex::new(reader),
            len,
        }
    }
}

impl ImageSource for Aff4Source {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // RED: positioned read not implemented yet.
        let _ = (offset, buf);
        Ok(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use forensic_vfs::ImageSource;

    use super::Aff4Source;
    use crate::Aff4Reader;

    /// The canonical Evimetry 3.0 AFF4 Standard v1.0 reference image (Tier-1 —
    /// independent third-party authorship). Source:
    /// <https://github.com/aff4/ReferenceImages>. Virtual disk size 268,435,456
    /// (256 MiB) per Evimetry's `information.turtle`, independent of our reader.
    static BASE_LINEAR: &[u8] = include_bytes!("../tests/data/Base-Linear.aff4");
    const VIRTUAL_DISK_SIZE: u64 = 268_435_456;

    #[test]
    fn aff4_reader_is_an_image_source() {
        let reader = Aff4Reader::open_reader(Box::new(Cursor::new(BASE_LINEAR)))
            .expect("open Base-Linear.aff4");
        assert_eq!(reader.virtual_disk_size(), VIRTUAL_DISK_SIZE);

        // The load-bearing claim: an Aff4Reader composes as a dyn ImageSource.
        let src: Arc<dyn ImageSource> = Arc::new(Aff4Source::new(reader));
        assert_eq!(src.len(), VIRTUAL_DISK_SIZE);
        assert!(!src.is_empty());

        // Sector 0 is a real MBR (Evimetry ground truth): boot signature 0x55AA
        // at virtual offset 510-511. Reaching it requires decompressing chunk 0
        // and routing through the Map.
        let mut sector = vec![0u8; 512];
        assert_eq!(src.read_at(0, &mut sector).expect("read_at 0"), 512);
        assert_eq!((sector[510], sector[511]), (0x55, 0xAA));
        assert_ne!(
            sector.as_slice(),
            [0u8; 512].as_slice(),
            "sector 0 is a real MBR, not a sparse zero region"
        );

        // A read starting at EOF yields 0 (ImageSource short-read contract).
        let mut eof = [0u8; 16];
        assert_eq!(
            src.read_at(VIRTUAL_DISK_SIZE, &mut eof).expect("eof read"),
            0
        );
    }
}
