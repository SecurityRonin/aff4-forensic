//! Fuzz target: feed arbitrary bytes to `LogicalContainer::open` and, on success,
//! read every enumerated logical file.
//!
//! Invariant: must not panic; may return Ok or Err.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_logical
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

fuzz_target!(|data: &[u8]| {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(data).expect("write");
    if let Ok(mut container) = aff4::LogicalContainer::open(f.path()) {
        let entries = container.files().to_vec();
        for entry in &entries {
            let _ = container.read_file(entry);
        }
    }
});
