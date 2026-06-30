//! Fuzz target: drive the integrity audit (open → recompute → reconcile) over
//! arbitrary bytes.
//!
//! Invariant: must not panic; may return Ok(findings) or Err.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_audit
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

fuzz_target!(|data: &[u8]| {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(data).expect("write");
    let _ = aff4_forensic::audit_image(f.path());
});
