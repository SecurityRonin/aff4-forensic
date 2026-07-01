//! Fuzz target: feed arbitrary bytes to the encrypted-AFF4 decrypt path with a
//! fixed password.
//!
//! Invariant: must not panic; may return Ok or Err. Exercises the keybag/turtle
//! parsing, PBKDF2/RFC-3394 key derivation, and the AES-XTS chunk loop over
//! attacker-controlled containers.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_decrypt
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

fuzz_target!(|data: &[u8]| {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(data).expect("write");
    let _ = aff4::decrypt_encrypted_stream(f.path(), "password");
});
