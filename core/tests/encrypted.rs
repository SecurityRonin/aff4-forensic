#![allow(clippy::unwrap_used, clippy::expect_used)]
//! AES-XTS encrypted-container decryption, validated against the minted oracle
//! `encrypted-linear-password.aff4` (see tests/data/README.md). Ground truth is
//! the plaintext MD5, cross-checked independently of pyaff4's own code path.

use aff4::{Aff4Error, LogicalContainer};
use md5::Digest as _;
use std::path::{Path, PathBuf};

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

#[test]
fn decrypt_and_read_inner_plaintext() {
    let p = data("encrypted-linear-password.aff4");
    let mut container =
        LogicalContainer::open_encrypted(&p, "password").expect("decrypt + open inner volume");
    let files = container.files().to_vec();
    let hello = files
        .iter()
        .find(|f| f.original_file_name.contains("hello.txt"))
        .expect("hello.txt logical entry");
    let bytes = container
        .read_file(hello)
        .expect("read decrypted hello.txt");
    assert_eq!(bytes.len(), 8192, "decrypted plaintext length");
    assert_eq!(
        format!("{:x}", md5::Md5::digest(&bytes)),
        "fedd7baa1fdf87bb8c12b18ad59ba738",
        "decrypted plaintext MD5 must match the independent oracle"
    );
}

#[test]
fn wrong_password_is_refused_not_garbage() {
    let p = data("encrypted-linear-password.aff4");
    let err = LogicalContainer::open_encrypted(&p, "not-the-password")
        .expect_err("a wrong password must be refused, never decoded to garbage");
    assert!(
        matches!(err, Aff4Error::Encrypted(_)),
        "wrong password must surface a named Encrypted error, got {err:?}"
    );
}
