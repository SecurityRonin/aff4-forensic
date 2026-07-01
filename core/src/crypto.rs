//! AES-XTS decryption of `aff4:EncryptedStream` containers.
//!
//! An encrypted AFF4 stores its ciphertext as an ImageStream-shaped bevy of
//! fixed-size chunks, each independently AES-XTS-encrypted, and wraps the volume
//! key in a password-derived keybag. Decryption (all RustCrypto — never
//! hand-rolled):
//!
//! 1. `KEK = PBKDF2-HMAC-SHA256(password, salt, iterations, keySizeInBytes)`.
//! 2. `VEK = RFC 3394 AES-Key-Unwrap(KEK, wrappedKey)` — an integrity-checked
//!    unwrap, so a wrong password fails loudly rather than yielding garbage.
//! 3. AES-128-XTS with `key1 = VEK[0..16]`, `key2 = VEK[16..32]`; each 512-byte
//!    chunk is one XTS sector with tweak = its global chunk index (little-endian).
//! 4. Concatenate, trim to the declared plaintext `aff4:size`.
//!
//! The decrypted bytes are themselves an inner AFF4 volume (see
//! [`crate::LogicalContainer::open_encrypted`]).

use std::fs::File;
use std::io::Read;
use std::path::Path;

use aes::cipher::KeyInit;
use aes::Aes128;
use aes_kw::KekAes256;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use xts_mode::{get_tweak_default, Xts128};
use zip_core::ZipArchive;

use crate::meta::{parse_encrypted_meta, EncryptedMeta};
use crate::{chunk_bounds_from_index, detect_zip_base, Aff4Error, ReadSeekSend};

/// Decrypt an encrypted AFF4 container with `password`, returning the plaintext
/// of its `aff4:EncryptedStream` — an inner AFF4 volume.
///
/// # Errors
/// [`Aff4Error::Encrypted`] for a wrong password or an unsupported keybag;
/// [`Aff4Error::BadFormat`] if the container is not an encrypted AFF4 or its
/// metadata cannot be parsed; [`Aff4Error::Io`] / [`Aff4Error::Zip`] on read
/// failures.
pub fn decrypt_encrypted_stream(path: &Path, password: &str) -> Result<Vec<u8>, Aff4Error> {
    decrypt_reader(Box::new(File::open(path)?), password)
}

/// Byte-source variant of [`decrypt_encrypted_stream`].
///
/// # Errors
/// See [`decrypt_encrypted_stream`].
pub fn decrypt_reader(
    backing: Box<dyn ReadSeekSend>,
    password: &str,
) -> Result<Vec<u8>, Aff4Error> {
    let mut archive = ZipArchive::new(backing)?;
    let turtle = {
        let mut entry = archive.by_name("information.turtle")?;
        let mut s = String::new();
        entry.read_to_string(&mut s)?;
        s
    };
    let meta = parse_encrypted_meta(&turtle)?;
    let vek = derive_vek(password, &meta)?;

    let cipher_1 = Aes128::new_from_slice(&vek[0..16])
        .map_err(|_| Aff4Error::BadFormat("XTS key1 length".into()))?;
    let cipher_2 = Aes128::new_from_slice(&vek[16..32])
        .map_err(|_| Aff4Error::BadFormat("XTS key2 length".into()))?;
    let xts = Xts128::new(cipher_1, cipher_2);

    let zip_base = detect_zip_base(&archive, &meta.stream_arn);
    let mut out = Vec::with_capacity(meta.size as usize);
    let mut produced: u64 = 0;
    let mut segment: u64 = 0;
    while produced < meta.size {
        let segment_name = format!("{zip_base}/{segment:08x}");
        let index = read_entry(&mut archive, &format!("{segment_name}.index"))?;
        let bevy = read_entry(&mut archive, &segment_name)?;
        let chunks_in_segment = index.len() / 12;
        if chunks_in_segment == 0 {
            return Err(Aff4Error::BadFormat(
                "encrypted segment has an empty chunk index".into(),
            ));
        }
        for chunk_in_seg in 0..chunks_in_segment as u64 {
            if produced >= meta.size {
                break;
            }
            let (start, end) = chunk_bounds_from_index(&index, chunk_in_seg)?;
            if end > bevy.len() {
                return Err(Aff4Error::BadFormat(format!(
                    "encrypted chunk bounds ({start}..{end}) exceed bevy size ({})",
                    bevy.len()
                )));
            }
            let mut sector = bevy[start..end].to_vec();
            let chunk_id = segment
                .checked_mul(meta.chunks_per_segment)
                .and_then(|b| b.checked_add(chunk_in_seg))
                .ok_or_else(|| Aff4Error::BadFormat("encrypted chunk index overflow".into()))?;
            xts.decrypt_sector(&mut sector, get_tweak_default(u128::from(chunk_id)));
            let take = (sector.len() as u64).min(meta.size - produced) as usize;
            out.extend_from_slice(&sector[..take]);
            produced += take as u64;
        }
        segment = segment
            .checked_add(1)
            .ok_or_else(|| Aff4Error::BadFormat("encrypted segment index overflow".into()))?;
    }
    Ok(out)
}

/// Derive the volume encryption key: PBKDF2 → RFC 3394 unwrap.
fn derive_vek(password: &str, meta: &EncryptedMeta) -> Result<[u8; 32], Aff4Error> {
    // AES-128-XTS uses a 32-byte VEK (two 16-byte keys); the KEK is likewise 32
    // bytes (AES-256 key wrap). Both equal `keySizeInBytes`.
    if meta.key_size != 32 {
        return Err(Aff4Error::Encrypted(format!(
            "unsupported keySizeInBytes {} (only 32-byte AES-128-XTS keys are supported)",
            meta.key_size
        )));
    }
    let mut kek = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &meta.salt, meta.iterations, &mut kek);

    // RFC 3394 AES-256 key unwrap — the integrity check (unwrapped IV must equal
    // 0xA6…A6) is what distinguishes a correct password from a wrong one.
    let kek = KekAes256::from(kek);
    let mut vek = [0u8; 32];
    kek.unwrap(&meta.wrapped_key, &mut vek).map_err(|_| {
        Aff4Error::Encrypted("wrong password (key-unwrap integrity check failed)".into())
    })?;
    Ok(vek)
}

fn read_entry(
    archive: &mut ZipArchive<Box<dyn ReadSeekSend>>,
    name: &str,
) -> Result<Vec<u8>, Aff4Error> {
    let mut entry = archive.by_name(name)?;
    let mut data = Vec::new();
    entry.read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::meta::EncryptedMeta;
    use std::io::Write as _;
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::CompressionMethod;

    const ORACLE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/encrypted-linear-password.aff4"
    );
    const ENC_INDEX: &str = "aff4://c2dbd75f-b81c-4c14-8449-29e22f1601c8/00000000.index";

    /// Rebuild the oracle, replacing the encrypted stream's index entry — the
    /// keybag is left intact so the VEK still derives and the decrypt loop runs.
    fn oracle_with_index(new_index: &[u8]) -> tempfile::NamedTempFile {
        let file = std::fs::File::open(ORACLE).unwrap();
        let mut zin = zip::ZipArchive::new(file).unwrap();
        let names: Vec<String> = zin.file_names().map(String::from).collect();
        let mut buf = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut zw = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for name in &names {
                let mut data = Vec::new();
                zin.by_name(name).unwrap().read_to_end(&mut data).unwrap();
                if name == ENC_INDEX {
                    data = new_index.to_vec();
                }
                zw.start_file(name, opts).unwrap();
                zw.write_all(&data).unwrap();
            }
            zw.finish().unwrap();
        }
        let out = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(out.path(), buf.into_inner()).unwrap();
        out
    }

    #[test]
    fn empty_segment_index_errs() {
        let f = oracle_with_index(&[]);
        let err = decrypt_encrypted_stream(f.path(), "password").unwrap_err();
        assert!(matches!(err, Aff4Error::BadFormat(m) if m.contains("empty chunk index")));
    }

    #[test]
    fn chunk_bounds_exceeding_bevy_errs() {
        // One 12-byte entry: offset 0, length far beyond the bevy.
        let mut idx = 0u64.to_le_bytes().to_vec();
        idx.extend_from_slice(&999_999u32.to_le_bytes());
        let f = oracle_with_index(&idx);
        let err = decrypt_encrypted_stream(f.path(), "password").unwrap_err();
        assert!(matches!(err, Aff4Error::BadFormat(m) if m.contains("exceed bevy size")));
    }

    #[test]
    fn stops_at_declared_size_with_extra_index_entry() {
        // Append a 19th index entry so the segment advertises more chunks than the
        // declared size needs — the loop must break at `size` (still decrypting the
        // correct inner volume).
        let file = std::fs::File::open(ORACLE).unwrap();
        let mut z = zip::ZipArchive::new(file).unwrap();
        let mut idx = Vec::new();
        z.by_name(ENC_INDEX).unwrap().read_to_end(&mut idx).unwrap();
        idx.extend_from_slice(&[0u8; 12]);
        let f = oracle_with_index(&idx);
        let inner = decrypt_encrypted_stream(f.path(), "password").unwrap();
        assert!(inner.starts_with(b"PK\x03\x04"), "inner AFF4 ZIP volume");
        assert_eq!(inner.len(), 9074, "trimmed to the declared plaintext size");
    }

    #[test]
    fn unsupported_key_size_is_refused() {
        let meta = EncryptedMeta {
            stream_arn: "aff4://s".into(),
            chunks_per_segment: 1,
            size: 1,
            salt: vec![0u8; 16],
            iterations: 1,
            key_size: 16, // not the required 32
            wrapped_key: vec![0u8; 24],
        };
        assert!(matches!(
            derive_vek("pw", &meta),
            Err(Aff4Error::Encrypted(_))
        ));
    }
}
