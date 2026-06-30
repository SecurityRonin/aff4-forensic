//! AFF4 forensic analyzer — image-hash integrity verification and structural
//! anomaly detection, layered over the `aff4` reader (`aff4::Aff4Reader`).
//!
//! **SCAFFOLD.** `audit_image` is a stub; the real work is the strict-TDD plan in
//! `../HANDOFF.md` (hash verification → `AFF4-HASH-MISMATCH` findings; the
//! reader-side gaps — allocated maps, AFF4-L, encryption — live in `core/`).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::Path;

use aff4::{Aff4Error, Aff4Reader, StoredHash};
use blake2::Blake2b512;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use forensicnomicon::report::{Category, Observation, Severity};
pub use forensicnomicon::report::{Finding, Source};

/// Integrity / structural anomalies the AFF4 audit can surface.
///
/// Codes (scheme-prefixed SCREAMING-KEBAB, a published contract):
/// `AFF4-HASH-MISMATCH`, `AFF4-HASH-UNREADABLE`. New variants get new codes;
/// never change a shipped code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Aff4Anomaly {
    /// A stored `aff4:hash` does not match the recomputed digest of the stream.
    HashMismatch {
        algorithm: String,
        stored: String,
        computed: String,
    },
    /// The image data could not be fully read while hashing (read-error region).
    HashUnreadable { offset: u64 },
}

impl Observation for Aff4Anomaly {
    fn severity(&self) -> Option<Severity> {
        match self {
            // A content-hash mismatch is a strong tamper/corruption indicator.
            Aff4Anomaly::HashMismatch { .. } => Some(Severity::High),
            // An unreadable region is a known integrity caveat, not proof of tampering.
            Aff4Anomaly::HashUnreadable { .. } => Some(Severity::Medium),
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Aff4Anomaly::HashMismatch { .. } => "AFF4-HASH-MISMATCH",
            Aff4Anomaly::HashUnreadable { .. } => "AFF4-HASH-UNREADABLE",
        }
    }

    fn category(&self) -> Category {
        Category::Integrity
    }

    fn note(&self) -> String {
        match self {
            Aff4Anomaly::HashMismatch {
                algorithm,
                stored,
                computed,
            } => format!(
                "stored {algorithm} aff4:hash ({stored}) does not match the digest recomputed \
                 over the ImageStream content ({computed}) — consistent with tampering or media \
                 corruption"
            ),
            Aff4Anomaly::HashUnreadable { offset } => format!(
                "the image marks a region unreadable at virtual offset {offset} \
                 (aff4:UnreadableData); those bytes could not be acquired, so whole-image \
                 integrity cannot be fully verified"
            ),
        }
    }
}

/// Audit an AFF4 image's integrity: recompute each declared `aff4:hash` over the
/// virtual stream and compare it against the stored digest.
///
/// **SCAFFOLD** — opens the reader to prove the wiring, then returns no findings.
/// Oracle: `core/tests/data/Base-Linear-AllHashes.aff4`. See `../HANDOFF.md` §1.
///
/// # Errors
/// Returns [`Aff4Error`] if the image cannot be opened or parsed.
pub fn audit_image(path: &Path) -> Result<Vec<Finding>, Aff4Error> {
    let mut reader = Aff4Reader::open(path)?;
    let anomalies = verify_image_hashes(&mut reader)?;

    let source = Source {
        analyzer: "aff4-forensic".to_string(),
        scope: "ImageStream".to_string(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    Ok(anomalies
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect())
}

/// Recompute each declared ImageStream `aff4:hash` over the decompressed content
/// and return an [`Aff4Anomaly::HashMismatch`] for every divergence.
///
/// Stored digests whose algorithm this build cannot compute are skipped (no
/// false negative is claimed for them). All recognized algorithms are hashed in
/// a single streaming pass over the content.
///
/// # Errors
/// [`Aff4Error`] if the ImageStream content cannot be read.
fn verify_image_hashes(reader: &mut Aff4Reader) -> Result<Vec<Aff4Anomaly>, Aff4Error> {
    let stored: Vec<StoredHash> = reader.stored_image_hashes().to_vec();
    let mut jobs: Vec<(StoredHash, Hasher)> = stored
        .into_iter()
        .filter_map(|s| Hasher::for_algorithm(&s.algorithm).map(|h| (s, h)))
        .collect();

    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    reader.read_image_stream_content(|chunk| {
        for (_, hasher) in &mut jobs {
            hasher.update(chunk);
        }
    })?;

    let mut anomalies = Vec::new();
    for (stored, hasher) in jobs {
        let computed = hasher.finalize_hex();
        if computed != stored.hex {
            anomalies.push(Aff4Anomaly::HashMismatch {
                algorithm: stored.algorithm,
                stored: stored.hex,
                computed,
            });
        }
    }
    Ok(anomalies)
}

/// The RustCrypto digests AFF4 reference images declare on the ImageStream.
///
/// Never hand-rolled — each arm is a vetted RustCrypto implementation. An
/// algorithm with no arm here is simply not verified (the audit makes no claim
/// about it) rather than silently passed.
enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
    Blake2b(Blake2b512),
}

impl Hasher {
    /// Map an `aff4:hash` datatype (e.g. `"SHA512"`, `"Blake2b"`) to a hasher,
    /// or `None` if this build cannot compute it.
    fn for_algorithm(algorithm: &str) -> Option<Self> {
        match algorithm.to_ascii_uppercase().as_str() {
            "MD5" => Some(Hasher::Md5(Md5::new())),
            "SHA1" => Some(Hasher::Sha1(Sha1::new())),
            "SHA256" => Some(Hasher::Sha256(Sha256::new())),
            "SHA512" => Some(Hasher::Sha512(Sha512::new())),
            "BLAKE2B" => Some(Hasher::Blake2b(Blake2b512::new())),
            _ => None,
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
            Hasher::Blake2b(h) => h.update(data),
        }
    }

    fn finalize_hex(self) -> String {
        match self {
            Hasher::Md5(h) => to_hex(&h.finalize()),
            Hasher::Sha1(h) => to_hex(&h.finalize()),
            Hasher::Sha256(h) => to_hex(&h.finalize()),
            Hasher::Sha512(h) => to_hex(&h.finalize()),
            Hasher::Blake2b(h) => to_hex(&h.finalize()),
        }
    }
}

/// Lowercase hex encoding of a digest.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
