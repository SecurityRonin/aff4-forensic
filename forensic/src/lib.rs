//! AFF4 forensic analyzer — image-hash integrity verification and structural
//! anomaly detection, layered over the `aff4` reader (`aff4::Aff4Reader`).
//!
//! **SCAFFOLD.** `audit_image` is a stub; the real work is the strict-TDD plan in
//! `../HANDOFF.md` (hash verification → `AFF4-HASH-MISMATCH` findings; the
//! reader-side gaps — allocated maps, AFF4-L, encryption — live in `core/`).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::Path;

use aff4::{Aff4Error, Aff4Reader};
use forensicnomicon::report::Finding;

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

// TODO(handoff §1): `impl forensicnomicon::report::Observation for Aff4Anomaly`
// + a `to_finding(Source) -> Finding`, per the fleet report model.

/// Audit an AFF4 image's integrity: recompute each declared `aff4:hash` over the
/// virtual stream and compare it against the stored digest.
///
/// **SCAFFOLD** — opens the reader to prove the wiring, then returns no findings.
/// Oracle: `core/tests/data/Base-Linear-AllHashes.aff4`. See `../HANDOFF.md` §1.
///
/// # Errors
/// Returns [`Aff4Error`] if the image cannot be opened or parsed.
pub fn audit_image(path: &Path) -> Result<Vec<Finding>, Aff4Error> {
    let _reader = Aff4Reader::open(path)?;
    // TODO(handoff §1, strict TDD): read the aff4:hash properties from
    // information.turtle, recompute over the virtual stream with the RustCrypto
    // digests, and push an AFF4-HASH-MISMATCH finding on any divergence.
    Ok(Vec::new())
}
