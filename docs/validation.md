# Validation (Tier-1)

`aff4-forensic` recomputes the integrity claims an AFF4 image makes about itself
and reconciles them against independent ground truth — Evimetry's own stored
`aff4:hash` digests on the reference corpus — not fixtures authored here alone.

## Hash verification (`AFF4-HASH-MISMATCH`)

`audit_image` recomputes every declared ImageStream `aff4:hash` (MD5, SHA1,
SHA256, SHA512, Blake2b — vetted RustCrypto digests) over the decompressed
ImageStream content in one streaming pass and emits an `AFF4-HASH-MISMATCH`
finding per divergence.

- **Clean image:** `Base-Linear-AllHashes.aff4` reconciles all five
  Evimetry-authored digests → zero mismatches.
- **Tamper:** flipping the first byte of the first stored-uncompressed chunk
  (derived from the 12-byte bevy index, not a magic offset) yields
  `AFF4-HASH-MISMATCH`.

The digests cover the ImageStream content (`aff4:size` bytes), not the
map-expanded virtual disk; no stored digest covers the full reconstructed disk,
so none is claimed.

## Unreadable regions (`AFF4-HASH-UNREADABLE`)

`Base-Linear-ReadError.aff4` carries 32 `aff4:UnreadableData` regions (2 MiB)
that could not be acquired. The audit emits one `AFF4-HASH-UNREADABLE` per region
(with its offset and length) while reporting **zero** `AFF4-HASH-MISMATCH` — the
intact ImageStream content still reconciles (stored MD5 `b2a8abd1…` matches), so
unreadable regions are reported as an integrity caveat, not as tampering.

## Epistemic framing

Findings are observations, never verdicts: a mismatch note reads "consistent with
tampering or media corruption", and an unreadable note states the caveat as a
property of the evidence ("whole-disk integrity cannot be fully established over
that region"). `Aff4Anomaly` maps to `forensicnomicon::report::Finding` via
`impl Observation` in the Integrity category. Finding codes
(`AFF4-HASH-MISMATCH`, `AFF4-HASH-UNREADABLE`) are a published contract.
