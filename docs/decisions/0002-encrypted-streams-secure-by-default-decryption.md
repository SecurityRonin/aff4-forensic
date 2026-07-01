# 2. Encrypted streams: refuse by default, decrypt only with a key

Status: accepted (2026-07-01)

## Context

AFF4 can wrap its data in an `aff4:EncryptedStream` (AES-XTS, with a
password- or certificate-wrapped keybag). A reader must neither silently emit
ciphertext as if it were plaintext nor make the safe path require reading docs.

## Decision

- **Secure by default:** the passwordless `Aff4Reader::open` *refuses* an
  encrypted image with a named `Aff4Error::Encrypted` — it never returns
  ciphertext. Decryption is a separate, explicit, key-bearing entry point,
  `LogicalContainer::open_encrypted(path, password)`.
- **Never hand-roll crypto:** key derivation and cipher are all RustCrypto —
  `PBKDF2-HMAC-SHA256` → `RFC 3394 AES key-unwrap` (`aes-kw`) → `AES-128-XTS`
  (`xts-mode`). The RFC 3394 integrity check *is* the wrong-password detector, so
  a bad password fails loudly instead of yielding garbage.
- **Dependency generation is pinned deliberately:** the crypto crates are held at
  the `cipher`-0.4 / `digest`-0.10 generation (`aes` 0.8, `aes-kw` 0.2,
  `xts-mode` 0.5, `pbkdf2` 0.12) rather than the newer 0.9/0.5 line. The reader
  already pulls `aes`/`cipher`/`crypto-common` transitively via
  `zip-forensic-core`'s AES-zip support; matching that generation keeps a single
  copy of each in the tree (satisfying `cargo deny`'s `multiple-versions = deny`)
  and keeps a low MSRV.
- **Only password keybags for now:** certificate/public-key keybags are detected
  and refused as unsupported (not attempted).

## Consequences

- The zero-config path is safe; decryption is an audited opt-in.
- Validation is Tier-2: a pyaff4-minted oracle decrypts to a known plaintext MD5,
  cross-checked by an independent from-scratch decrypt (not pyaff4's own code).
- Bumping the crypto crates to the 0.9/0.5 generation is a deliberate future
  decision that must be paired with `zip-forensic-core` moving too, or it
  reintroduces duplicate `aes`/`cipher` versions.
