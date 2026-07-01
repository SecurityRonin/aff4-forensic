# 5. Read via zip-forensic-core; the third-party ZIP writer is test-only

Status: accepted (2026-07-01, aff4 0.2.2)

## Context

An AFF4 container is a ZIP archive, so two ZIP crates are in play:

- **`zip-forensic-core`** — our pure-Rust, read-only forensic ZIP reader. It reads
  hostile archives without panicking and is the fleet's reader for ZIP-based
  containers.
- **The third-party `zip` crate** — a full read/write ZIP library. We use its
  *writer* to build synthetic AFF4 containers for the test fixtures (`testutil`,
  `#[cfg(test)]` modules); `zip-forensic-core` deliberately has no writer.

The reader had always read through `zip-forensic-core`, but `zip` was declared as a
plain dependency, so every downstream consumer of `aff4` pulled the third-party
writer even though the shipped reader never touches it.

## Decision

- All container reading goes through **`zip-forensic-core`** (`zip_core::ZipArchive`)
  — `Aff4Reader`, `LogicalContainer`, and the encrypted-stream decrypt path.
- The third-party `zip` crate is used **only to write test fixtures**, and is made
  **optional**, gated behind the `test-helpers` feature (`test-helpers = ["dep:zip"]`)
  plus a dev-dependency for this crate's own tests.

## Consequences

- A normal `aff4` consumer pulls **only** `zip-forensic-core`, not the third-party
  `zip` — smaller graph, one audited ZIP reader.
- The read path stays on the fleet's forensic reader (control over hostile-input
  handling, consistency), and a forensic reader carries no mutating ZIP writer.
- Building fixtures against `aff4`'s API downstream requires enabling `test-helpers`
  (which pulls `zip`), an explicit opt-in.
- If `zip-forensic-core` ever gains a writer, the fixtures should move to it and the
  third-party `zip` dependency dropped entirely — revisit this ADR then.
