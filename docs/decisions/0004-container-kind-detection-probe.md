# 4. A `container_kind()` detection probe, not opener try/catch

Status: accepted (2026-07-01, aff4 0.2.1)

## Context

An AFF4 file is a ZIP; its shape — disk image (`aff4:ImageStream`/`aff4:Map`),
AFF4-Logical (`aff4:FileImage`), or encrypted (`aff4:EncryptedStream`) — is declared
only inside `information.turtle`. Downstream consumers (issen's `CollectionProvider`,
4n6mount's mount dispatch) must decide *which* reader to use before opening one.
Without a probe they either reach into the turtle themselves (duplicating the RDF
parsing and coupling to internals) or try one opener, catch its error, and try the
next — using exceptions for control flow and conflating "wrong shape" with "corrupt".

## Decision

Expose a single lightweight classifier:

```rust
pub enum ContainerKind { Disk, Logical, Encrypted }
pub fn container_kind(path: &Path) -> Result<ContainerKind, Aff4Error>;
```

It reads `information.turtle` once and classifies in a fixed order — logical
(`aff4:FileImage` present) → disk (`parse_turtle` resolves an ImageStream/Map) →
encrypted (`parse_turtle` returns `Aff4Error::Encrypted`) — and otherwise surfaces the
underlying `BadFormat`. It does **not** open a full reader or read bevy/segment data.

## Consequences

- Consumers dispatch on a value, not on caught errors; a genuinely malformed
  container still errors distinctly from a well-formed one of a known shape.
- The RDF/turtle knowledge stays in the `aff4` crate; consumers depend on the
  `ContainerKind` contract, not on `information.turtle` layout.
- Detection is cheap (one ZIP entry read + turtle parse), so it is safe to call as a
  format probe over many candidate files.
- The classification order is load-bearing: a container is Logical if it has any
  `FileImage`, else Disk/Encrypted per the top-level stream — documented so a future
  hybrid shape gets a deliberate rule, not an accidental one.
