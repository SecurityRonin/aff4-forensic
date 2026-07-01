# 3. AFF4-Logical is a separate collection reader, not the disk pipeline

Status: accepted (2026-07-01)

## Context

AFF4 has two unrelated stream families. A disk image (`aff4:ImageStream` /
`aff4:Map`) is a flat virtual address space read via `Read + Seek`. An
AFF4-Logical (AFF4-L) container is a *collection of files* — each an
`aff4:FileImage` stored as a named ZIP segment with its own path, size, hashes,
and timestamps. Forcing both through one API would misrepresent one of them.

## Decision

- Disk images are exposed by `Aff4Reader` (`Read + Seek` over the virtual disk).
- Logical containers are exposed by a distinct `LogicalContainer` that enumerates
  `LogicalEntry` files and reads each file's bytes from its ZIP segment — a
  collection interface, not a seekable stream. Downstream this feeds a
  file-collection consumer, not the disk/partition pipeline.
- Decryption composes with this split: an `aff4:EncryptedStream` decrypts to an
  inner AFF4 volume, which `open_encrypted` opens via `LogicalContainer::open_reader`
  over an in-memory cursor — reuse, not a new code path.
- Metadata parsing tolerates real-world omissions: a `FileImage` may lack
  `aff4:size` (the ZIP segment length is authoritative), and entry names appear in
  three conventions (URL-encoded IRI, literal `aff4://…`, or bare path).

## Consequences

- Consumers pick the reader that matches the artifact; neither API pretends to be
  the other.
- New logical-container features (encryption, dedup, cross-segment references)
  extend `LogicalContainer` without touching the disk reader.
