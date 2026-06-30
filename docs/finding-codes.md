# Finding Codes

`aff4-forensic` emits typed `Aff4Anomaly` values, converted to
`forensicnomicon::report::Finding` via `impl Observation`. The codes are a
**published contract** (scheme-prefixed SCREAMING-KEBAB) — once shipped, a code's
meaning never changes. All are in the **Integrity** category.

Findings are **observations**, not verdicts: a note states what the evidence is
consistent with, never a legal conclusion.

## `AFF4-HASH-MISMATCH`

**Severity:** High.

A stored ImageStream `aff4:hash` does not match the digest recomputed over the
decompressed ImageStream content. Carries the algorithm, the stored digest, and
the recomputed digest.

> Consistent with tampering **or** media corruption — the finding does not
> distinguish the two.

The digests cover the ImageStream content (`aff4:size` bytes), not the
map-expanded virtual disk; algorithms the build cannot compute are skipped, never
silently passed.

## `AFF4-HASH-UNREADABLE`

**Severity:** Medium.

A virtual region is marked `aff4:UnreadableData` — the acquisition could not read
those bytes. Carries the region's offset and length.

> Whole-disk integrity cannot be fully established over that region. This is an
> acquisition caveat, not evidence of tampering: an image with unreadable regions
> can still have an intact, reconciling ImageStream content hash.

---

[Home](index.md) · [Audit Validation](validation.md)
