//! AFF4 Map stream: binary `/map` entry parsing and virtual-offset resolution.
//!
//! An `aff4:Map` redirects virtual disk addresses to target streams
//! (ImageStream, Zero, SymbolicStreamFF, …). The binary map file contains
//! fixed-width 28-byte entries; the `/idx` sidecar lists target stream URIs.
//!
//! Binary entry layout (little-endian, packed, no padding):
//!
//! ```text
//! offset  size  field
//!      0     8  map_offset    (u64) — virtual byte offset where mapping begins
//!      8     8  length        (u64) — number of virtual bytes covered
//!     16     8  target_offset (u64) — byte offset within the target stream
//!     24     4  target_id     (u32) — index into the /idx URI list
//! ```

const ENTRY_SIZE: usize = 28;

/// One entry in an AFF4 map file.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MapEntry {
    pub map_offset: u64,
    pub length: u64,
    pub target_offset: u64,
    pub target_id: u32,
}

/// The repeating ASCII tile of a multi-byte symbolic stream.
///
/// pyaff4 builds a tile of the seed repeated to exactly 1 MiB and reads
/// `tile[readptr % 1_MiB]`; because 1 MiB is not a multiple of the seed length,
/// the pattern resets (a "seam") at every 1 MiB boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tile {
    /// `aff4:UnknownData` — region present in the address space but not imaged.
    Unknown,
    /// `aff4:UnreadableData` — region that could not be read during acquisition.
    Unreadable,
}

impl Tile {
    /// The ASCII seed repeated across the 1 MiB tile.
    pub(crate) fn seed(self) -> &'static [u8] {
        match self {
            Tile::Unknown => b"UNKNOWN",
            Tile::Unreadable => b"UNREADABLEDATA",
        }
    }

    /// Byte produced at target-stream position `p`, honoring pyaff4's 1 MiB tile
    /// reset: `seed[(p % 1_MiB) % seed.len()]`.
    pub(crate) fn byte_at(self, p: u64) -> u8 {
        const TILE: u64 = 1024 * 1024;
        let seed = self.seed();
        seed[((p % TILE) % seed.len() as u64) as usize]
    }
}

/// What kind of data a map target produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetKind {
    /// A real `aff4:ImageStream` — read from the bevy chunks.
    ImageStream,
    /// A constant-byte symbolic stream: `aff4:Zero` (0x00),
    /// `aff4:SymbolicStreamFF` (0xFF), `aff4:SymbolicStream{XX}` (0xXX).
    Fill(u8),
    /// A repeating-tile symbolic stream (`UnknownData` / `UnreadableData`).
    Tile(Tile),
    /// Unrecognised or unmapped target — produce zeros (best effort).
    Unknown,
}

/// Loaded, resolved map ready for virtual-offset lookups.
pub(crate) struct LoadedMap {
    /// Entries sorted by `map_offset`, zero-length entries removed.
    pub entries: Vec<MapEntry>,
    /// Target kind for each `target_id` (index matches idx-file line order).
    pub targets: Vec<TargetKind>,
    /// What to return for virtual bytes not covered by any map entry.
    pub gap_default: TargetKind,
}

/// Parse the binary `/map` file into a sorted, filtered entry list.
pub(crate) fn parse_map_entries(data: &[u8]) -> Vec<MapEntry> {
    let n = data.len() / ENTRY_SIZE;
    let mut entries: Vec<MapEntry> = (0..n)
        .map(|i| {
            let off = i * ENTRY_SIZE;
            MapEntry {
                map_offset: u64::from_le_bytes(data[off..off + 8].try_into().expect("slice")),
                length: u64::from_le_bytes(data[off + 8..off + 16].try_into().expect("slice")),
                target_offset: u64::from_le_bytes(
                    data[off + 16..off + 24].try_into().expect("slice"),
                ),
                target_id: u32::from_le_bytes(data[off + 24..off + 28].try_into().expect("slice")),
            }
        })
        .filter(|e| e.length > 0)
        .collect();
    entries.sort_by_key(|e| e.map_offset);
    entries
}

/// Parse the `/idx` file (newline-separated target URIs) into `TargetKind` values.
pub(crate) fn parse_idx(data: &str, image_stream_arn: &str) -> Vec<TargetKind> {
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| classify_target(line.trim(), image_stream_arn))
        .collect()
}

/// Classify one `/idx` target URI into the kind of data it produces.
fn classify_target(s: &str, image_stream_arn: &str) -> TargetKind {
    if s == image_stream_arn {
        TargetKind::ImageStream
    } else if s.ends_with("#Zero") || s == "aff4:Zero" {
        TargetKind::Fill(0x00)
    } else if s.ends_with("#UnknownData") {
        TargetKind::Tile(Tile::Unknown)
    } else if s.ends_with("#UnreadableData") {
        TargetKind::Tile(Tile::Unreadable)
    } else if let Some(byte) = symbolic_stream_byte(s) {
        TargetKind::Fill(byte)
    } else {
        TargetKind::Unknown
    }
}

/// Extract the constant fill byte of a `SymbolicStream{XX}` target, where `XX`
/// is two hex digits. Handles the AFF4 Standard form
/// (`…#SymbolicStreamFF`) and the afflib-2012 form (`…/SymbolicStream#FF`).
fn symbolic_stream_byte(s: &str) -> Option<u8> {
    let after = s.split("SymbolicStream").nth(1)?;
    let hex = after.strip_prefix('#').unwrap_or(after);
    if hex.len() == 2 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        u8::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}

/// The resolved result of a virtual-offset lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedRegion {
    pub kind: TargetKind,
    /// Byte offset within the target stream to read from (only meaningful for `ImageStream`).
    pub target_offset: u64,
    /// How many bytes remain in this contiguous region before the next boundary.
    pub bytes_in_region: u64,
}

/// Resolve `virtual_pos` to its target, given the full `virtual_size` for bounds.
///
/// Uses binary search on `entries` (sorted by `map_offset`). If no entry covers
/// `virtual_pos`, returns `gap_default` with `bytes_in_region` up to the next entry
/// start (or `virtual_size`).
pub(crate) fn resolve(map: &LoadedMap, virtual_pos: u64, virtual_size: u64) -> ResolvedRegion {
    // Binary search: find the last entry whose map_offset <= virtual_pos.
    let idx = map.entries.partition_point(|e| e.map_offset <= virtual_pos);

    if idx > 0 {
        let e = &map.entries[idx - 1];
        if virtual_pos < e.map_offset + e.length {
            // Inside entry idx-1.
            let offset_in_entry = virtual_pos - e.map_offset;
            let kind = map
                .targets
                .get(e.target_id as usize)
                .copied()
                .unwrap_or(TargetKind::Unknown);
            return ResolvedRegion {
                kind,
                target_offset: e.target_offset + offset_in_entry,
                bytes_in_region: e.length - offset_in_entry,
            };
        }
    }

    // In a gap: bytes until the start of the next entry (or virtual_size).
    let gap_end = map
        .entries
        .get(idx)
        .map(|e| e.map_offset)
        .unwrap_or(virtual_size);
    let bytes_in_gap = gap_end.saturating_sub(virtual_pos).max(1);

    ResolvedRegion {
        kind: map.gap_default,
        target_offset: 0,
        bytes_in_region: bytes_in_gap,
    }
}
