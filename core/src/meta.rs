//! Minimal AFF4 `information.turtle` metadata parser.
//!
//! Extracts enough RDF predicates to construct an `Aff4Reader`:
//! - Direct `aff4:ImageStream`: virtual size, chunk geometry, compression.
//! - `aff4:Map`-backed image: Map ARN, virtual size, gap default, plus the
//!   inner ImageStream's chunk geometry.

use crate::Aff4Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Compression {
    Null,
    Deflate,
    Snappy,
    Lz4,
}

/// Metadata for an optional Map stream wrapping the ImageStream.
#[derive(Debug)]
pub(crate) struct MapMeta {
    /// ARN of the `aff4:Map` resource (used to find `/map` and `/idx` in the ZIP).
    pub map_arn: String,
    /// ARN of the dependent `aff4:ImageStream`.
    pub image_stream_arn: String,
    /// Whether the gap default is SymbolicStreamFF (0xFF) instead of Zero.
    pub gap_is_symbolic_ff: bool,
}

#[derive(Debug)]
pub(crate) struct StreamMeta {
    /// ARN of the `aff4:ImageStream` (used to locate bevies in the ZIP).
    pub stream_arn: String,
    /// Virtual disk size: Map's `aff4:size` when Map is present; otherwise ImageStream's.
    pub virtual_size: u64,
    pub chunk_size: u64,
    pub chunks_per_segment: u64,
    pub compression: Compression,
    /// Present when the image uses an `aff4:Map` as its top-level data stream.
    pub map_meta: Option<MapMeta>,
}

/// Parse `information.turtle` and return `StreamMeta`.
///
/// When an `aff4:Map` block is present, extracts the Map's virtual size and the
/// dependent `aff4:ImageStream`'s chunk geometry. Without a Map block, falls back
/// to the first `aff4:ImageStream` block (direct image).
pub(crate) fn parse_turtle(turtle: &str) -> Result<StreamMeta, Aff4Error> {
    // Normalize: collapse whitespace variants and `;` so every predicate-object
    // pair is whitespace-separated with blocks delimited by " . ".
    let normalized: String = turtle
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t' | ';') {
                ' '
            } else {
                c
            }
        })
        .collect();

    let blocks: Vec<&str> = normalized.split(" . ").collect();

    // Try to find an aff4:Map block first.
    if let Some(map_block) = blocks.iter().find(|b| b.contains("aff4:Map")) {
        return parse_map_turtle(&blocks, map_block);
    }

    // No Map — parse as a direct ImageStream.
    let image_block = blocks
        .iter()
        .find(|b| b.contains("ImageStream"))
        .ok_or_else(|| Aff4Error::BadFormat("no aff4:ImageStream found in metadata".into()))?;

    parse_image_stream_block(image_block, None)
}

/// Parse metadata when a Map block is present.
fn parse_map_turtle(blocks: &[&str], map_block: &str) -> Result<StreamMeta, Aff4Error> {
    let map_arn = extract_iri(map_block)
        .ok_or_else(|| Aff4Error::BadFormat("Map IRI not found in aff4:Map block".into()))?;

    let virtual_size = extract_pred_u64(map_block, "aff4:size")?;

    let dep_arn = extract_pred_iri(map_block, "aff4:dependentStream").ok_or_else(|| {
        Aff4Error::BadFormat("aff4:dependentStream not found in Map block".into())
    })?;

    let gap_is_symbolic_ff = map_block.contains("SymbolicStreamFF");

    // Find the ImageStream block matching the dependentStream ARN.
    let image_block = blocks
        .iter()
        .find(|b| b.contains("ImageStream") && b.contains(dep_arn.as_str()))
        .ok_or_else(|| {
            Aff4Error::BadFormat(format!(
                "dependent ImageStream {dep_arn} not found in turtle"
            ))
        })?;

    let map_meta = MapMeta {
        map_arn,
        image_stream_arn: dep_arn,
        gap_is_symbolic_ff,
    };

    parse_image_stream_block(image_block, Some((map_meta, virtual_size)))
}

/// Extract chunk geometry from an ImageStream block and assemble `StreamMeta`.
///
/// `map_override`: when `Some((MapMeta, virtual_size))` the given values replace
/// the ImageStream's own `aff4:size` and attach `map_meta`.
fn parse_image_stream_block(
    block: &str,
    map_override: Option<(MapMeta, u64)>,
) -> Result<StreamMeta, Aff4Error> {
    let stream_arn = extract_iri(block)
        .ok_or_else(|| Aff4Error::BadFormat("stream IRI not found in ImageStream block".into()))?;

    let chunk_size = extract_pred_u64(block, "aff4:chunkSize")?;
    let chunks_per_segment = extract_pred_u64(block, "aff4:chunksInSegment")?;

    if chunk_size == 0 {
        return Err(Aff4Error::BadFormat("aff4:chunkSize must be > 0".into()));
    }
    if chunks_per_segment == 0 {
        return Err(Aff4Error::BadFormat(
            "aff4:chunksInSegment must be > 0".into(),
        ));
    }

    let compression = detect_compression(block);

    let (virtual_size, map_meta) = match map_override {
        Some((mm, vs)) => (vs, Some(mm)),
        None => (extract_pred_u64(block, "aff4:size")?, None),
    };

    Ok(StreamMeta {
        stream_arn,
        virtual_size,
        chunk_size,
        chunks_per_segment,
        compression,
        map_meta,
    })
}

fn detect_compression(block: &str) -> Compression {
    if block.contains("snappy") || block.contains("google.com/p/snappy") {
        Compression::Snappy
    } else if block.contains("rfc1950") || block.contains("DeflateCompressor") {
        Compression::Deflate
    } else if block.contains("lz4") || block.contains("github.com/lz4") {
        Compression::Lz4
    } else {
        Compression::Null
    }
}

/// Extract the first IRI (`<...>`) from a string.
pub(crate) fn extract_iri(s: &str) -> Option<String> {
    let start = s.find('<')? + 1;
    let end = s[start..].find('>')? + start;
    Some(s[start..end].to_string())
}

/// Find `predicate` and extract the IRI (`<...>`) that immediately follows it.
fn extract_pred_iri(block: &str, predicate: &str) -> Option<String> {
    let tokens: Vec<&str> = block.split_whitespace().collect();
    for window in tokens.windows(2) {
        if window[0] == predicate {
            let v = window[1];
            if v.starts_with('<') && v.ends_with('>') {
                return Some(v[1..v.len() - 1].to_string());
            }
        }
    }
    None
}

/// Find `predicate` among whitespace-delimited tokens and parse the next token as `u64`.
pub(crate) fn extract_pred_u64(block: &str, predicate: &str) -> Result<u64, Aff4Error> {
    let tokens: Vec<&str> = block.split_whitespace().collect();
    for window in tokens.windows(2) {
        if window[0] == predicate {
            // Value may be plain `512` or quoted `"512"^^xsd:integer`
            let val = window[1]
                .trim_start_matches('"')
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    Aff4Error::BadFormat(format!("no integer value after {predicate}"))
                })?;
            return val.parse().map_err(|_| {
                Aff4Error::BadFormat(format!("bad integer after {predicate}: {val}"))
            });
        }
    }
    Err(Aff4Error::BadFormat(format!(
        "{predicate} not found in block"
    )))
}
