//! Minimal AFF4 `information.turtle` metadata parser.
//!
//! Extracts enough RDF predicates from the ImageStream subject to construct
//! an `Aff4Reader`: virtual size, chunk geometry, and compression method.

use crate::Aff4Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Compression {
    Null,
    Deflate,
    Snappy,
}

#[derive(Debug)]
pub(crate) struct StreamMeta {
    pub stream_arn: String,
    pub virtual_size: u64,
    pub chunk_size: u64,
    pub chunks_per_segment: u64,
    pub compression: Compression,
}

/// Parse `information.turtle` and return metadata for the first `aff4:ImageStream` found.
pub(crate) fn parse_turtle(turtle: &str) -> Result<StreamMeta, Aff4Error> {
    // Normalize: collapse all whitespace variants and `;` to plain spaces so
    // every predicate-object pair is whitespace-separated.
    let normalized: String = turtle
        .chars()
        .map(|c| if matches!(c, '\n' | '\r' | '\t' | ';') { ' ' } else { c })
        .collect();

    // Split into subject blocks (delimited by ' . ')
    let image_block = normalized
        .split(" . ")
        .find(|block| block.contains("ImageStream"))
        .ok_or_else(|| Aff4Error::BadFormat("no aff4:ImageStream found in metadata".into()))?;

    let stream_arn = extract_iri(image_block)
        .ok_or_else(|| Aff4Error::BadFormat("stream IRI not found in ImageStream block".into()))?;

    let virtual_size = extract_pred_u64(image_block, "aff4:size")?;
    let chunk_size = extract_pred_u64(image_block, "aff4:chunkSize")?;
    let chunks_per_segment = extract_pred_u64(image_block, "aff4:chunksInSegment")?;

    // Validate geometry before values feed division arithmetic in the reader.
    if chunk_size == 0 {
        return Err(Aff4Error::BadFormat("aff4:chunkSize must be > 0".into()));
    }
    if chunks_per_segment == 0 {
        return Err(Aff4Error::BadFormat("aff4:chunksInSegment must be > 0".into()));
    }

    // Detect compression from the compressionMethod URI.
    // Real images use the full URI; some tools use the short name.
    let compression = if image_block.contains("snappy") || image_block.contains("google.com/p/snappy") {
        Compression::Snappy
    } else if image_block.contains("rfc1950") || image_block.contains("DeflateCompressor") {
        Compression::Deflate
    } else {
        Compression::Null
    };

    Ok(StreamMeta {
        stream_arn,
        virtual_size,
        chunk_size,
        chunks_per_segment,
        compression,
    })
}

/// Extract the first IRI (`<...>`) from a string.
pub(crate) fn extract_iri(s: &str) -> Option<String> {
    let start = s.find('<')? + 1;
    let end = s[start..].find('>')? + start;
    Some(s[start..end].to_string())
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
    Err(Aff4Error::BadFormat(format!("{predicate} not found in ImageStream block")))
}
