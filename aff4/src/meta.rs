//! Minimal AFF4 `information.turtle` metadata parser.
//!
//! Extracts enough RDF predicates from the ImageStream subject to construct
//! an `Aff4Reader`: virtual size, chunk geometry, and compression method.

use crate::Aff4Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Compression {
    Null,
    Deflate,
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
    todo!()
}

/// Extract the first IRI (`<...>`) from a string.
pub(crate) fn extract_iri(s: &str) -> Option<String> {
    let start = s.find('<')? + 1;
    let end = s[start..].find('>')? + start;
    Some(s[start..end].to_string())
}

/// Find `predicate` followed by a whitespace-separated token and parse it as `u64`.
pub(crate) fn extract_pred_u64(block: &str, predicate: &str) -> Result<u64, Aff4Error> {
    todo!()
}
