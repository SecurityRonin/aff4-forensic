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
    /// The ImageStream's own `aff4:size` — the length of its decompressed content,
    /// which the ImageStream `aff4:hash` digests cover. Equals `virtual_size` for a
    /// direct (non-Map) image.
    pub image_stream_size: u64,
    pub chunk_size: u64,
    pub chunks_per_segment: u64,
    pub compression: Compression,
    /// Content digests declared on the ImageStream node (`aff4:hash`).
    pub image_hashes: Vec<crate::StoredHash>,
    /// Present when the image uses an `aff4:Map` as its top-level data stream.
    pub map_meta: Option<MapMeta>,
}

/// Parse `information.turtle` and return `StreamMeta`.
///
/// When an `aff4:Map` block is present, extracts the Map's virtual size and the
/// dependent `aff4:ImageStream`'s chunk geometry. Without a Map block, falls back
/// to the first `aff4:ImageStream` block (direct image).
/// Normalize a turtle document: collapse `\n\r\t` and `;` to spaces so each
/// predicate-object pair is whitespace-separated and RDF nodes are delimited by
/// `" . "`.
fn normalize_turtle(turtle: &str) -> String {
    turtle
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t' | ';') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

pub(crate) fn parse_turtle(turtle: &str) -> Result<StreamMeta, Aff4Error> {
    let normalized = normalize_turtle(turtle);

    let blocks: Vec<&str> = normalized.split(" . ").collect();

    // Encrypted volumes (aff4:EncryptedStream, AES-XTS, wrapped keybag): detect
    // and refuse loudly. Decryption is a later epic; emitting the ciphertext as
    // if it were plaintext would fabricate evidence.
    if let Some(block) = blocks.iter().find(|b| b.contains("aff4:EncryptedStream")) {
        let arn = extract_iri(block).unwrap_or_else(|| "<unknown stream>".into());
        return Err(Aff4Error::Encrypted(format!(
            "stream {arn} is an aff4:EncryptedStream (AES-XTS); provide-key decryption \
             is not yet implemented"
        )));
    }

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
    let image_stream_size = extract_pred_u64(block, "aff4:size")?;
    let image_hashes = parse_image_hashes(block);

    let (virtual_size, map_meta) = match map_override {
        Some((mm, vs)) => (vs, Some(mm)),
        None => (image_stream_size, None),
    };

    Ok(StreamMeta {
        stream_arn,
        virtual_size,
        image_stream_size,
        chunk_size,
        chunks_per_segment,
        compression,
        image_hashes,
        map_meta,
    })
}

/// Parse the `aff4:hash` content digests declared on an ImageStream block.
///
/// Values follow the predicate as a comma-separated list of `"<hex>"^^aff4:<ALGO>`
/// terms (e.g. `"d58…"^^aff4:MD5`). The sibling predicates `aff4:imageStreamHash`
/// / `aff4:imageStreamIndexHash` hash the *stored* bevy and index, not the
/// reconstructed content, and are intentionally excluded.
fn parse_image_hashes(block: &str) -> Vec<crate::StoredHash> {
    let tokens: Vec<&str> = block.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] != "aff4:hash" {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < tokens.len() {
            match tokens[j] {
                "," => j += 1,
                t => match parse_hash_term(t) {
                    Some(h) => {
                        out.push(h);
                        j += 1;
                    }
                    None => break,
                },
            }
        }
        i = j.max(i + 1);
    }
    out
}

/// Parse one `"<hex>"^^aff4:<ALGO>` hash term; `None` if it is not such a term.
fn parse_hash_term(token: &str) -> Option<crate::StoredHash> {
    let rest = token.strip_prefix('"')?;
    let (hex, dtype) = rest.split_once("\"^^aff4:")?;
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // A datatype token may carry a trailing `,` (more values follow) when the
    // serializer wrote no space before it — e.g. pyaff4's `…"^^aff4:MD5,`. Keep
    // only the alphanumeric datatype name.
    let algorithm = dtype
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_string();
    if algorithm.is_empty() {
        return None;
    }
    Some(crate::StoredHash {
        algorithm,
        hex: hex.to_ascii_lowercase(),
    })
}

/// Parsed metadata for one AFF4-Logical `aff4:FileImage` node.
pub(crate) struct LogicalFileMeta {
    /// The FileImage node IRI (its path tail names the ZIP segment).
    pub arn: String,
    /// `aff4:originalFileName`.
    pub original_file_name: String,
    /// `aff4:size` — content length in bytes.
    pub size: u64,
    /// Content digests declared on the node (`aff4:hash`).
    pub hashes: Vec<crate::StoredHash>,
    /// `aff4:lastWritten`, if present.
    pub last_written: Option<String>,
}

/// Parse all `aff4:FileImage` nodes from an AFF4-Logical `information.turtle`.
///
/// Returns one entry per logical file. Empty when the container declares no
/// FileImage nodes (e.g. a disk image).
pub(crate) fn parse_logical_files(turtle: &str) -> Result<Vec<LogicalFileMeta>, Aff4Error> {
    let normalized = normalize_turtle(turtle);
    let mut out = Vec::new();
    for block in normalized.split(" . ") {
        if !block.contains("aff4:FileImage") {
            continue;
        }
        let arn = extract_iri(block)
            .ok_or_else(|| Aff4Error::BadFormat("FileImage node has no IRI subject".into()))?;
        // `aff4:size` is authoritative when present, but some producers omit it
        // (the ZIP segment length is the real content size); default to 0 then.
        let size = extract_pred_u64(block, "aff4:size").unwrap_or(0);
        let original_file_name =
            extract_pred_quoted(block, "aff4:originalFileName").unwrap_or_else(|| arn.clone());
        let hashes = parse_image_hashes(block);
        let last_written = extract_pred_quoted(block, "aff4:lastWritten");
        out.push(LogicalFileMeta {
            arn,
            original_file_name,
            size,
            hashes,
            last_written,
        });
    }
    Ok(out)
}

/// Parsed metadata for an `aff4:EncryptedStream` and its password-wrapped keybag.
pub(crate) struct EncryptedMeta {
    /// The EncryptedStream IRI (its bevies hold the ciphertext chunks).
    pub stream_arn: String,
    /// Chunks per bevy segment — maps a per-segment chunk to its global index.
    pub chunks_per_segment: u64,
    /// Plaintext length of the decrypted stream (`aff4:size`).
    pub size: u64,
    /// PBKDF2 salt (decoded from `xsd:hexBinary`).
    pub salt: Vec<u8>,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Derived-key size in bytes (`aff4:keySizeInBytes`, 32 for AES-128-XTS).
    pub key_size: usize,
    /// RFC 3394-wrapped volume encryption key (decoded from `xsd:hexBinary`).
    pub wrapped_key: Vec<u8>,
}

/// Parse an `aff4:EncryptedStream` + its `aff4:PasswordWrappedKeyBag` from the
/// turtle. Errors if the container is not password-wrapped (e.g. a public-key
/// keybag) — decryption of those is unsupported.
pub(crate) fn parse_encrypted_meta(turtle: &str) -> Result<EncryptedMeta, Aff4Error> {
    let normalized = normalize_turtle(turtle);
    let blocks: Vec<&str> = normalized.split(" . ").collect();

    let stream_block = blocks
        .iter()
        .find(|b| b.contains("aff4:EncryptedStream"))
        .ok_or_else(|| Aff4Error::BadFormat("no aff4:EncryptedStream in metadata".into()))?;
    let stream_arn = extract_iri(stream_block)
        .ok_or_else(|| Aff4Error::BadFormat("EncryptedStream has no IRI".into()))?;
    let chunk_size = extract_pred_u64(stream_block, "aff4:chunkSize")?;
    let chunks_per_segment = extract_pred_u64(stream_block, "aff4:chunksInSegment")?;
    let size = extract_pred_u64(stream_block, "aff4:size")?;
    if chunk_size == 0 || chunks_per_segment == 0 {
        return Err(Aff4Error::BadFormat(
            "EncryptedStream chunk geometry must be > 0".into(),
        ));
    }
    let keybag_arn = extract_pred_iri(stream_block, "aff4:keyBag")
        .ok_or_else(|| Aff4Error::BadFormat("EncryptedStream has no aff4:keyBag".into()))?;

    let keybag_block = blocks
        .iter()
        .find(|b| b.contains(keybag_arn.as_str()) && b.contains("KeyBag"))
        .ok_or_else(|| Aff4Error::BadFormat(format!("keybag {keybag_arn} not found")))?;
    if !keybag_block.contains("PasswordWrappedKeyBag") {
        return Err(Aff4Error::Encrypted(
            "only password-wrapped keybags are supported (this container uses another keybag type)"
                .into(),
        ));
    }

    let iterations = u32::try_from(extract_pred_u64(keybag_block, "aff4:iterations")?)
        .map_err(|_| Aff4Error::BadFormat("aff4:iterations out of range".into()))?;
    let key_size = usize::try_from(extract_pred_u64(keybag_block, "aff4:keySizeInBytes")?)
        .map_err(|_| Aff4Error::BadFormat("aff4:keySizeInBytes out of range".into()))?;
    let salt = extract_pred_quoted(keybag_block, "aff4:salt")
        .and_then(|h| hex_decode(&h))
        .ok_or_else(|| Aff4Error::BadFormat("aff4:salt missing or not hex".into()))?;
    let wrapped_key = extract_pred_quoted(keybag_block, "aff4:wrappedKey")
        .and_then(|h| hex_decode(&h))
        .ok_or_else(|| Aff4Error::BadFormat("aff4:wrappedKey missing or not hex".into()))?;

    Ok(EncryptedMeta {
        stream_arn,
        chunks_per_segment,
        size,
        salt,
        iterations,
        key_size,
        wrapped_key,
    })
}

/// Decode an even-length ASCII hex string to bytes; `None` on odd length or a
/// non-hex digit.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Extract the first quoted string value following `predicate`, handling values
/// that contain spaces or unicode (e.g. a filename). Returns the bytes between
/// the first `"` after the predicate and its closing `"` (excluding any `^^`
/// datatype suffix).
fn extract_pred_quoted(block: &str, predicate: &str) -> Option<String> {
    let after_pred = &block[block.find(predicate)? + predicate.len()..];
    let open = after_pred.find('"')? + 1;
    let rest = &after_pred[open..];
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_image_stream_is_err() {
        let err = parse_turtle("<x> rdf:type aff4:Something .").unwrap_err();
        assert!(matches!(err, Aff4Error::BadFormat(m) if m.contains("ImageStream")));
    }

    #[test]
    fn map_without_dependent_stream_is_err() {
        let t = "<aff4://m> rdf:type aff4:Map ; aff4:size 1024 .";
        let err = parse_turtle(t).unwrap_err();
        assert!(matches!(err, Aff4Error::BadFormat(m) if m.contains("dependentStream")));
    }

    #[test]
    fn map_with_missing_dependent_image_stream_is_err() {
        let t = "<aff4://m> rdf:type aff4:Map ; aff4:size 1024 ; \
                 aff4:dependentStream <aff4://s> .";
        let err = parse_turtle(t).unwrap_err();
        assert!(matches!(err, Aff4Error::BadFormat(m) if m.contains("dependent ImageStream")));
    }

    #[test]
    fn map_iri_missing_is_err() {
        // A Map block with no `<...>` subject IRI.
        let err = parse_turtle("aff4:Map aff4:size 10 .").unwrap_err();
        assert!(matches!(err, Aff4Error::BadFormat(m) if m.contains("Map IRI")));
    }

    #[test]
    fn detect_compression_all_branches() {
        assert_eq!(detect_compression("x snappy"), Compression::Snappy);
        assert_eq!(detect_compression("x rfc1950"), Compression::Deflate);
        assert_eq!(
            detect_compression("x DeflateCompressor"),
            Compression::Deflate
        );
        assert_eq!(detect_compression("x github.com/lz4"), Compression::Lz4);
        assert_eq!(detect_compression("x NullCompressor"), Compression::Null);
    }

    #[test]
    fn extract_pred_u64_errors() {
        assert!(extract_pred_u64("aff4:size notanumber", "aff4:size").is_err());
        assert!(extract_pred_u64("no predicate here", "aff4:size").is_err());
        // A digit run that overflows u64 hits the parse error branch.
        assert!(extract_pred_u64("aff4:size 99999999999999999999999999", "aff4:size").is_err());
    }

    #[test]
    fn extract_iri_none_when_absent() {
        assert!(extract_iri("no angle brackets").is_none());
    }

    #[test]
    fn extract_pred_iri_none_when_value_not_iri() {
        // predicate present but the following token is not `<...>`.
        assert!(extract_pred_iri("aff4:dependentStream plain", "aff4:dependentStream").is_none());
    }

    #[test]
    fn parse_hash_term_rejects_non_hash() {
        assert!(parse_hash_term("notquoted").is_none());
        assert!(parse_hash_term("\"\"^^aff4:MD5").is_none()); // empty hex
        assert!(parse_hash_term("\"zz\"^^aff4:MD5").is_none()); // non-hex
        assert!(parse_hash_term("\"ab\"^^aff4:,").is_none()); // empty algorithm
    }

    #[test]
    fn parse_logical_files_empty_when_no_file_image() {
        assert!(parse_logical_files("<x> rdf:type aff4:ImageStream .")
            .unwrap()
            .is_empty());
    }

    // ── Encrypted-stream metadata ─────────────────────────────────────────────

    /// A complete, well-formed encrypted turtle with the keybag predicate `kb`
    /// injected — lets each test omit or corrupt one field.
    fn enc_turtle(stream_extra: &str, keybag_body: &str) -> String {
        format!(
            "<aff4://s> a aff4:EncryptedStream ; aff4:chunkSize 512 ; \
             aff4:chunksInSegment 2048 ; aff4:size 100 ; aff4:keyBag <aff4://kb> {stream_extra} . \
             <aff4://kb> a aff4:PasswordWrappedKeyBag ; {keybag_body} ."
        )
    }

    fn good_keybag() -> &'static str {
        "aff4:iterations 1000 ; aff4:keySizeInBytes 32 ; \
         aff4:salt \"00112233445566778899aabbccddeeff\" ; \
         aff4:wrappedKey \"00112233445566778899aabbccddeeff0011223344556677\""
    }

    #[test]
    fn parse_encrypted_meta_happy() {
        let m = parse_encrypted_meta(&enc_turtle("", good_keybag())).unwrap();
        assert_eq!(m.stream_arn, "aff4://s");
        assert_eq!(m.iterations, 1000);
        assert_eq!(m.key_size, 32);
        assert_eq!(m.salt.len(), 16);
    }

    #[test]
    fn parse_encrypted_meta_error_paths() {
        // No EncryptedStream at all.
        assert!(matches!(
            parse_encrypted_meta("<x> a aff4:ImageStream ."),
            Err(Aff4Error::BadFormat(_))
        ));
        // Non-password keybag → Encrypted (unsupported).
        let cert = "<aff4://s> a aff4:EncryptedStream ; aff4:chunkSize 512 ; \
                    aff4:chunksInSegment 1 ; aff4:size 1 ; aff4:keyBag <aff4://kb> . \
                    <aff4://kb> a aff4:CertEncryptedKeyBag .";
        assert!(matches!(
            parse_encrypted_meta(cert),
            Err(Aff4Error::Encrypted(_))
        ));
        // Missing keyBag predicate.
        let nokb = "<aff4://s> a aff4:EncryptedStream ; aff4:chunkSize 512 ; \
                    aff4:chunksInSegment 1 ; aff4:size 1 .";
        assert!(parse_encrypted_meta(nokb).is_err());
        // Zero chunk geometry.
        let zero = "<aff4://s> a aff4:EncryptedStream ; aff4:chunkSize 0 ; \
                    aff4:chunksInSegment 1 ; aff4:size 1 ; aff4:keyBag <aff4://kb> .";
        assert!(parse_encrypted_meta(zero).is_err());
        // Bad hex salt.
        let badsalt = enc_turtle(
            "",
            "aff4:iterations 1 ; aff4:keySizeInBytes 32 ; aff4:salt \"zz\" ; \
             aff4:wrappedKey \"0011\"",
        );
        assert!(parse_encrypted_meta(&badsalt).is_err());
        // Missing wrappedKey.
        let nowrap = enc_turtle(
            "",
            "aff4:iterations 1 ; aff4:keySizeInBytes 32 ; aff4:salt \"0011\"",
        );
        assert!(parse_encrypted_meta(&nowrap).is_err());
    }

    #[test]
    fn hex_decode_edges() {
        assert_eq!(hex_decode("00ff"), Some(vec![0x00, 0xff]));
        assert!(hex_decode("abc").is_none()); // odd length
        assert!(hex_decode("zz").is_none()); // non-hex
    }
}
