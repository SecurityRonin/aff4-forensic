//! AFF4-Logical (AFF4-L): a container of logical files, not a disk image.
//!
//! An AFF4-L container stores each captured file as a named ZIP segment described
//! by an `aff4:FileImage` RDF node (path, size, content hashes, timestamps). This
//! is a different stream family from `aff4:ImageStream`/`aff4:Map`: there is no
//! virtual disk, no bevy/chunk/map machinery — the content is read straight from
//! the ZIP segment. Downstream this is a *collection* of files (like a zip/UAC),
//! not a disk, so it is exposed as its own reader.
//!
//! Reference: pyaff4 `test_images/AFF4-L/dream.aff4`.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use zip_core::ZipArchive;

use crate::meta::parse_logical_files;
use crate::{Aff4Error, ReadSeekSend, StoredHash};

/// One logical file in an AFF4-L container (an `aff4:FileImage` node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalEntry {
    /// ZIP segment entry name holding the file's content.
    pub(crate) segment: String,
    /// `aff4:originalFileName` — the captured file's path as recorded.
    pub original_file_name: String,
    /// `aff4:size` — the file's content length in bytes.
    pub size: u64,
    /// Content digests declared on the FileImage node (`aff4:hash`).
    pub hashes: Vec<StoredHash>,
    /// `aff4:lastWritten`, if present (ISO-8601 as written in the turtle).
    pub last_written: Option<String>,
}

/// A read-only AFF4-Logical container: a collection of logical files.
pub struct LogicalContainer {
    archive: ZipArchive<Box<dyn ReadSeekSend>>,
    files: Vec<LogicalEntry>,
}

impl std::fmt::Debug for LogicalContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogicalContainer")
            .field("files", &self.files.len())
            .finish()
    }
}

impl LogicalContainer {
    /// Open an AFF4-L container from a file path.
    ///
    /// # Errors
    /// [`Aff4Error`] if the file is not a valid AFF4-L container or its metadata
    /// cannot be parsed. Returns [`Aff4Error::BadFormat`] if the container holds
    /// no `aff4:FileImage` entries (e.g. it is a disk image — use
    /// [`crate::Aff4Reader`] for those).
    pub fn open(path: &Path) -> Result<Self, Aff4Error> {
        Self::open_reader(Box::new(File::open(path)?))
    }

    /// Open an AFF4-L container from any seekable byte source.
    ///
    /// # Errors
    /// See [`Self::open`].
    pub fn open_reader(backing: Box<dyn ReadSeekSend>) -> Result<Self, Aff4Error> {
        let mut archive = ZipArchive::new(backing)?;

        let turtle = {
            let mut entry = archive.by_name("information.turtle")?;
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            content
        };

        let parsed = parse_logical_files(&turtle)?;
        if parsed.is_empty() {
            return Err(Aff4Error::BadFormat(
                "no aff4:FileImage entries found — not an AFF4-Logical container".into(),
            ));
        }

        // Resolve each FileImage ARN to its ZIP segment. Real containers URL-encode
        // the IRI (aff4%3A%2F%2F…); the path tail after the volume is the segment.
        let names: Vec<String> = archive.file_names().map(String::from).collect();
        let mut files = Vec::with_capacity(parsed.len());
        for p in parsed {
            let segment = resolve_segment(&names, &p.arn).ok_or_else(|| {
                Aff4Error::BadFormat(format!("FileImage {} has no matching ZIP segment", p.arn))
            })?;
            files.push(LogicalEntry {
                segment,
                original_file_name: p.original_file_name,
                size: p.size,
                hashes: p.hashes,
                last_written: p.last_written,
            });
        }

        Ok(Self { archive, files })
    }

    /// The logical files in this container.
    pub fn files(&self) -> &[LogicalEntry] {
        &self.files
    }

    /// Read a logical file's content from its ZIP segment.
    ///
    /// The returned bytes are the file content the entry's `aff4:hash` digests
    /// cover; verify by recomputing and comparing against [`LogicalEntry::hashes`].
    ///
    /// # Errors
    /// [`Aff4Error`] if the segment cannot be read.
    pub fn read_file(&mut self, entry: &LogicalEntry) -> Result<Vec<u8>, Aff4Error> {
        let mut zip_entry = self.archive.by_name(&entry.segment)?;
        let mut data = Vec::new();
        zip_entry.read_to_end(&mut data)?;
        Ok(data)
    }
}

/// Resolve a FileImage ARN to its ZIP segment entry name.
///
/// The segment is the ARN's path tail (after the `aff4://<uuid>` authority). Real
/// containers store it either verbatim or URL-encoded; match against the actual
/// ZIP entry names so both forms resolve.
fn resolve_segment(names: &[String], arn: &str) -> Option<String> {
    // Path tail: strip the `aff4://<authority>` prefix, keep the leading-slash path.
    let after_scheme = arn.strip_prefix("aff4://").unwrap_or(arn);
    let tail = match after_scheme.find('/') {
        Some(i) => &after_scheme[i..],
        None => after_scheme,
    };
    let candidates = [
        tail.to_string(),
        tail.trim_start_matches('/').to_string(),
        urlencode_arn(arn),
    ];
    for c in &candidates {
        if names.iter().any(|n| n == c) {
            return Some(c.clone());
        }
    }
    // Fall back to a suffix match on the path tail (handles container-relative
    // prefixes), preferring the longest matching entry name.
    names
        .iter()
        .filter(|n| !n.ends_with('/') && n.ends_with(tail.trim_start_matches('/')))
        .max_by_key(|n| n.len())
        .cloned()
}

/// The fully URL-encoded ARN form some imagers use as the ZIP entry name.
fn urlencode_arn(arn: &str) -> String {
    let stripped = arn.strip_prefix("aff4://").unwrap_or(arn);
    format!("aff4%3A%2F%2F{stripped}")
}
