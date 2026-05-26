#!/usr/bin/env bash
# AFF4 corpus — no download required.
#
# All five Evimetry 3.0 reference images are committed to tests/data/ and are
# used directly by `cargo test --test corpus` (which reads from tests/data/,
# not CORPUS_DIR). This script is kept as a no-op so the CI corpus job
# structure remains consistent with other container repos.
set -euo pipefail
