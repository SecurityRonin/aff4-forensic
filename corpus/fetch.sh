#!/usr/bin/env bash
# Fetch AFF4 reference images produced by Evimetry 3.0 (the AFF4 Standard v1.0
# reference implementation). Source: https://github.com/aff4/ReferenceImages
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"
BASE="https://github.com/aff4/ReferenceImages/raw/master"

curl -fLo "${DEST}/Base-Linear.aff4"        "${BASE}/Base-Linear.aff4"
curl -fLo "${DEST}/Base-Allocated.aff4"     "${BASE}/Base-Allocated.aff4"
curl -fLo "${DEST}/Base-ExabyteSparse.aff4" "${BASE}/Base-ExabyteSparse.aff4"
