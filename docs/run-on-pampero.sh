#!/usr/bin/env bash
set -euo pipefail

# Wrapper de compatibilidad. El runner oficial versionado vive en scripts/.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$REPO_ROOT/scripts/run-on-pampero.sh" "$@"
