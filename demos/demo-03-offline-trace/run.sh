#!/usr/bin/env bash
# Demo 3: Offline TRACE verification
#
# Verifies the signed TRACE claim from demo-01 with no server connection.
# Only the claim file and the hashes embedded in it are used.
#
# Run demo-01 first:  bash demo-01-cmcp-in-action/run.sh
#
# Usage: bash demo-03-offline-trace/run.sh   (from repo root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -f "$REPO_ROOT/workspace/trace-claim.json" ]]; then
  echo "No claim found. Run demo-01 first:"
  echo "  bash demo-01-cmcp-in-action/run.sh"
  exit 1
fi

echo ""
echo "=== Demo 3: Offline TRACE verification ==="
echo ""
python "$SCRIPT_DIR/verify.py"
