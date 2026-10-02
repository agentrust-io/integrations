#!/usr/bin/env bash
# Demo 4: context-aware enforcement
#
# Thin wrapper around run.py, which is the cross-platform launcher and the one
# CI exercises. This script used to start the servers itself with a fixed
# `sleep 2`, which raced cMCP startup and, worse, carried no check that the
# ports were free. Keeping the logic in one place means the shell path and the
# CI path cannot drift apart again.
#
# Usage: bash demo-04-context-enforcement/run.sh   (from repo root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python "$SCRIPT_DIR/run.py" "$@"
