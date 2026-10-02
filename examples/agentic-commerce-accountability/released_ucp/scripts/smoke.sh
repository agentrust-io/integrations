#!/bin/sh
# Dependencies are installed during image build / explicit host uv sync.
# No dependency resolution or downloads occur in this verification command.
set -eu

cd -- "$(dirname -- "$0")/.."
smoke_scratch=$(mktemp -d)
trap 'rm -rf "$smoke_scratch"' EXIT HUP INT TERM
export COVERAGE_FILE="$smoke_scratch/.coverage"
export RUFF_CACHE_DIR="$smoke_scratch/ruff"
export UV_CACHE_DIR="$smoke_scratch/uv"
export PYTHONDONTWRITEBYTECODE=1

run() {
  uv run --frozen --offline --no-sync "$@"
}

run python -m ucp_commerce
run python -m coverage run --branch -m pytest -p no:cacheprovider
run python -m coverage report
run ruff check .
run ruff format --check .
run mypy --cache-dir "$smoke_scratch/mypy"
run bandit -q -r ucp_commerce
printf '%s\n' 'OFFLINE_SMOKE_PASSED'
