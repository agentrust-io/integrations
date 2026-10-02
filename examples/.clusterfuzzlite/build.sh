#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# The targets import the example modules straight from their directories, the
# way a reader runs them. cryptography is the only third-party dependency, and
# it comes from the same hashed lock the receipts CI job uses.

cd "$SRC/integrations/examples"
pip3 install --no-cache-dir --require-hashes -r requirements/receipts-tests.txt

# compile_python_fuzzer bundles each target with PyInstaller, which follows
# static imports only. The cryptography stack reaches email.mime lazily, so
# without this the bundled target dies at runtime with
# "ModuleNotFoundError: No module named 'email.mime'" and libFuzzer reports it
# as a crash in the target.
PYI_ARGS=(
  --collect-submodules=email
  --paths="$SRC/integrations/examples/embodied-action-receipts"
  --paths="$SRC/integrations/examples/agentic-commerce-accountability"
  --paths="$SRC/integrations/examples/industrial-embodied-ai"
)

for target in "$SRC"/integrations/examples/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done

# Seed each JSON target with the committed fixtures, so the fuzzer starts from
# documents that already get past parsing and, for receipts, past signature
# verification.
zip -j "$OUT/fuzz_receipts_seed_corpus.zip" embodied-action-receipts/fixtures/*.json
zip -j "$OUT/fuzz_purchase_seed_corpus.zip" agentic-commerce-accountability/fixtures/*.json
