#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# The two first-party packages are installed rather than added to the path, so
# the targets exercise the same import surface a consumer gets from PyPI.

cd "$SRC/integrations"
pip3 install --no-cache-dir ./packages/agentrust-capture-core ./packages/agentrust-trace-adapters

# compile_python_fuzzer bundles each target with PyInstaller, which follows
# static imports only. The cryptography stack reaches email.mime lazily, so
# without this a bundled target dies at runtime with
# "ModuleNotFoundError: No module named 'email.mime'" and libFuzzer reports it
# as a crash in the target.
PYI_ARGS=(--collect-submodules=email)

for target in "$SRC"/integrations/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done
