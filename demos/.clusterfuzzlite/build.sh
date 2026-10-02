#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# The targets import the demo servers straight from the source tree, so the only
# install is their runtime (starlette), from a hashed lock. Atheris ships with
# the base image.

cd "$SRC/integrations/demos"
pip3 install --no-cache-dir --require-hashes -r requirements/fuzz.txt

# compile_python_fuzzer bundles each target with PyInstaller, which follows
# static imports only and does not see the sys.path the targets set up at run
# time. --paths hands it the three directories the demo modules live in.
# --collect-submodules=email is the house default: several stacks reach
# email.mime lazily and a bundled target then dies with ModuleNotFoundError,
# which libFuzzer reports as a crash in the target.
PYI_ARGS=(
  --paths="$SRC/integrations/demos/web-console"
  --paths="$SRC/integrations/demos/server"
  --paths="$SRC/integrations/demos/demo-10-model-gateway"
  --collect-submodules=email
)

for target in "$SRC"/integrations/demos/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done
