#!/bin/sh
# Mechanical generation only: do not hand-edit the vendored JSON Schemas.
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: UCP_SCHEMA=/path/to/ucp-schema $0 /path/to/pinned-ucp-checkout" >&2
  exit 2
fi

ucp_source=$(cd "$1" && pwd)
output_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../schemas" && pwd)
resolver=${UCP_SCHEMA:-ucp-schema}
expected_revision=cd78fb38e819de77d9b527d110476eccb876f1bd
if [ "$(git -C "$ucp_source" rev-parse HEAD)" != "$expected_revision" ]; then
  echo "UCP checkout must be the exact v2026-08-25 source revision." >&2
  exit 1
fi
if [ -n "$(git -C "$ucp_source" status --porcelain --untracked-files=normal)" ]; then
  echo "UCP source checkout must be clean." >&2
  exit 1
fi
if [ "$("$resolver" --version)" != "ucp-schema 1.4.1" ]; then
  echo "The exact released ucp-schema 1.4.1 resolver is required." >&2
  exit 1
fi

cd "$ucp_source"
"$resolver" resolve source/schemas/shopping/checkout.json \
  --response --op read --bundle --pretty \
  --schema-local-base source/schemas --schema-remote-base https://ucp.dev/schemas \
  --output "$output_dir/checkout-response.json"
"$resolver" resolve source/schemas/shopping/checkout.json \
  --request --op complete --bundle --pretty \
  --schema-local-base source/schemas --schema-remote-base https://ucp.dev/schemas \
  --output "$output_dir/checkout-complete-request.json"

# Add a notice to each transformed source without changing validation keywords.
notice='Generated from UCP v2026-08-25 by ucp-schema 1.4.1: bundled references and resolved visibility annotations; added this non-normative notice. See provenance.json and LICENSE-UCP.'
for filename in checkout-response.json checkout-complete-request.json; do
  jq --arg notice "$notice" '. + {"$comment": $notice}' \
    "$output_dir/$filename" > "$output_dir/$filename.generated"
  mv "$output_dir/$filename.generated" "$output_dir/$filename"
done

# Retain the upstream Apache license alongside the transformed sources.
cp LICENSE "$output_dir/LICENSE-UCP"
echo "Generated schemas. Verify hashes against schemas/provenance.json."
