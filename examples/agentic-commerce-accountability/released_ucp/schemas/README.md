# Pinned UCP schema artifacts

These are mechanically transformed copies of the Apache-2.0-licensed
[UCP v2026-08-25 source schemas](https://github.com/Universal-Commerce-Protocol/ucp/tree/v2026-08-25/source/schemas),
not a locally invented checkout schema. `LICENSE-UCP` retains the upstream
license. Each output includes a non-normative `$comment` identifying the
transformation. `provenance.json` records the immutable source/tool revisions,
commands, and SHA-256 hashes.
Local Git attributes preserve LF line endings for the hashed schema/license
artifacts and regeneration script, including on autocrlf-enabled checkouts.

- `checkout-response.json`: base checkout, response/read view.
- `checkout-complete-request.json`: base checkout, request/complete view.

The released [ucp-schema 1.4.1 resolver](https://github.com/Universal-Commerce-Protocol/ucp-schema/tree/v1.4.1)
bundles references and applies `ucp_request`/`ucp_response` annotations. Only
internal fragment references remain. Runtime validation never retrieves schemas
or profiles from the network. `$id` and advertised schema URLs identify the
upstream vocabulary; they are not runtime fetch instructions.

## Regeneration

From the `released_ucp` directory, with `git`, Rust/Cargo, `jq`, and an otherwise
clean checkout of the exact UCP source commit available:

```sh
cargo install ucp-schema --version 1.4.1 --locked
ucp_source=$(mktemp -d)
git clone --branch v2026-08-25 --depth 1 https://github.com/Universal-Commerce-Protocol/ucp.git "$ucp_source"
./scripts/regenerate_schemas.sh "$ucp_source"
uv run --frozen pytest tests/test_schema.py
```

The script rejects another source revision, a dirty checkout, or another
resolver version. It regenerates the artifacts, not their expected hashes;
unexpected changes fail the provenance test and require investigation. Ordinary
tests require neither Rust nor a schema download. Source dependency/toolchain
availability remains a build-environment dependency; this is not a claim of
bit-reproducible tool binaries.

## Scope and limitations

Validation applies both the resolved JSON Schema (including supported format
checks) and the released `ucp-sdk==0.5.0` models to the original object, without
returning a coerced replacement. Errors do not echo payload contents.

The example uses an unextended checkout and an empty payment-instrument list.
It does not implement payment processing, handler-specific schemas, capability
negotiation, or arbitrary extension composition. Open `additionalProperties`
behavior is preserved; this is not a strict replacement schema. Fields omitted
from the resolved request's named properties are not necessarily forbidden by
the open schema. The controller must independently enforce its supported
profile and authorize the exact request.

Schema/model acceptance does not establish signatures, merchant identity,
spending authority, price arithmetic, lifecycle transitions, payment settlement,
or every prose requirement of UCP. The example's local policy and receipt
checks are distinct from this layer.
