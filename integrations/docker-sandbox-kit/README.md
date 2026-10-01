# Docker Sandbox Kit to TRACE

A [Docker Sandbox Kit](https://github.com/docker/sandbox-kit-spec) is one OCI
image whose manifest annotation `vnd.docker.sandbox.kit.descriptor` lists what
the agent inside it asks to reach: network allow and deny rules by phase,
credentials, volumes, ports. This adapter takes a published Kit's platform
manifest and builds a TRACE Level 0 Trust Record whose `policy.bundle_hash` is
the digest of that descriptor, byte for byte as the frontend published it.

Written against [SPEC-v3](https://github.com/docker/sandbox-kit-spec/blob/main/docs/spec/SPEC-v3.md)
at commit `31791ea` (2026-10-01).

## Run it

Fetch the platform manifest exactly as the registry serves it. The digest is
over these bytes, so a pretty-printed copy will not match. For a public Docker
Hub Kit:

```bash
REPO=docker/sbx-kit-claude-acp-set
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPO:pull" | jq -r .token)
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  "https://registry-1.docker.io/v2/$REPO/manifests/sha256:86d56a3b2ea714d55c2a48b55b9ca64e2145245f43583100dd944eccfb8fe78e" > kit.json
```

The platform digest comes from the Kit's image index, one entry per platform.

Then build the unsigned record:

```bash
pip install -r integrations/docker-sandbox-kit/requirements.txt
python integrations/docker-sandbox-kit/kit_to_trace.py kit.json \
  --expected-digest sha256:86d56a3b2ea714d55c2a48b55b9ca64e2145245f43583100dd944eccfb8fe78e \
  --kit-reference docker.io/docker/sbx-kit-claude-acp-set \
  --subject spiffe://example.org/agent/claude-acp \
  --model-provider anthropic --model-id claude-sonnet-4-6 \
  --workload-digest sha256:<digest of the assembled image that ran> \
  --jwk pubkey.jwk > record.json
```

Pass the result to `agentrust_trace.sign_record`. Signing is kept separate from
assembly.

## What the record claims

| TRACE field | Value |
|---|---|
| `policy.bundle_hash` | SHA-256 of the published descriptor annotation |
| `policy.enforcement_mode` | `declared`, always |
| `policy.policy_uri` | `oci://<repository>@<Kit manifest digest>`, when `--kit-reference` is given |
| `origin.kind` | `third-party-control-plane` |
| `origin.producer` | The frontend named in `vnd.docker.sandbox.kit.built-by`, else `docker/sandbox-kit` |
| `origin.source_event_id` | The Kit manifest digest |
| `build_provenance.digest` | The digest the caller supplies for the image that ran |
| `runtime.platform` | `software-only` |
| `appraisal` | `none`, stated by this adapter |

**Why `declared`.** The descriptor is a request. What a host granted is the
permission surface of the effective descriptor, with this installation's
create-phase args expanded, and it lives in the runtime's lock (SPEC-v3
sections 7.4 and 10). The image carries neither, so a record built from it can
name the policy the Kit asked for and claim nothing about enforcement. The
adapter takes no mode argument. A record claiming `enforce` needs evidence from
the runtime that it applied this descriptor.

**Why the Kit digest is not the workload digest.** SPEC-v3 section 10: "What
runs is never a published artifact." The assembler emits an ordinary image
identified by the lock, and that is the digest `build_provenance.digest`
needs. The Kit digest identifies where the policy came from.

## Failure behavior

The adapter builds no record when the input is an image index, an artifact
manifest, an image without the descriptor annotation, a v2 Kit, a `set`, a
descriptor that is not JSON, a schema version other than 3 or one that
disagrees with its annotation, or a `vnd.docker.sandbox.kit.capabilities`
index that does not mirror the descriptor's capability types. With
`--expected-digest`, it also refuses bytes that hash to anything else. The CLI
exits 2 and says which check failed.

## Tests and conformance

The fixtures are the registry bytes of `docker/sbx-kit-claude-acp-set` 1.0.1
and `docker/doodle` 2026 (linux/amd64), with the index for the refusal case.

```bash
pip install -r integrations/docker-sandbox-kit/requirements.txt
python -m pytest integrations/docker-sandbox-kit -q
```

The suite builds, schema-checks, signs and verifies a record from both Kits
with the released packages pinned in `requirements.txt`, and checks every
refusal above. A signed record from either Kit passes
`trace-tests verify --level 0`.
