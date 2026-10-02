# agentrust-io demos

Community updates and contributor highlights: [AgenTrust on LinkedIn](https://www.linkedin.com/company/agentrust-io/).

Runnable demos for [cMCP](https://github.com/agentrust-io/cmcp), [TRACE](https://github.com/agentrust-io/trace-spec), and [WCM](https://pypi.org/project/weight-custody-manifest/). Ten demos, ~12 minutes total.

Project support is recognized in [SPONSORS.md](SPONSORS.md). Sponsorship is
separate from demo authorship, fixture identities, and project governance.

---

Clone the combined repository and run commands from `integrations/demos`:

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/demos
```

## Prerequisites

```
pip install -r requirements.txt
```

The requirements install cMCP for demos 1 through 5, Weight Custody Manifest for demos 6 through 9, and the OpenAI client used by demo 10. All demos use `CMCP_DEV_MODE=1` (software-only TEE, no hardware required). The local MCP server performs real filesystem operations on `./workspace/`.

## Quick start: one command

```
python demo.py            # run all demos, pausing before each (good for live talks)
python demo.py --no-pause # run straight through
python demo.py 2          # run only demo 2
```

`demo.py` sets the token and dev mode for you and prints the detected `cmcp-runtime` version. If your active Python cannot find the `cmcp` command, it will use a local `.venv` if one exists (`python -m venv .venv` then install `cmcp-runtime` into it). To run the demos individually instead, use the per-demo commands below.

Set a bearer token (the cMCP Runtime requires one):

```bash
# bash
export CMCP_BEARER_TOKEN=demo-token
```

```powershell
# PowerShell
$env:CMCP_BEARER_TOKEN = "demo-token"
```

Each demo has a `run.py` (works on any OS) and a `run.sh` (bash only). Server and cMCP Runtime logs are written to `*.log` files in the demo directory, not the terminal.

---

## Browser console

A point-and-click version for showing on a screen instead of a terminal. It runs the real `financial-services` example (the shared EU corporate credit-risk scenario in `../examples/financial-services`) behind a small web UI.

```
pip install cmcp-runtime httpx
python web-console/run.py
```

Opens `http://localhost:8000`. Pick an obligor and run a six-step credit assessment: watch Cedar allow each step and block the write when the result breaches a control (CRR concentration, EBA delegated authority, IFRS 9, EU AML), each deny citing its regulation. Close the session into a signed TRACE record and verify it offline -- every result comes from the real gateway. See [`web-console/README.md`](web-console/README.md).

---

## Demo 1 -- cMCP in action (~90 seconds)

The agent calls three tools through the cMCP gateway. Cedar policy is enforced for every call. At session close, the gateway produces a signed TRACE claim carrying the policy bundle hash.

On real Intel TDX hardware, the policy bundle hash flows into RTMR[2] at startup. Here it appears in `trace.policy.bundle_hash` in the claim.

```
python demo-01-cmcp-in-action/run.py
```

What you see:
- cMCP starts, measures the policy bundle hash
- `write_file`: Cedar allows it, real file written to `workspace/hello.txt`
- `read_file`: Cedar allows it, reads the file back
- `list_dir`: **denied by Cedar policy** (HTTP 403, error_code: POLICY_DENY)
- TRACE claim shows `runtime.platform`, `runtime.measurement`, `policy.bundle_hash`
- Claim saved to `workspace/trace-claim.json` (needed by demos 2 and 3)

---

## Demo 2 -- Policy swap = attestation failure (~90 seconds)

The operator loads a different Cedar policy bundle (v1 vs v2). The claim's `policy.bundle_hash` changes. A verifier that pinned the v1 hash rejects v2 claims with `POLICY_HASH_MISMATCH`.

On real TDX hardware, the policy hash flows into RTMR[2] at startup -- the TEE measurement itself changes, not just a field in the claim.

**Requires demo 1 to have run first** (reads `workspace/trace-claim.json`).

```
python demo-02-policy-swap/run.py
```

What you see:
- v1 and v2 bundle hashes printed (visibly different SHA-256 values)
- `write_file` is DENIED under v2 policy (new Cedar forbid rule)
- `cmcp verify` on the v2 claim with the pinned v1 hash -> `policy_bundle.hash` FAILS (POLICY_HASH_MISMATCH)
- `cmcp verify` on the v2 claim with the v2 hash -> `policy_bundle.hash` PASSES (overall result stays `partially_verified` in software-only mode, because only `hardware_attestation` is left unchecked)

---

## Demo 3 -- Offline TRACE verification (~60 seconds)

The signed TRACE claim from demo-01 is verified with no gateway, no server, and no network call. Only `cmcp_verify` and the hashes embedded in the claim are used.

**Requires demo 1 to have run first**.

```
python demo-03-offline-trace/run.py
```

What you see:
- Claim fields printed: `runtime.platform`, `runtime.measurement`, `policy.bundle_hash`
- All cryptographic checks pass (schema, signature, policy hash, catalog hash, audit chain)
- `hardware_attestation` is in `unverified_fields`, so the status reads `partially_verified` (software-only mode -- on real TDX that field verifies too and the status becomes `verified`)
- No connection made to any server

---

## Demo 4 -- Context-aware enforcement (~90 seconds)

Demos 1-3 are the trust chain: enforce, tamper, verify. Demo 4 is a second axis. The same tool is allowed in one workflow and denied in another, so authorization tracks the declared call context, not the tool's identity and not the model's stated intent.

```
python demo-04-context-enforcement/run.py
```

What you see:
- `write_file` under `workflow_id="invoice-run"`: Cedar **allows** it (the `WriteFile` permit is guarded by `context.workflow_id == "invoice-run"`)
- the identical `write_file`, same arguments, under `workflow_id="chat-freeform"`: **denied by Cedar** (HTTP 403, POLICY_DENY) -- no permit matches, default-deny holds
- `read_file` under `workflow_id="chat-freeform"`: **allowed** (reads are permitted in any workflow, so the second workflow is not blocked wholesale; only the write capability is scoped)
- both the allow and the deny are committed to the signed audit chain under one `policy.bundle_hash`

---

## Demo 5 -- Attribute-based enforcement (~90 seconds)

Demo 1 denies by tool name, demo 4 by call context. Demo 5 denies by the tool's compliance attributes. A tool that is not BAA-covered is refused by a single guardrail rule, whatever it is named.

```
python demo-05-compliance-domain/run.py
```

What you see:
- `write_file` and `read_file` (`compliance_domain=clinical`, `baa_covered=true`): **allowed**
- `list_dir` (`compliance_domain=external-analytics`, `baa_covered=false`): **denied by Cedar** (HTTP 403, POLICY_DENY)
- the deny comes from `forbid ... when { context.baa_covered == false }`, which overrides the baseline permit; the call is refused on its attribute, not its name
- one rule covers every non-BAA-covered tool in the catalog, present and future

---

## Demo 6 -- Weight custody (~60 seconds)

Demos 1-5 govern what an agent *does*. Demo 6 is the layer beneath: the model *weights* themselves. A Weight Custody Manifest binds the exact weight hash, gates the decryption key behind attestation, and carries the fine-tune's lineage. It needs no hardware and no server, and depends only on the `weight-custody-manifest` package from PyPI.

```
python demo-06-weight-custody/run.py
```

What you see:
- a manifest jointly signed (builder + custodian) binds the checkpoint's exact `weights_hash`, and the signature verifies
- the attestation gate releases the key only for the certified serving stack (genuine nonce, approved platform, signed image measurement)
- a tampered checkpoint's hash does not match the manifest, so it is **refused before it ever loads**
- a fine-tune is a derivative whose lineage verifies back to the signed base (the derivative is the real IP)
- honest scope: this is accountability-grade against an operator who physically owns the silicon (see TEE.fail), not silicon-proof custody

---

## Demo 7 -- Closed-weight custody (~60 seconds)

The mirror of demo 6. There the base was an open-weight model, so the machinery did integrity, license, and derivative custody. Here the model is **closed** (a frontier lab shipping weights into a customer's or sovereign's own enclave), so the base weights *are* the secret and the job is to keep the decryption key off the operator.

```
python demo-07-closed-weight/run.py
```

What you see:
- a manifest with `base_confidentiality: confidential`, jointly signed by the lab and the customer
- the decryption key releases only into the attested, lab-signed serving stack
- an unapproved serving stack (one that could export plaintext weights) is refused the key
- the closed-vs-open contrast spelled out: same protocol, different job

---

## Demo 8 -- Derivative lineage (~60 seconds)

When a customer fine-tunes inside the enclave on private data, the result is novel IP that never existed publicly. WCM gives the derivative its own signed manifest with a `derived_from` pointer and a `rights_holder` split, so its chain of custody resolves back to the base.

```
python demo-08-derivative-lineage/run.py
```

What you see:
- a base manifest permitting `fine-tune-only`, and a derivative that permits `none`
- `verify_lineage` resolving the derivative back to the base (chain, depth, root)
- the derivative's `rights_holder` recording the base/derivative IP split
- monotone rights: a fork of the no-derivatives derivative is **rejected**, the base's terms travel down the chain

---

## Demo 9 -- Sovereign threshold (~90 seconds)

For a sovereign deployment the honest limit bites hardest: a hardware owner who forges one attestation could release a key. The answer is to never let one release be enough. The model key is split **2-of-3** across independent parties, each releasing its share only against its own attestation.

```
python demo-09-sovereign-threshold/run.py
```

What you see:
- the model key split 2-of-3 across the lab, the sovereign authority, and the customer
- a single share reconstructs nothing (one forged attestation is below threshold)
- two independent shareholders each attest and release their share
- the quorum reconstructs the key, so forging it requires forging attestation to a quorum of independent roots, not one

---

## Demo 10 -- Governed model calls (~90 seconds)

The other nine demos govern **tool** calls. This one governs **model** calls, a different
question: not whether an agent may use a tool, but whether this class of data may reach
that model, in that region, on that infrastructure. The caller changes one line,
`base_url`, and keeps its existing OpenAI client.

```
python demo-10-model-gateway/run.py
```

What you see:
- `public` data reaching an out-of-region model, allowed and recorded
- `pii` allowed out of region **only after** identifiers are stripped at the boundary
- `confidential` refused out of region: proof makes a call provable, not permissible
- `hipaa_phi` refused in region on **shared** infrastructure and allowed on **dedicated** -- same prompt, same class, so jurisdiction is necessary but not sufficient
- the session closing into a signed TRACE claim, verifiable offline

---

## Structure

```
demos/
+-- README.md
+-- requirements.txt
+-- server/
|   +-- server.py               # Plain HTTP JSON-RPC 2.0 server: write_file, read_file, list_dir
|   +-- requirements.txt
+-- workspace/                  # Files written by demos (created at runtime)
+-- demo-01-cmcp-in-action/
|   +-- cmcp-config.yaml
|   +-- catalog.json            # Approves write_file, read_file, list_dir
|   +-- policies/               # Cedar: permit write_file+read_file, forbid list_dir
|   +-- call.py                 # Demo agent: calls tools, closes session, saves claim
|   +-- run.py                  # Cross-platform launcher (use this)
|   +-- run.sh                  # bash-only launcher
+-- demo-02-policy-swap/
|   +-- catalog.json
|   +-- cmcp-config.yaml        # Points to policies-v1/
|   +-- cmcp-config-v2.yaml     # Points to policies-v2/
|   +-- policies-v1/            # Cedar: permit all
|   +-- policies-v2/            # Cedar: deny write_file (hash differs from v1)
|   +-- check_hash.py           # Computes and compares bundle hashes
|   +-- run.py                  # Cross-platform launcher (use this)
|   +-- run.sh                  # bash-only launcher
+-- demo-03-offline-trace/
|   +-- verify.py               # cmcp_verify.verify_trace_claim (no network)
|   +-- run.py                  # Cross-platform launcher (use this)
|   +-- run.sh                  # bash-only launcher
+-- demo-04-context-enforcement/
|   +-- cmcp-config.yaml
|   +-- catalog.json            # Approves write_file, read_file (compliance_domain: finance)
|   +-- policies/               # Cedar: WriteFile permitted only when context.workflow_id == "invoice-run"
|   +-- call.py                 # Same write in two workflows: one allowed, one denied
|   +-- run.py                  # Cross-platform launcher (use this)
|   +-- run.sh                  # bash-only launcher
+-- demo-05-compliance-domain/
|   +-- cmcp-config.yaml
|   +-- catalog.json            # Tags tools with compliance_domain + BAA status
|   +-- policies/               # Cedar: forbid any tool when context.baa_covered == false
|   +-- call.py                 # Two BAA-covered tools allowed, one non-covered tool denied
|   +-- run.py                  # Cross-platform launcher (use this)
|   +-- run.sh                  # bash-only launcher
+-- demo-06-weight-custody/
|   +-- run.py                  # WCM flow: sign, attestation gate, tamper refusal, lineage
+-- demo-07-closed-weight/
|   +-- run.py                  # Closed-weight secrecy: key releases only into the attested stack
+-- demo-08-derivative-lineage/
|   +-- run.py                  # The fine-tune is the IP: derived_from + rights split + lineage
+-- demo-09-sovereign-threshold/
    +-- run.py                  # 2-of-3 threshold split, each share released against attestation
```

---

## How it connects

```
Agent (call.py)
     |
     v  POST /mcp  Authorization: Bearer <token>
[cMCP runtime :8443]  <--  Cedar policy bundle (hash -> RTMR[2] on TDX)
     |
     v  POST http://localhost:9001/mcp  (JSON-RPC 2.0)
[server/server.py :9001]  -->  workspace/ (real file writes)
     |
POST /sessions/{id}/close
     |
     v
TRACE claim (Ed25519 signed)  -->  workspace/trace-claim.json
     |
     v
cmcp_verify.verify_trace_claim()  (no network, no operator trust)
```
