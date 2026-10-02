# Demo 10 — Governed model calls

An OpenAI-compatible endpoint in front of cMCP. The caller changes one line —
`base_url` — and from then on every model call is checked against policy before it
leaves, identifiers are stripped at the boundary, and the session closes into a signed
TRACE claim anyone can verify offline.

The other demos govern **tool** calls. This one governs **model** calls, which is a
different surface with a different question: not "may this agent use that tool", but
"may this class of data reach that model, in that region, on that infrastructure".

```
caller's OpenAI client
        │  base_url = http://127.0.0.1:8500/v1      ← the only change
        ▼
  endpoint.py            OpenAI surface, redaction at the boundary
        │
        ▼
  cMCP gateway :8444     Cedar decides, audit chain records, TRACE claim signed
        │
        ▼
  model_server.py        the inference call
```

## Run it

```
python demo-10-model-gateway/run.py
```

Ports: model backend `:9010`, gateway `:8444`, endpoint `:8500`. `CMCP_DEV_MODE=1` is
set for you, so no hardware is required, and no API key or network is needed.

## What you see

Five calls, at four sensitivity classes from cMCP's own vocabulary, against models in
two regions and two tenancies:

| # | Model | Placement | Class | Outcome |
|---|---|---|---|---|
| 1 | `frontier-large` | out of region, shared | `public` | **allow** |
| 2 | `frontier-large` | out of region, shared | `pii`, prompt carries identifiers | **allow**, after `NATIONAL_ID` and `ACCOUNT_NO` are redacted |
| 3 | `frontier-large` | out of region, shared | `confidential` | **deny** — `data-residency` |
| 4 | `regional-small` | in region, **shared** | `hipaa_phi` | **deny** — `phi-isolation` |
| 5 | `regional-isolated` | in region, **dedicated** | `hipaa_phi` | **allow** |

Call 2 is the one that changes what is possible: a model the caller could not use with
that data becomes usable, because the identifiers never leave and the call is provable.

Calls 4 and 5 are the argument. Same prompt, same classification, both in region.
Refused on shared infrastructure, allowed on dedicated. **Proof makes an out-of-region
call provable, not permissible** — a residency rule still binds at `confidential`, and at
`hipaa_phi` the jurisdiction is necessary but not sufficient.

Then the session closes into a signed claim, and:

```
cmcp verify demo-10-model-gateway/trace-claim.json
```

verifies it with no network, no gateway and no trust in whoever ran it. For the tamper
case — edit the policy, watch the pinned hash stop matching — see
[demo 2](../demo-02-policy-swap/).

## What is real, and what stands in

**Real** — the cMCP gateway, Cedar evaluation and the deny with its advice payload, the
hash-chained audit log, the signed TRACE claim, offline verification, and the boundary
redaction: `endpoint.py` genuinely strips the identifier before the prompt is forwarded.
The OpenAI request and response shapes are the real thing, so a stock SDK works.

**Stands in** — the inference. `model_server.py` synthesises the completion so the demo
needs no key and no network. Set `MODEL_API_KEY` (and optionally `MODEL_BASE_URL`) and it
forwards to a real provider instead; nothing else in the path changes.

**Demonstrative rather than production** — three redaction expressions, not a DLP engine.

**Where the classification comes from** — `data_class` arrives as a request header,
standing in for a routing layer's own decision. That division matters: a caller must
never be able to declare its own data down a tier, so in a real deployment the header is
replaced by the router's verdict.

**One thing the claim does not surface yet** — the transcript's per-entry `data_class`
reports the catalogued sensitivity of the tool, not the class of the individual call. The
per-call class is what was enforced and it travels in the audit chain, but a single
catalogued tool serving several classes cannot express that in the transcript today. See
[cmcp#479](https://github.com/agentrust-io/cmcp/issues/479).

**Software-only** — `CMCP_DEV_MODE=1`, so `hardware_attestation` does not verify and the
claim reads `partially_verified`. On TDX or SEV-SNP that check passes too.
