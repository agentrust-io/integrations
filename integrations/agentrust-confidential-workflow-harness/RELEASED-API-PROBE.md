# Experimental released-protocol interoperability and authenticated response

This deterministic acceptance milestone executes the published `cmcp-runtime==0.7.0`
`MCPGateway.intercept_tool_call` and `ca2a-runtime==0.4.0`
`emit_dag` / `trace_record_hash` APIs, plus
`PendingResponse` / `ResponseProducer` authenticated response verification.
Positive and refusal tests are paired. All dependencies are transitively pinned
by the SHA-256 hash-locked requirements file.

A local test-generated X25519 peer key is marked assurance `none`, rather than
hardware-verified. Signed TRACE DAG records use temporary Ed25519 keys and a
synthetic source. The actual dispatch count is zero. This is **not** a live
model, tool or network workflow.

Reproduce from the repository root with Python 3.12:

```sh
python -m pip install --require-hashes -r requirements/confidential-workflow-probe.txt
cd integrations/agentrust-confidential-workflow-harness
python -m unittest discover -s tests -v
```

The authenticated-response probe covers permitted execution, unauthorized tool,
MAC alteration, single-use replay, expiry, signed denial, request/response
context mismatch, and unobserved receipt remaining unknown. The valid twin is
executed independently for each adversarial case. It does **not** establish
independent issuer enrollment, externally operated peer receipt, a real execution
side effect, secure confinement or hardware-backed runtime measurement.

Issue #199 must remain open until actual mediated tool and peer network transport,
independent boundary observations, composed mutation testing, and independently
operated live evidence are produced and externally reproduced. Component
interoperability may not be substituted for these requirements.
