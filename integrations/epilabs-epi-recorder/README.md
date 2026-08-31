# EPI Recorder TRACE / WCM attestation source

`epi export trace` maps a sealed `.epi` file to a TRACE v0.2 **log-import** Trust Record. `tool_transcript.hash` is `sha256` of the `.epi` bytes. This is **Level 0** (software-only). It does **not** claim TEE attestation, Cedar evaluation, or a TRACE verifier appraisal (`appraisal.status` is `none`). WCM role is `attestation-source`: evidence for someone else's verifier; this integration does not verify a WCM manifest.

## Run it

Against the published PyPI release:

```bash
pip install "epi-recorder==4.4.3" agentrust-trace agentrust-trace-tests
epi record --out demo.epi -- python -c "print('ok')"
epi export trace demo.epi --out demo.trace.json
trace-tests verify --record demo.trace.json --level 0
```

Release artifacts: [v4.4.3](https://github.com/mohdibrahimaiml/epi-recorder/releases/tag/v4.4.3) (`build-v4.4.3.epi`, `build-v4.4.3.trace.json`).

## What is verified

A reviewer can:

1. `pip install epi-recorder==4.4.3` from PyPI (not an editable checkout).
2. Export TRACE JSON and run `trace-tests verify --level 0`. Expect **Level 0** only. L1/L2 fail `TR-RTE-001` (software-only) and `TR-RTE-004` (nonce) by design.
3. Confirm `tool_transcript.hash` equals `sha256:` of the `.epi` file.
4. Tamper the record signature → `InvalidSignature`.

Conformance digest (Level 0, `iter_errors=0`, `origin.producer=epi-recorder/4.4.3`): `sha256:d17f305b7f3e9950614df5ae6810b86b111c6a9aa23c37c71cac5dd503da591f`.

Seal completeness (truncation through 4.4.1; 4.4.3 seals full payloads): [historical step-content truncation](https://github.com/mohdibrahimaiml/epi-recorder/blob/v4.4.3/docs/KNOWN_LIMITATIONS.md#historical-step-content-truncation-through-441).

Byte-level seal map: [byte-level seal scope](https://github.com/mohdibrahimaiml/epi-recorder/blob/v4.4.3/docs/KNOWN_LIMITATIONS.md#byte-level-seal-scope-from-1kb-sweep-440-demo-banking-amlepi-405612-b).

## Verified tier request

Please evaluate this integration for the **Verified** tier. Reproduction is the four steps above against `epi-recorder==4.4.3` and `agentrust-trace-tests==0.5.1`.
