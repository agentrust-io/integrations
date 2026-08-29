# EPI Recorder TRACE / WCM attestation source

`epi export trace` maps a sealed `.epi` file to a TRACE v0.2 **log-import** Trust Record. `tool_transcript.hash` is `sha256` of the `.epi` bytes. This is **Level 0** (software-only). It does **not** claim TEE attestation, Cedar evaluation, or a TRACE verifier appraisal (`appraisal.status` is `none`). WCM role is `attestation-source`: evidence for someone else's verifier; this integration does not verify a WCM manifest.

## Run it

Against the published PyPI release:

```bash
pip install "epi-recorder==4.4.1" agentrust-trace agentrust-trace-tests
epi record --out demo.epi -- python -c "print('ok')"
epi export trace demo.epi --out demo.trace.json
trace-tests verify --record demo.trace.json --level 0
```

Release artifacts used in the 4.4.1 ship: [v4.4.1](https://github.com/mohdibrahimaiml/epi-recorder/releases/tag/v4.4.1) (`build-v4.4.1.epi`, `build-v4.4.1.trace.json`).

## What is verified

A reviewer can:

1. `pip install epi-recorder==4.4.1` from PyPI (not an editable checkout).
2. Export TRACE JSON and run `trace-tests verify --level 0`. Expect **Level 0** only. L1/L2 fail `TR-RTE-001` (software-only) and `TR-RTE-004` (nonce) by design.
3. Confirm `tool_transcript.hash` equals `sha256:` of the `.epi` file.
4. Tamper the record signature → `InvalidSignature`.

Pre-release conformance digest (Level 0, `iter_errors=0`): `sha256:8c84baf799f0c0e59c2878d4a2a6f94941dd7f73e6965009a10c54e313a78112`.

Seal map (what a byte flip hits): [byte-level seal scope](https://github.com/mohdibrahimaiml/epi-recorder/blob/v4.4.1/docs/KNOWN_LIMITATIONS.md#byte-level-seal-scope-from-1kb-sweep-440-demo-banking-amlepi-405612-b).

## Verified tier request

Please evaluate this integration for the **Verified** tier. Reproduction is the four steps above against `epi-recorder==4.4.1` and `agentrust-trace-tests==0.5.1`.
