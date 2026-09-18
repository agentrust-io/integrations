# Bernstein MCP verifier for TRACE

[mcp.bernstein.run](https://mcp.bernstein.run) is a stateless HTTP service that
verifies evidence. Two of its MCP tools take TRACE v0.2 Trust Records:
`verify_trace_record` runs the conformance checks on one record and
`verify_delegation_chain` walks a set of records from the leaf to the root.
Nothing is stored, nothing is fetched, no account is needed. The verdict names
the record by its RFC 8785 digest (`record_sha256`), so anyone can recompute
which bytes were judged.

[Bernstein](https://github.com/sipyourdrink-ltd/bernstein) itself is a
record producer: every run mints a software-only (Level 0) Trust Record from
its hash-chained journal. Its mapping onto TRACE is documented in the
trace-spec vendor annex proposed in
[agentrust-io/trace-spec#371](https://github.com/agentrust-io/trace-spec/pull/371).

## What it does not claim

- No hardware attestation. Bernstein records are `software-only`; the verifier
  accepts any `runtime.platform` the schema allows but appraises no TEE evidence.
- No freshness window. A committed record with a fixed `iat` verifies the same
  way in a year. Age is a policy of the relying party, not of this tool.
- No key trust beyond the record. `verify_trace_record` checks the signature
  with the key the record carries in `cnf.jwk`; whether that key is trusted is
  answered only by `verify_delegation_chain` with `trusted_root_keys`.
- No policy resolution, no transparency anchoring. `policy.policy_uri` and
  `transparency` are checked for shape, never fetched.
- Not a substitute for `trace-tests`. It applies the same profile rules to a
  record but does not grade conformance levels.

## Run it

Any MCP client over Streamable HTTP:

```bash
claude mcp add --transport http bernstein https://mcp.bernstein.run/mcp
```

Or plain JSON-RPC. Verify a record from the trace-spec corpus:

```bash
curl -sL https://raw.githubusercontent.com/agentrust-io/trace-spec/main/examples/canonicalization-boundary/01-non-ascii-values.json \
  | python3 -c 'import json,sys; v=json.load(sys.stdin); print(json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify_trace_record","arguments":{"record":v["record"]}}}))' \
  | curl -s -X POST https://mcp.bernstein.run/mcp \
      -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
      --data-binary @- \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]["structuredContent"]; print(r["verdict"], r["failing_check"], r["record_sha256"])'
```

Expected output:

```
valid None sha256:9e161ec7869d8039e4556917d4613bdb51350b88f163228772e9bdf8a51c2c54
```

The same pipeline on `05-ascii-escaped-signature.json` from the same directory
prints `invalid signature sha256:acd8dbd2c555476ae9326d2fddc4ebed51b106c8d827bc605dd7e4d11d56d192`:
the corpus expects `signature_invalid` for that vector and the verifier stops
at the `signature` check.

## What is verified

`verify_trace_record` runs these checks in this order and reports each as
`ok`, `fail`, `unverifiable` or `skipped`. The verdict is `valid` only when no
check failed and none was unverifiable.

| Check | What it reads |
|---|---|
| `parse` | JSON text or object; duplicate keys and non-finite numbers refuse |
| `schema` | `schema/trace-claim.json` vendored from trace-spec `0ec0453`, evaluated offline |
| `profile` | `eat_profile` sentinel for v0.2 |
| `subject` | absolute workload URI |
| `runtime` | `software-only` records carry the conventional all-zero measurement |
| `policy` | digest format, `enforcement_mode`, `policy_uri` shape |
| `cnf_key` | public-only key, supported `kty`/`crv`, private members refuse |
| `signature` | EdDSA, ES256 or ES384 over the RFC 8785 canonical record, key from `cnf.jwk` |
| `appraisal` | status enumeration, absolute verifier URI, optional members well-formed |
| `delegation` | `parent_record_hash` and `credential_id` shape when the member is present |
| `references` | each reference carries a digest of the declared format |
| `canonicalization` | flags keys outside the Basic Multilingual Plane, where code-point and UTF-16 orders diverge |

`verify_delegation_chain` takes the records plus a `context`: `trusted_root_keys`,
`credentials` keyed by `credential_id` with `issuer`, `holder`, `not_before`,
`not_after`, and optionally `max_depth`, `supported_digest_algorithms`,
`data_class_lattice`. It classifies the chain as `verified`,
`provenance-invalid`, `authorization-invalid` or `unverifiable` and names the
first broken link. Without a context every chain is `provenance-invalid`
(`credential_unknown`, `root_key_untrusted`), which is the correct answer for a
verifier that has been told to trust nothing.

## Records Bernstein emits

Seven signed records minted by the producer at
[`tests/fixtures/trust-record-vectors/`](https://github.com/sipyourdrink-ltd/bernstein/tree/4281e3c1ac86adbfae704dc4d1e69d4bb2a61559/tests/fixtures/trust-record-vectors)
(commit `4281e3c1`): single execution, a parent, child and grandchild delegation
chain, an aggregate, and a supplementary-plane pair. Regeneration is
byte-identical and a test holds it to the committed files.

Against the released conformance suite:

```bash
pip install "agentrust-trace-tests==0.5.1" "agentrust-trace==0.10.0"
curl -sLO https://raw.githubusercontent.com/sipyourdrink-ltd/bernstein/4281e3c1ac86adbfae704dc4d1e69d4bb2a61559/tests/fixtures/trust-record-vectors/single-execution-trust-record.json
trace-tests verify --record single-execution-trust-record.json --level 0 --max-age 400000000
```

Result: `PASS (8 checks, 0 skipped)`. The `--max-age` is needed because a
committed record carries a fixed `iat`; without it the only failure is
`TR-ENV-002` (stale record). `delegated-parent` and `aggregate` give the same
result.

## Verified tier: reproduction steps

1. Run the `curl` pipeline above on `01-non-ascii-values.json` and on
   `05-ascii-escaped-signature.json`; compare the verdicts and digests to the
   values printed here.
2. Run the same pipeline on
   `https://raw.githubusercontent.com/sipyourdrink-ltd/bernstein/4281e3c1ac86adbfae704dc4d1e69d4bb2a61559/tests/fixtures/trust-record-vectors/single-execution-trust-record.json`
   (the file is the record itself, so pass it as `record` directly). Expected:
   `valid None sha256:62e4a01503fb745974ffb550836882d3c017ad7c17395442de848150445ba672`,
   and `python3 -c 'import hashlib,json,rfc8785; print(hashlib.sha256(rfc8785.dumps(json.load(open("single-execution-trust-record.json")))).hexdigest())'`
   prints the same digest.
3. Delegation chain, parent and child from the same directory:

   ```bash
   B=https://raw.githubusercontent.com/sipyourdrink-ltd/bernstein/4281e3c1ac86adbfae704dc4d1e69d4bb2a61559/tests/fixtures/trust-record-vectors
   curl -sLO $B/delegated-parent-trust-record.json && curl -sLO $B/delegated-child-trust-record.json
   python3 - <<'PY' | curl -s -X POST https://mcp.bernstein.run/mcp -H "content-type: application/json" -H "accept: application/json, text/event-stream" --data-binary @- | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]["structuredContent"]; print(r["classification"], r["depth"], r["codes"])'
   import json
   p = json.load(open("delegated-parent-trust-record.json")); c = json.load(open("delegated-child-trust-record.json"))
   root = {k: v for k, v in p["cnf"]["jwk"].items() if k != "kid"}
   cred = c["delegation"]["credential_id"]
   ctx = {"trusted_root_keys": [root], "credentials": {cred: {"issuer": p["subject"], "holder": c["subject"], "not_before": c["iat"] - 60, "not_after": c["iat"] + 60}}}
   print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "verify_delegation_chain", "arguments": {"records": [c, p], "context": ctx}}}))
   PY
   ```

   Expected: `verified 1 []`. Drop the `context` and the expected answer is
   `provenance-invalid 1 ['credential_unknown', 'root_key_untrusted']`.
4. Run the `trace-tests` command above; expected `PASS`.

## Limits

Request body up to 1 MiB, up to 64 records per chain call, rate-limited per
client. Source, tests against every trace-spec corpus vector, and the vendored
schema's provenance (`vendor/SOURCE.md`) are in the
[repository](https://github.com/sipyourdrink-ltd/bernstein-mcp).
