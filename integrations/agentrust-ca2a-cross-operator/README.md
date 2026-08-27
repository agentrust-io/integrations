# cA2A cross-operator delegation tutorial

This runnable example shows what happens when an agent at one operator gives a
limited task to an agent at another operator. The child agent gets only the
permissions both sides allow. The task is encrypted to the child's attested key,
and each hop leaves evidence that an auditor can check later without contacting
either operator.

Source: [cross-operator delegation example](https://github.com/agentrust-io/ca2a/tree/main/examples/cross-operator-delegation)

## Run it

```bash
git clone https://github.com/agentrust-io/ca2a.git
cd ca2a
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python examples/cross-operator-delegation/demo.py
```

Expected final line:

```text
KEY RESULT: 12/12 checks passed
```

The checks cover independent operator keys, mutual channel-key binding,
permission narrowing, local Cedar policy, an allowed call, a denied call,
task sealing, changed-binary detection, and offline verification of the signed
delegation chain and hash-linked provenance DAG.

## Check the saved evidence

The demo writes `chain.json` and `dag.json`. It then verifies both with the cA2A
command line tool. You can repeat those checks later without running the agents:

```bash
cd examples/cross-operator-delegation
ca2a validate-config --config ca2a-config.yaml
ca2a verify-chain --chain chain.json --trusted-root-issuer <root-issuer-hex>
ca2a verify-dag --dag dag.json --chain chain.json \
  --trusted-root-issuer <root-issuer-hex>
```

The demo prints the root issuer value needed by the last two commands.

## What is real

- The delegation signatures, chain continuity, permission narrowing, depth and
  replay checks are real cryptographic checks.
- The child really intersects delegated permissions with its local Cedar policy.
- The task is really sealed to the child's bound key.
- The provenance records are really hash-linked and checked against the signed
  delegation chain.
- Changing the saved chain or DAG makes the verifier exit with an error.

## What is simulated

The SEV-SNP attestation evidence is synthetic. It exercises the protocol and
measurement checks, but it does not prove that this run happened on genuine AMD
hardware or that keys stayed inside a trusted execution environment. The runtime
configuration is also advisory because this example runs offline, not over a live
agent transport.

Use this tutorial to understand the flow and inspect the evidence. Do not use its
synthetic attestation as proof of a production workload.
