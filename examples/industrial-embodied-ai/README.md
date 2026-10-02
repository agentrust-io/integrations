# industrial-embodied-ai: Governed Material Movement

End-to-end example of an AI agent requesting motion from an industrial robot
cell through cMCP, with Agent Manifest declarations and a runtime-issued TRACE
Trust Record.

The example also demonstrates evidence continuity: after the governed session
closes, its saved TRACE Trust Record and audit bundle remain verifiable after
the agent, cMCP Runtime and mock controller stop. This is continuity of
evidence, not continuity of agent memory, reputation or process identity.
Live runs also attach a controller-signed `external_execution_evidence`
receipt to each motion decision when run with a cMCP Runtime that supports
issue #301 external evidence binding.

The scenario is synthetic. It uses no robot hardware, vendor SDK, production
endpoint, or proprietary industrial data.

## What the example demonstrates

The agent runs three paths through a live cMCP Runtime, then closes the session
to produce durable evidence:

1. **Allowed and completed:** cMCP authorizes the declared workflow, then the
   independent controller accepts and completes the simulated motion.
2. **Scope denied, the same motion out of scope:** the agent requests the same
   in-envelope motion as the authorized path (the same approved zone and
   in-limit speed, a fresh valid safety token) but under an undeclared workflow.
   cMCP denies it on scope before the controller is consulted, so the safety
   token is never checked. The only difference from the authorized path is the
   workflow scope, not the motion or its safety: the trust layer withholds the
   action because it is outside the agent's declared purpose.
3. **Safety rejected:** cMCP authorizes the declared workflow, but the
   controller rejects motion after its current state reports a person in the
   safeguarded area.
4. **Controller-signed execution receipts:** each motion decision includes a
   mock controller receipt that cMCP can bind to the audit entry for that
   `call_id`.
5. **Closed-session evidence:** cMCP signs a TRACE Trust Record and audit
   bundle that can be verified from the saved files without a running agent,
   runtime or controller.

Two boundaries sit at the center of this example, and they point in opposite
directions:

> A cMCP `allow` decision means the software request is authorized. It does
> not mean that a physical action is safe, accepted by the controller, or
> completed by a machine.

> A controller `accept` decision means a motion is inside the safety envelope.
> It does not mean the action was authorized, in declared scope, or issued by
> the agent that was reviewed. The safety controller has no concept of
> workflow, declared purpose, or agent identity, so it cannot answer those
> questions. The trust layer is what answers them.

The third path shows the first boundary: an authorized request the controller
still refuses. The second path shows the second boundary: an in-envelope motion
the trust layer refuses on scope. Neither layer subsumes the other, and an
individually safe motion is not, by itself, a trusted one.

## Architecture

```text
 Signed Agent Manifest                 Material-movement agent
 - agent identity declaration                   |
 - prompt, policy and tool hashes               | MCP tools/call
          |                                      v
          | offline validator         +--------------------------+
          +-- compares hashes ------> | cMCP Runtime             |
                                      | - loads policy + catalog |
                                      | - Cedar authorization    |
                                      | - hash-chained audit     |
                                      +------------+-------------+
                                                   |
                                                   | authorized request
                                                   v
 +-------------------------------+
 | Independent mock controller   |
 | - validates fresh state token |
 | - rechecks current cell state |
 | - enforces speed and zone     |
 | - signs motion decisions      |
 +---------------+---------------+
                 |
                 | accepted command
                 v
        Simulated robot execution

 Session close -> signed TRACE Trust Record + signed audit bundle
 Saved files remain verifiable after all three processes stop
```

The current cMCP preview loads the policy and catalog directly. It does not
ingest the Agent Manifest, so the diagram shows an offline hash comparison
rather than a native runtime binding.

## Trust chain demonstrated

| Boundary | Demonstrated behavior |
|---|---|
| Declared agent configuration | A signed Agent Manifest declares the development agent identity and hashes for its prompt, policy and tools |
| Governed tool access | cMCP intercepts each MCP request and evaluates the active Cedar policy before forwarding |
| Scope over safety | cMCP denies an in-envelope motion that falls outside the declared workflow, a check the safety controller does not perform |
| Physical authority | The independent controller rechecks current state and remains authoritative for simulated execution |
| External controller evidence | Motion outcomes can include controller-signed receipts bound to the cMCP audit call id |
| Durable session evidence | TRACE and the signed audit bundle bind the cMCP session, policy, catalog and tool-call transcript |

The example composes these boundaries without claiming that the developer
preview already forms one end-to-end identity and outcome proof. The precise
gaps are listed under [Evidence boundaries](#evidence-boundaries).

## Why individually safe motions still need trust

A safety controller answers one question per motion: is this movement, right
now, inside the envelope. It cannot answer whether a long run of individually
safe motions adds up to something the operator never authorized: an agent that
quietly skips an inspection step, drifts from its declared task, or runs a
configuration that no longer matches the one that was reviewed. Every motion
passes. The harm is in the pattern, not in any single move, and no safety
controller is built to see it.

That is why the durable evidence matters as much as the live decision. The
signed TRACE record and audit bundle let a later reader, an auditor or an
insurer who has no reason to trust the operator's database, reconstruct which
agent configuration acted, under which policy, and against which declared scope,
across the whole session. The trust layer is not a second safety check. It
answers a different question, on a different clock, that physical safety alone
cannot. The controller-side of this boundary is pinned by
`test_safe_motion_is_not_proof_of_authorization` in `tests/test_controller.py`:
a motion the controller accepts as safe carries no claim about scope, purpose
or agent identity.

## Run it

Prerequisites:

- Python 3.11 or newer
- Git

The project is a developer preview. `requirements.txt` pins the TRACE commit
and a cMCP external-evidence PR commit used for this reproducible example
until the summit release stack is available from PyPI.

```bash
cd industrial-embodied-ai
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the mock controller:

```bash
python server/mock_robot_controller.py
```

In a second terminal, start cMCP in explicitly non-hardware development mode:

```bash
cd industrial-embodied-ai
source .venv/bin/activate
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

In a third terminal, run the agent:

```bash
cd industrial-embodied-ai
source .venv/bin/activate
python agent/material_movement_agent.py
```

Expected summary:

```text
SCOPE DENY
  cMCP policy: denied (out of declared scope)
  controller: not consulted

SUCCESS
  cMCP policy: authorized
  controller: accepted
  execution: completed

SAFETY REJECT
  cMCP policy: authorized
  controller: rejected
  reason: human_detected
  execution: not_started

TRACE VERIFICATION
  schema/signature/hashes/freshness: verified
  audit bundle: verified
  controller receipts: verified (2)
  runtime platform: software-only
  hardware attestation: not verified (development mode)
```

The agent writes fresh evidence to:

- `trace-output/latest-trust-record.json`
- `trace-output/latest-audit-bundle.json`

These files are ignored by Git. The committed `example-*` files were captured
from a real run and remain available for offline inspection.

## Verify after shutdown

After the agent exits, stop the cMCP Runtime and mock controller. The fresh
files can still be verified locally:

```bash
cmcp verify trace-output/latest-trust-record.json \
  --policy-hash sha256:c8358148d201749ebd05651ea03cf92fb3ff8cc9cf05816483c394ebc3e1cac9 \
  --catalog-hash sha256:792c86ff8152fa9713d52584c084611eb4929fa5ebf3ec8271dd21f0e0aa7eeb \
  --audit-bundle trace-output/latest-audit-bundle.json
```

This command reads the saved evidence and does not contact the stopped
services. The normal attestation-freshness window still applies: offline
verification means that no live runtime is required, not that an old claim
remains current indefinitely.

## Hardware-attested run

On a supported host, do not set `CMCP_DEV_MODE`. Pin the expected artifacts
and configure the same bearer token for the runtime and agent:

```bash
export CMCP_BEARER_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export CMCP_POLICY_HASH="sha256:c8358148d201749ebd05651ea03cf92fb3ff8cc9cf05816483c394ebc3e1cac9"
export CMCP_CATALOG_HASH="sha256:792c86ff8152fa9713d52584c084611eb4929fa5ebf3ec8271dd21f0e0aa7eeb"

cmcp start --config cmcp-config.yaml
```

Then require hardware verification in the agent:

```bash
python agent/material_movement_agent.py --require-hardware
```

The runtime must detect and successfully verify one of its supported
attestation providers. Development mode intentionally cannot satisfy
`--require-hardware`.

## Verify committed artifacts

```bash
python validate_artifacts.py
python -m unittest discover -s tests -v
```

The validator checks:

- cMCP configuration and catalog definition hashes
- policy bundle and catalog hashes
- Agent Manifest artifact bindings and Ed25519 signature
- runtime-issued TRACE schema and signature
- signed audit-bundle integrity and binding to the TRACE record
- controller execution receipts when present in the audit bundle

## Evidence boundaries

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| Agent Manifest | The signed agent identity declaration and hashes of the approved prompt, policy and tools | That cMCP loaded the manifest or bound its agent identity to the runtime session |
| cMCP decision | The active policy authorized or denied a cataloged tool request | That an authorized physical request was safe |
| Controller accept | The motion was inside the safety envelope for this run | That the action was authorized, in declared scope, or issued by the reviewed agent |
| Controller execution receipt | The mock controller signed a specific accepted or rejected motion decision and linked it to a cMCP audit `call_id` | Hardware-backed execution, physical completion, or functional-safety compliance |
| TRACE Trust Record | cMCP session identity, runtime, policy hash, catalog hash and tool-call transcript integrity | The Agent Manifest identity, controller acceptance, physical completion or functional-safety compliance |
| Saved TRACE and audit files | The closed session can be checked after the processes stop | Continuity of agent memory, reputation or logical identity across a restart or replacement |

When run against a cMCP build with issue #301 support, the audit bundle records
the response hash and can bind the mock controller's signed receipt for each
motion decision. The receipt proves the mock controller signed a decision for
that call id. It does not claim that TRACE proves physical completion,
hardware-backed execution, or compliance with industrial safety standards.

The committed TRACE subject identifies the cMCP session, while the Agent
Manifest declares a separate agent identity. The validator confirms that the
static policy and catalog hashes agree, but the current preview does not
cryptographically bind that manifest identity to the runtime session. It also
does not establish that a restarted or replacement process is the same logical
agent.

## AgenTrust artifacts

| File | Purpose |
|---|---|
| `agent-manifest.json` | Signed development declaration binding the prompt, policy bundle and tool catalog |
| `manifest-public-key.json` | Public verification key for the Agent Manifest |
| `artifact-hashes.json` | Approved cMCP and Agent Manifest artifact hashes |
| `controller-receipt-public-key.json` | Development-only public key for verifying mock controller receipts |
| `catalog.json` | Attested definitions for safety-state and motion-request tools |
| `cmcp-config.yaml` | cMCP configuration shared by development and hardware runs |
| `policy/allow.cedar` | Explicit workflow-scoped permits with default deny |
| `trace-output/example-trust-record.json` | TRACE Trust Record captured from the live development run |
| `trace-output/example-audit-bundle.json` | Signed cMCP audit bundle captured from the same session |

The Agent Manifest is a signed declaration artifact in this example. The
current cMCP preview loads the policy and catalog directly; the validator
checks that their hashes agree with the manifest instead of claiming cMCP
consumes the manifest natively.

## Threats illustrated

- **Compromised planner:** only cataloged tools in the declared workflow are
  authorized.
- **Policy bypass:** the undeclared workflow is denied before forwarding.
- **Untrusted request arguments:** the controller never accepts agent-supplied
  safety booleans.
- **Stale or modified state:** short-lived authenticated state tokens fail
  closed.
- **Replay:** a state token is single-use.
- **Time-of-check/time-of-use change:** the controller rechecks current state
  and rejects motion even after cMCP authorization.

The HMAC state token is a teaching mechanism, not an industrial security
protocol. A real deployment requires authenticated device identity, protected
keys, replay protection, secure time and a validated industrial communication
architecture.

## Safety boundary

This example does not provide or certify:

- emergency-stop functions
- protective stops or safe torque off
- collision avoidance
- safe speed or separation monitoring
- safety-rated control logic
- machinery conformity assessment

Those functions remain in independently engineered and validated
safety-related control systems.

## External references

- [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [ISO 10218-1:2025](https://www.iso.org/standard/73933.html)
- [ISO 10218-2:2025](https://www.iso.org/standard/73934.html)
- [ISO 13849-1:2023](https://www.iso.org/standard/73481.html)
- [IEC 62443-4-2:2019](https://webstore.iec.ch/en/publication/34421)
- [IETF RFC 9334](https://datatracker.ietf.org/doc/rfc9334/)
- [IETF RFC 9711](https://datatracker.ietf.org/doc/rfc9711/)
- [ROS 2 Security Enclaves](https://design.ros2.org/articles/ros2_security_enclaves.html)
- [ROS 2 Access Control Policies](https://design.ros2.org/articles/ros2_access_control_policies.html)
- [Regulation (EU) 2023/1230](https://eur-lex.europa.eu/eli/reg/2023/1230/oj/eng)
- [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)

These references inform the separation of responsibilities. The example is
not a claim of compliance with any standard or regulation.

## License

Apache 2.0. See [LICENSE](../LICENSE) in the repository root.
