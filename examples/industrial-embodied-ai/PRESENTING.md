# Present the workflow-authority demo

Message: a motion can be inside the controller's safety envelope and still be
outside the agent's authorized task. cMCP checks workflow scope before forwarding
the motion. The same request under the declared workflow is allowed, and the
resulting signed records can be checked after the services stop.

Use one terminal with a large font. No frontend, dashboard, slide, or robot
animation is required. This is an AgenTrust cMCP demonstration; it does not run
Agent Governance Toolkit. Both the agent's requests and robot cell are
simulated, while the MCP gateway, Cedar policy evaluation, signatures, and
evidence verifier run locally against released packages.

## Reproduce from a clean checkout

Use Python 3.11 and Git on macOS or Linux. Install dependencies before the talk;
the walkthrough itself needs only local loopback networking, with ports 8080
and 8443 free. No model API key, cloud account, robot hardware, or internet
connection is needed after installation.

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/examples/industrial-embodied-ai
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-presenter.txt
python present.py --auto
python present.py
```

`--auto` rehearses all six steps without pauses. The interactive command waits
for Enter five times. Each run creates a fresh session, audit database, and
directory under `trace-output/presenter-<timestamp>-<random>/`. To choose a
location, pass `--output-dir /path/to/a/new-run`. The directory must not exist;
previous evidence is never overwritten.

The launcher validates the committed example artifacts before starting the
services, checks readiness, and keeps service output in that run's log files.
It uses an ephemeral local bearer token and explicitly selects software-only
development mode. It stops only its own child processes, including on Ctrl+C,
closed input, startup failure, or a failed check. An occupied port causes a
failure without stopping its owner. Stop a previous manual instance yourself
before retrying; the example's catalog intentionally fixes the controller port.

## Three-minute script

Start the command and wait for **1/6 MISSION** before beginning the timed demo.
Treat these as speaking cues rather than text to read verbatim.

| Time | Presenter action | What the audience sees and hears |
| --- | --- | --- |
| 0:00-0:20 | Show the mission. | "Move material to this station at 0.3 m/s. The controller checks the motion. Who checks whether the agent is authorized to do this task?" |
| 0:20-0:55 | Press Enter: undeclared workflow. | **SCOPE DENIED**. A fresh state token, approved target, and in-limit speed accompany the request. cMCP denies the workflow; the controller's measured motion-request counter stays **0 -> 0**. "Motion safety alone does not grant task authority." |
| 0:55-1:25 | Press Enter: declared workflow. | **AUTHORIZED**. The same motion parameters now use `industrial-material-movement`. cMCP allows it; the controller accepts the simulated motion; its counter becomes **0 -> 1**. |
| 1:25-1:45 | Press Enter: close and stop. | **SERVICES STOPPED**. The session closes, evidence is saved, and both demo-owned service processes exit. |
| 1:45-2:15 | Press Enter: offline verification. | **OFFLINE VERIFICATION**. TRACE signature, policy/catalog hashes, freshness, audit chain, and one controller receipt verify from files. Software-only limitations remain visible. |
| 2:15-2:50 | Press Enter: tamper check. | **TAMPER CHECK**. The original verifies; an altered copy of the signed outcome digest is rejected. "We need task authority beyond motion safety, and records we can check later." |

The pauses happen **before** each state-read and motion pair. The controller's
five-second state-token expiry and replay checks remain active. You can pause
to speak without reusing an old observation. Do not add a pause between a state
read and its motion request. A slow or suspended machine can still exceed the
five-second interval during a pair; that run must fail and be restarted.

The controller counter measures received `robot.request_motion` calls. State
reads do reach the controller, including before the denied motion. These
diagnostic counters and `observations.json` are local observations, not signed
hardware telemetry. The original three-path agent additionally demonstrates
controller rejection after authorization; see the [main guide](README.md#run-it).

## Check the saved files independently

Use the directory printed at the end of the run. For example, if you ran
`python present.py --auto --output-dir /tmp/industrial-demo-run`:

```bash
python verify_evidence.py /tmp/industrial-demo-run/trust-record.json \
  /tmp/industrial-demo-run/audit-bundle.json
python verify_evidence.py /tmp/industrial-demo-run/trust-record.json \
  /tmp/industrial-demo-run/tampered-audit-bundle.json
```

The first command exits 0 and reports `EVIDENCE VERIFIED`; the second exits 1
and reports `EVIDENCE REJECTED`. The verifier requires a controller receipt and
prints verification success only after all checks pass. It does not contact
the stopped services. Normal attestation freshness checks still apply: an old
record may be rejected even if it was valid at rehearsal time.

Saved files include the original TRACE record and audit bundle, a separate
tampered bundle, the rejection reason, observed forwarding counts, the generated
runtime configuration and database, and preflight/runtime/controller logs.
Keep the original files together. Avoid publishing unreviewed logs or replacing
the committed teaching fixtures with generated session evidence.

## Evidence boundaries

- This demonstrates local workflow authorization and integrity of software
  records. A signed simulated outcome is not proof of physical completion.
- The mock controller uses a public, deterministic teaching key. Anyone with
  the source can reproduce that key; its signature is not independent
  controller identity or hardware provenance.
- Runtime attestation is explicitly software-only. TRACE verification checks
  the signing key in the record; this run establishes no hardware root of trust
  or independently trusted runtime identity.
- Agent Manifest hashes/signature are checked offline by preflight. The runtime
  does not cryptographically bind that manifest to the calling agent session.
- The tamper step changes `external_execution_evidence.evidence_hash`, the
  digest of the recorded controller outcome. Verification detects the changed
  signed evidence; it does not inspect a real robot or reconstruct motion.

## Maintainer checks

```bash
python -m unittest discover -s tests -v
python validate_artifacts.py
python -m unittest discover -s tests -p 'live_*.py' -v
```

The live suite runs two fresh sessions, tests both first pauses beyond five
seconds, verifies saved files with socket operations forbidden, rejects altered
claims/bundles, and checks cleanup after interruption and closed input. Run it
serially with ports 8080 and 8443 free. CI runs it on same-repository PRs and
pushes under the existing dependency-install policy; fork PRs still run the
controller and launcher unit tests.

To refresh the hash lock deliberately with `uv` installed, use:

```bash
uv pip compile requirements.txt --python-version 3.11 --generate-hashes \
  -o requirements-presenter.txt
```

Review package changes and repeat the live suite before committing the lock.
