# ca2a-delegation: The Agent-to-Agent Boundary

The other examples in this repo govern the **agent-to-tool** boundary: cMCP decides what a *single* agent may call. This example governs the **agent-to-agent** boundary with [cA2A](https://github.com/agentrust-io/ca2a): when a lead agent hands part of a task to a sub-agent, each hop carries a signed delegation credential whose scope is a provable subset of its parent, so authority can only ever narrow as it flows outward.

It uses the credit-risk workflow from [`financial-services/`](../financial-services/README.md) as the worked case, and maps the same pattern onto the other examples at the bottom.

> **Scope of what runs here.** cA2A is in alpha. This example exercises the part that is built today: **attenuated delegation credentials and offline chain verification** (`ca2a_runtime.delegation`). The live peer path (attesting an inbound peer, sealing the payload to its measurement) and the per-hop TRACE provenance record are cA2A roadmap. See the [cA2A ROADMAP](https://github.com/agentrust-io/ca2a/blob/main/ROADMAP.md) and [LIMITATIONS](https://github.com/agentrust-io/ca2a/blob/main/LIMITATIONS.md).

---

## The scenario

A credit assessment is decomposed across three agents. The authority to **write the risk report** is the sensitive one: it is granted to the lead agent but is deliberately never delegated onward, so no sub-agent can regain it.

```
  credit-platform
      │  grants: read:documents, screen:sanctions, read:bureau, run:risk-model, write:risk-report
      ▼
  lead-credit-agent
      │  delegates (evidence-gathering only): read:documents, screen:sanctions, read:bureau
      │  WITHHELD: run:risk-model, write:risk-report
      ▼
  screening-sub-agent
      │  delegates (narrowest): read:bureau
      ▼
  bureau-connector
```

Each hop's scope is a subset of its parent's; each hop's issuer is the previous hop's subject; each links to its parent by `credential_id`.

---

## Run it

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/examples/ca2a-delegation
pip install --pre ca2a-runtime      # cA2A is alpha; --pre is required
```

```bash
python delegation_agent.py
```

```
Building the credit delegation chain:
  [0] credit-platform -> lead-credit-agent
        scope: ['read:bureau', 'read:documents', 'run:risk-model', 'screen:sanctions', 'write:risk-report']
  [1] lead-credit-agent -> screening-sub-agent
        scope: ['read:bureau', 'read:documents', 'screen:sanctions']
  [2] screening-sub-agent -> bureau-connector
        scope: ['read:bureau']

verify_chain: verified=True  hops=3  leaf_scope=['read:bureau']
  authority withheld at the first delegation (never reaches a sub-agent): ['run:risk-model', 'write:risk-report']

Now the bureau connector tries to grant itself write:risk-report ...
  verify_chain: verified=False  code=SCOPE_ESCALATION
  reason: hop 2 scope exceeds parent grant
```

The demo writes both chains to `chain-output/`. Check either from the CLI. `ca2a verify-chain` in ca2a-runtime 0.2.0 takes no trusted root, so it checks invariants 1 to 4 below but not the root:

```bash
ca2a verify-chain --chain chain-output/credit-delegation-chain.json
# {"verified": true, "hops": 3, "leaf_scope": ["read:bureau"]}

ca2a verify-chain --chain chain-output/escalation-attempt.json
# {"verified": false, "code": "SCOPE_ESCALATION", "error": "hop 2 scope exceeds parent grant"}
```

---

## What verification checks

`verify_chain` fails on the first violation:

0. **Trusted root**: the first hop's issuer is in `trusted_root_issuers` (`UNTRUSTED_DELEGATION_ROOT` otherwise). The demo passes the credit platform's key. Leave the argument out and `verify_chain` is structural only: a chain an attacker signs from a key of their own passes 1 to 4.
1. **Signature** on every hop against the issuer's Ed25519 public key.
2. **Continuity**: each hop's issuer is the previous hop's subject.
3. **Attenuation**: each hop's scope is a subset of its parent's scope (`SCOPE_ESCALATION` otherwise).
4. **Anti-replay / structure**: unique `credential_id`s, `parent_id` links to the previous hop, depth increments by one and stays within `max_depth`.

Because the write authority is withheld at the first delegation, attenuation from a trusted root guarantees that no descendant, however many hops down, can write the risk report. That is separation of duties enforced by the credential, not by convention.

---

## How this maps onto the other examples

The same agent-to-agent boundary applies wherever one agent hands work to another. cA2A is the layer above the cMCP tool boundary each of these already demonstrates.

| Example | Delegation hop | Attenuation the chain proves | Escalation it blocks |
|---|---|---|---|
| [`financial-services`](../financial-services/) | lead credit agent → screening sub-agent → bureau connector | evidence-gathering scope is a subset; `write:risk-report` is withheld | a sub-agent trying to write the risk report |
| [`healthcare`](../healthcare/) | clinician agent → pharmacy/medication-safety sub-agent | pharmacist gets only `check:interaction`; no `read:record` or `write:plan` | a consult agent trying to write the treatment plan |
| [`multi-tenant-saas`](../multi-tenant-saas/) | tenant orchestrator → export processor | EU parent holds `export:eea-only`; it cannot mint a child with `export:us` | a cross-border delegation the tenant never had authority to grant |
| [`industrial-embodied-ai`](../industrial-embodied-ai/) | cell orchestrator → robot-cell agent (its `delegation_chain` field is the hook) | the cell agent gets only `move:buffer-zone-1` | a motion request outside the granted zone |

In each, the sensitive capability is granted high and withheld from the delegated scope, so cA2A's attenuation check is what stops a sub-agent from doing more than it was handed. Where a sub-agent is in a different trust domain (the SaaS export processor, a cross-hospital consult), the cA2A **sealed channel** (roadmap) is what would bind the task payload to that peer's attested measurement.

---

## The tests

`tests/test_delegation_scenario.py` checks that the chain verifies, that each hop is a subset of its parent, that the write authority is never delegated, and that the escalation attempt raises `ScopeEscalation`.

```bash
python -m unittest discover -s tests -v
```

---

## License

Apache 2.0. See [LICENSE](../LICENSE) in the repo root.
