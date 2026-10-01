# Observed-effect references

A TRACE Trust Record says what an agent was and what it ran under. This integration adds what an observer outside the agent saw change while it ran: each record carries one `references` entry with `rel: "observed-effect"`, and the entry's `digest` pins an in-toto statement the observer signed over the state before and after the interval.

## What it does

- `examples/` holds five signed Trust Records and the effect store their references resolve against. The two observer statements in `examples/source/` are copied byte for byte from [vectors-observed-effect at v0.15.0](https://github.com/probityai/agent-evidence-vectors/tree/v0.15.0/vectors-observed-effect); everything else regenerates from one published seed.
- `tests/` verifies every record with released `agentrust-trace`, then recomputes the relying party's verdict for each case from the committed bytes: verified, digest mismatch, unresolved, and observer key not configured.
- CI also replays the whole published corpus the statements come from, pinned to one release.

## Run it

```
pip install -e "integrations/probityai-observed-effect[test]"
python -m pytest integrations/probityai-observed-effect/tests
uvx agent-evidence-vectors==0.15.0 --corpus vectors-observed-effect
```

## What it does NOT claim

A verified reference establishes that the resolved bytes are the cited bytes and that the named observer signed them. It does not establish that the change the statement reports occurred, and it never changes whether the Trust Record itself verifies (trace-v0.2 section 3.1.2 rule 3). The `observed-effect` value is proposed for the references registry in [trace-spec#403](https://github.com/agentrust-io/trace-spec/pull/403) and is not registered yet; the v0.2 schema leaves `rel` open. No TRACE conformance level is claimed.
