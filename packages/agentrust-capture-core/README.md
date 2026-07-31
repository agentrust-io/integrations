# agentrust-capture-core

Shared fingerprinting, comparison and baseline-sealing core for AgenTrust
agent-integrity capture engines.

Each engine answers one question about a different coding agent:

> Is this the agent composition I approved, with nothing added and nothing
> subtracted?

What differs between agents is **where to look** and **what to call things**. What
must not differ is how content is fingerprinted, how snapshots are compared, how a
baseline is sealed, and the rules that keep a report honest. This package owns the
second list.

## Why it exists

Those parts lived in three copies, and the cost was not theoretical:

- The same skill-fingerprinting bypass had to be found and fixed **twice**,
  independently, in two shipped engines. A component was digested by its manifest
  alone, so a payload swapped into a sibling `scripts/` directory left the
  fingerprint unchanged and the report said "nothing added, nothing subtracted".
- A reporting defect that rendered **unmeasured** categories as measured zeros was
  fixed in one engine while the other kept shipping it.

A fourth engine would have meant writing both bugs a fourth time.

## What it does not do

No dependencies. The engines are invoked by shell hooks at session start and must
run before anything is installed, so this package is standard library only and a
test asserts it.

No opinion on where an agent keeps its files, what its categories are called, or
how its report is laid out. Baseline scoping in particular is deliberately not
unified: Claude Code keeps one baseline per machine, Codex keeps one per workspace
because a workspace carries its own instructions and skills. Both are correct for
their agent, so an engine supplies its own paths.

## The pieces

| Module | Owns |
|---|---|
| `hashing` | `tree_digest` over a component directory, file and mapping digests, the exclusion denylist, `uuid7`, `now_iso` |
| `seal` | Sealing a baseline with a content digest and checking it: `ok`, `unsealed`, `broken` |
| `compare` | Map, set, scalar and rollup diffs, plus observed-category and measurement-scope gating |
| `state` | Atomic write, load-corrupt-as-absent, sealed baseline write |
| `report` | The honesty vocabulary: unmeasured labelling, partial-coverage qualification, the baseline-integrity block |

## Two rules worth knowing before you use it

**An unmeasured category is not an empty one.** A shell hook cannot see a live tool
roster or the model. Rendering those as `0 tools` states a measurement that was
never taken, and a reader who cannot tell "we did not check" from "we checked and
found nothing" treats an absence as a pass. Use `measured_or` and
`unmeasured_footnote`.

**A partial check is not a clean bill of health.** `clean_verdict(complete=False)`
qualifies the verdict as "in the categories checked".

## On what sealing is worth

`attach_seal` stores a SHA-256 digest of the baseline's own content. It catches
corruption, truncation, and a hand-edit that does not recompute it. **It does not
catch an attacker who owns the state directory**, who can recompute the digest as
easily as this package can.

An earlier design used an HMAC with a locally stored secret. It was removed: the
only adversary an HMAC defeats here is one who can *write* the state directory
without being able to *read* it, which barely exists on a developer machine, and
the stored secret was a credential to leak in exchange.

The control that does survive a real adversary is off-box. Engines print the
baseline digest on approve and on verify, so a human who recorded the first sees a
silent re-baseline even when the attacker resealed it perfectly. There is a test
that makes this limit executable rather than prose.

## License

Apache-2.0.
