# Agentic Usage Control: start here

## The one-sentence explanation

Agentic Usage Control helps a data owner prove that its rules were followed even
when an AI agent handed work to other agents, models, or tools.

## The problem

Giving an AI agent access is not the same as controlling what happens next.

A hospital might permit an agent to summarize patient information only for a
clinical purpose and only using approved processing in France. The first agent may
follow those rules but delegate the task to another agent, which may choose a model
running somewhere else.

Ordinary access control answers:

> Was this agent allowed through the front door?

Agentic Usage Control also answers:

> Did the rules continue to hold after the agent started making decisions and
> handing work downstream?

## What the example binds

Five pieces go into one checkable record:

1. The data owner's rules.
2. The authority given to each agent in the chain.
3. Evidence about the workload and its operating environment.
4. The policy decision made before data was sent to a model or tool.
5. A signed evidence trail that an independent party can verify later.

The demonstration uses synthetic French healthcare data:

```text
Hospital rule: clinical summarization in France only
                         |
                         v
              Agent delegates the task
                         |
               +---------+---------+
               |                   |
               v                   v
       Approved French model   Non-French model
               |                   |
             ALLOW          DENY BEFORE DATA MOVES
               |                   |
               +---------+---------+
                         v
               Signed evidence bundle
```

## What runs in this folder

The tests and committed vectors show that:

- the approved French route is dispatched;
- the non-French route is denied before dispatch;
- the denial is enforced by cMCP's real policy path;
- delegation is checked cryptographically by cA2A;
- the policy decisions are recorded in a signed TRACE record;
- a separate verifier reproduces the result from the evidence bundle; and
- tampering with the agreement, delegation, decision, evidence chain, or receipt
  causes verification to fail.

The appraisal module also contains placement helpers for two cloud evidence
formats (an attested instance-metadata document joined to a control-plane region,
and a confidential-workload token carrying a zone). They are exercised by unit
tests with synthetic inputs only. The committed vectors are software-only and say
so: `hardware_attested` is `false`.

## What is different about it

Most products solve one part of the problem:

- identity establishes who an agent is;
- authorization grants access to one resource;
- policy describes permitted use;
- attestation reports something about a workload;
- logging records events.

The missing piece is making those artifacts refer to the same protected action and
proving that no required enforcement boundary disappeared from the record.

This example does not replace established standards. It defines the bindings and
verification rules that make them work together for dynamic agent execution.

## What it does not claim

- It does not claim that hardware proves physical geography.
- It does not turn a machine-readable policy into a legal contract by itself.
- It does not make a signed statement automatically true.
- It does not replace OAuth, MCP authorization, or existing policy engines.
- It does not protect production data. All data here is synthetic.
- No standards body has reviewed or endorsed it.

## Who might care

Organizations that own sensitive data or a protected action and want to permit
external or autonomous agents to use it, for example:

- healthcare data owners with purpose and location restrictions;
- financial institutions controlling model, tool, and data boundaries;
- public-sector organizations with sovereign-processing requirements;
- enterprises enforcing export controls or separation of duties; and
- data-space operators whose agreements must survive dynamic downstream routing.

## Status

Experimental. The profile identifiers, schemas, and fixtures may change. External
review of the standards-gap analysis and independent reproduction of the verifier
by another party are both still open. See [standards-gap.md](standards-gap.md).
