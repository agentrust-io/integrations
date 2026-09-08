# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/agentrust-io/integrations/security/advisories/new). You will receive a confirmation within 2 business days and a triage decision within 5 business days.

## Response SLAs

| Severity | Definition | Fix Target |
|----------|------------|------------|
| Critical | Signing key extraction, forged or replayed evidence accepted as genuine, arbitrary code execution from a captured artifact | 30 days from confirmed report |
| High / Medium / Low | All other confirmed vulnerabilities | 90 days from confirmed report |

The timeline starts when the issue is confirmed as a valid vulnerability, not on initial receipt. We will report progress at least every 14 days during active remediation.

## Scope

This repository publishes two packages to PyPI, and those are the sharpest edge of its scope:

- **`agentrust-capture-core`** (`packages/agentrust-capture-core`). Fingerprinting, comparison, sealing and report rules. It is what the editor and agent plugins are built on, so a flaw here reaches every one of them.
- **`agentrust-trace-adapters`** (`packages/agentrust-trace-adapters`). Framework adapters that observe a run and emit TRACE records.

Also in scope:

- **The plugins and integrations under `plugins/` and `integrations/`**, where they parse, sign, verify or transmit evidence. A plugin that reports a drift check as passing when it did not is a security defect here, not a bug.
- **The publish workflows.** These build and upload the two packages above, so anything that would let an unintended artifact be published, or an intended one be altered in transit, is in scope.

## Not in scope

- **Vulnerabilities in the third-party tools these integrations observe.** Report those to the tool's own maintainers. If our adapter mishandles a response from one of them, that part is ours and is in scope.
- **Findings that a published package resolves to a newer dependency than a lockfile pins.** Several conformance jobs install released packages from PyPI on purpose, so that drift between the published artifact and this tree is caught rather than hidden. Those steps are named for it and run with `permissions: contents: read`.
- **Sample data and fixtures** under test directories, which are synthetic and are not credentials.

## What to include

The package or plugin and its version, what you did, what happened, and what you expected. A failing test or a minimal reproducer is the fastest route to a fix. If the finding depends on a specific artifact, include its hash.

## Disclosure

We prefer coordinated disclosure. Tell us if you intend to publish, and we will agree a date. We will credit you in the advisory unless you ask us not to.
