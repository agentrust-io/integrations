# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/agentrust-io/integrations/security/advisories/new). You will receive a confirmation within 2 business days and a triage decision within 5 business days.

## Response SLAs

| Severity | Definition | Fix Target |
|----------|------------|------------|
| Critical | A demo that reports a control as enforced when it is not, or that would leak a real credential if followed as written | 30 days from confirmed report |
| High / Medium / Low | All other confirmed vulnerabilities | 90 days from confirmed report |

The timeline starts when the issue is confirmed as a valid vulnerability, not on initial receipt.

## Scope

This repository is demonstration code, which shapes what counts as a vulnerability here rather than excusing it. Two things are firmly in scope:

- **A demo whose output misrepresents what was enforced.** The point of these demos is to show a policy denying something, a gate holding, or evidence verifying. A demo that prints a success heading over a failed check is a security defect in this repository, not a cosmetic bug, because the whole artifact is a claim about behaviour. One of these was fixed in August 2026, where demo-06 printed `gate released key: False` under a heading that claimed the opposite.
- **A demo that teaches an unsafe pattern.** Code people copy is code people ship. Disabled verification, an ignored return value, a hardcoded trust anchor presented as normal practice: report it.

Also in scope: anything in this repository that would expose a real credential, endpoint, or customer identifier if run as written.

## Not in scope

- **The demo services themselves as production systems.** They bind local ports, use throwaway keys, and are not hardened for exposure to a network. Report an unsafe *default* that a reader would carry into production; do not report that a demo gateway on localhost has no rate limiting.
- **Vulnerabilities in the upstream projects being demonstrated.** Those belong to agentrust-io/cmcp, agentrust-io/agent-manifest and the other component repositories, each of which has its own policy. If the demo misuses one of them, that part is ours.
- **Synthetic fixtures and sample keys**, which exist to be published and are not secrets.

## What to include

Which demo, the command you ran, what it printed, and what it should have printed. For a misreporting bug, the output is the evidence.

## Disclosure

We prefer coordinated disclosure. Tell us if you intend to publish and we will agree a date. We will credit you in the advisory unless you ask us not to.
