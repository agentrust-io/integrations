# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/agentrust-io/integrations/security/advisories/new). You will receive a confirmation within 2 business days and a triage decision within 5 business days.

## Response SLAs

| Severity | Definition | Fix Target |
|----------|------------|------------|
| Critical | An example that verifies nothing while appearing to, or that would leak a real credential if followed as written | 30 days from confirmed report |
| High / Medium / Low | All other confirmed vulnerabilities | 90 days from confirmed report |

The timeline starts when the issue is confirmed as a valid vulnerability, not on initial receipt.

## Scope

These are reference examples, which is exactly why a flaw in one travels. Code here is meant to be copied.

- **An example that teaches an unsafe pattern.** Verification switched off to make a sample run, a signature checked and the result discarded, a trust anchor hardcoded without saying that a real deployment must not do that. Report it.
- **An example whose output misstates what happened.** If a snippet prints that a record verified when the call failed or was skipped, that is a security defect here, because the example is a claim about behaviour that a reader will rely on.
- **Response scanners and detectors** under this repository, where a missed detection is the failure mode that matters. A known false positive, such as a ten-digit number read as a phone number, is a bug rather than a vulnerability.

## Not in scope

- **Vulnerabilities in the upstream components being demonstrated.** Those belong to agentrust-io/cmcp, agentrust-io/agent-manifest, agentrust-io/trace-spec and their siblings, each with its own policy. If an example misuses one of them, that part is ours.
- **The example services as production systems.** They are not hardened for network exposure. Report an unsafe default a reader would carry into production, not the absence of hardening in a sample.
- **Synthetic fixtures, sample keys and test vectors**, which exist to be published.

## What to include

The example, the command you ran, its output, and what it should have been. A minimal reproducer is the fastest route to a fix.

## Disclosure

We prefer coordinated disclosure. Tell us if you intend to publish and we will agree a date. We will credit you in the advisory unless you ask us not to.
