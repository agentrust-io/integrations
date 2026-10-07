# Publication status

Alakris tracking issue: https://git.elibot.ru/agent-bot/aaif-publication-reference/issues/2

Imran requested an issue in `agentrust-io/integrations`, a linked PR containing the shared runner/adapters/reproducible fixtures, and links from https://github.com/aaif/wg-identity-and-trust/issues/13.

**Those GitHub artifacts are not yet published.** GitHub CLI authentication is verified as `wlad232` on 2026-10-07; the saved browser permission still rejects github.com. No alternate browser or API posting route was used to circumvent that setting. The final manifest names the verified human GitHub maintainer `wlad232`.

Prepared review material:

- `UPSTREAM-ISSUE.md`: requested scope, actual findings, review requests and evidence checklist.
- `UPSTREAM-PR.md`: implementation summary and exact validation scope; replace the tracking URL only after issue creation.
- `WG13-COMMENT.md`: link the real issue/PR after both exist.
- `integration.yaml`: manifest naming `wlad232`, validated locally before upstream publication.
- `upstream-workflow.yml.in`: intended upstream `.github/workflows/alakris-authority-comparison.yml`.

Final manifest validation and index/catalog generation are performed locally; after the saved site restriction is removed, create the issue and linked PR against base `0966a565e538fdcdd831389b6c843b327b09ab18`, and verify the resulting links before posting to WG #13. The upstream contribution is human-directed by Vladislav Kostitsyn and must retain truthful submitter identity and the project’s no-bot-spam policy.
