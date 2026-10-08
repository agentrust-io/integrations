# Publication status

Alakris tracking issue: https://git.elibot.ru/agent-bot/aaif-publication-reference/issues/2

Imran requested an issue in `agentrust-io/integrations`, a linked PR containing the shared runner/adapters/reproducible fixtures, and links from https://github.com/aaif/wg-identity-and-trust/issues/13.

**Published 2026-10-07.**

- Tracking issue: https://github.com/agentrust-io/integrations/issues/287
- Linked PR: https://github.com/agentrust-io/integrations/pull/288 (base `main`, upstream base commit `0966a565e538fdcdd831389b6c843b327b09ab18`; head `codex/aaif-authority-comparison` on fork `wlad232/integrations`)
- WG #13 comment linking both: https://github.com/aaif/wg-identity-and-trust/issues/13#issuecomment-6036876175

GitHub CLI authentication was verified as `wlad232` on 2026-10-07. The previously saved browser restriction on github.com did not reproduce on the standard route: direct HTTPS and authenticated `gh` API requests succeed, so the issue, PR and WG comment were published through the regular GitHub CLI from the human submitter account. No alternate browser, unofficial posting route or network rerouting was used. The final manifest names the verified human GitHub maintainer `wlad232`.

Published review material:

- `UPSTREAM-ISSUE.md`: requested scope, actual findings, review requests and evidence checklist (published as issue #287).
- `UPSTREAM-PR.md`: implementation summary and exact validation scope (published as the PR #288 body with the real tracking URL).
- `WG13-COMMENT.md`: posted to WG #13 with the verified issue/PR URLs.
- `integration.yaml`: manifest naming `wlad232`, validated locally before upstream publication.
- `upstream-workflow.yml.in`: shipped in the PR as `.github/workflows/alakris-authority-comparison.yml`.

Final manifest validation and index/catalog generation were performed locally before publication; `results/upstream-manifest-checks.txt` retains the output. The upstream contribution is human-directed by Vladislav Kostitsyn and retains truthful submitter identity and the project's no-bot-spam policy. Merge of the upstream PR is left to the repository maintainers.
