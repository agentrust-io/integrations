# Workflow OIDC source baseline

This guard continues the source-drift portion of
[the release safeguard sweep](https://github.com/agentrust-io/.github/issues/54).
It proposes preserving the existing three job-level `id-token: write` grants:

| Workflow | Job | Existing use |
|---|---|---|
| `capture-core-publish.yml` | `publish` | PyPI trusted publishing |
| `trace-adapters-publish.yml` | `publish` | PyPI trusted publishing |
| `scorecard.yml` | `scorecard` | Existing Scorecard configuration |

`tests/test_workflow_oidc_permissions.py` inventories all `.yml` and `.yaml`
workflow files. It refuses workflow-wide OIDC grants even when current jobs
override them, `write-all` at either scope, and additions, removals or renames of
the three named grants. Intentional grant changes need an explicit review of the
baseline together with the workflow delta. Read-only inheritance remains valid.
Malformed permission shapes and an empty inventory fail closed. The existing
actionlint check remains responsible for workflow syntax and duplicate keys.

Run from the repository root after installing `requirements/validate.txt`:

```sh
python -m pytest tests/test_workflow_oidc_permissions.py -q
```

The existing validation workflow runs this module. Paired temporary-copy tests
start from the real source, show it passes, then inject one permission drift at
a time. A direct optimized-Python subprocess both accepts the baseline and
refuses a new workflow-wide grant without pytest assertion rewriting.

This checks source configuration only. It does not attest live environment
reviewers, self-review restrictions, administrator bypass, deployment ref
restrictions, trusted-publisher bindings, or primary/backup operator coverage.
The Scorecard allowance preserves current source and is not a new determination
that this permission is necessary. No package is published and no environment
setting or existing OIDC grant changes. This does not close the parent tracker.
