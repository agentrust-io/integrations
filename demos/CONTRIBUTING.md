# Contributing

Thanks for looking. This directory holds runnable demos for cMCP, TRACE and the
agent governance tooling. Everything here is meant to be executed rather than only read,
which shapes what a good contribution looks like.

## Getting the code and running it

```
git clone https://github.com/agentrust-io/integrations
cd integrations/demos
pip install -r requirements.txt
python demo-01-cmcp-in-action/run.py
```

The README lists every demo and roughly how long each takes. CI runs all of them
on every pull request, so if a demo does not run from a clean checkout, that is a
bug worth reporting.

## Reporting a problem or suggesting a demo

Open an issue: <https://github.com/agentrust-io/integrations/issues>. For a broken demo,
include the command you ran and what it printed. The output is the evidence.

For a security issue, do not open an issue. See [SECURITY.md](SECURITY.md).

## What an acceptable contribution looks like

**A demo must assert its own outcome.** This is the one rule worth stating
plainly. A demo prints claims about what was enforced, denied, or verified, and a
reader believes them. So the script must check the thing it claims and fail
loudly when the check fails. Printing a heading and then printing a value that
contradicts it is the specific failure mode we have already shipped once: demo-06
printed `gate released key: False` under a heading saying the opposite. A demo
that can print a success message while the underlying check failed is not
finished.

Concretely, for a change to be merged:

- The demo runs end to end from a clean checkout with the documented command.
- It exits non-zero when its own assertion fails, so CI catches it.
- Its output states what actually happened, including when that is a denial.
- Any new demo is added to the README with what it shows and how long it takes,
  and to `../.github/workflows/demos-ci.yml` so it is run on every pull request.
- Tests under `tests/` cover any shared helper you add.

## Style

- Match the surrounding code. There is no separate style guide to learn.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org),
  e.g. `fix(demo-06): assert the gate result the heading claims`.
- Keep pull requests small and single-purpose.

## Fixtures and keys

Everything committed here is synthetic. Sample keys and fixtures exist to be
published and are not secrets. Never add a real credential, endpoint or customer
identifier, even in a comment.

## Licence

By contributing you agree that your contribution is licensed under the MIT
Licence in [LICENSE](LICENSE), the same terms as the rest of the repository.
