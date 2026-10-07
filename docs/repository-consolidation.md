# Examples and demos consolidation

The separate examples and demos repositories were merged into this one. This page
records what was copied from where, which licenses still apply, how review works
now, and the steps for retiring the old repositories.

The canonical working repository is agentrust-io/integrations. Its existing
adapter and package paths remain supported. First-party scenarios live in
examples/, short demonstrations in demos/, and vendor submissions in integrations/.

## Imported sources

| Repository | Source main commit | Imported files |
|---|---|---|
| examples | 7c720e6cbc1f5cdee271f9c9b48238b5fd9d96e1 | 183 |
| demos | fd0a9ef166987a0e640598a8a935b8fe323e6b7b | 89 |

Source licenses remain in examples/LICENSE (Apache-2.0) and demos/LICENSE (MIT).
Their copyright notices and evidence fixtures are retained. Source repository
history remains available in the original repositories; this import does not
rewrite or move that history.

Source .github workflows and ownership settings are consolidated at the root.
Examples CI, example smoke tests, and demos CI are separate workflows. Existing
root CodeQL, actionlint, approval, link, and contributor checks cover the combined
repository. ClusterFuzzLite builds all three suites with their existing dependency
locks. Dependabot covers the imported Python roots.

The demos web-console/vendor/examples submodule and .gitmodules are omitted.
The console runs the shared examples/financial-services scenario directly.

## Review rules

Examples retain maintainer review of every line and verified run claims.
Demos must assert their outcomes and pass the runnable demo checks.
Vendor integrations retain their declared community/verified tier and maintainer
responsibility. Moving code into this repository does not raise its verification tier.

## Cutover

1. Merge this migration after the examples, smoke, demos, and existing integration
   checks pass.
2. Update the organization profile and website demo clone commands to this repository.
3. Update WCM's .github/workflows/python.yml consumer: checkout integrations,
   use examples/weight-custody-manifest, and retain its wheel-against-examples check.
4. Add a moved notice to each source README pointing to the corresponding directory.
5. Recheck source issues, PRs, and main commits immediately before archival.
   Both source issue/PR queues were empty at the initial inventory.
6. Archive the source repositories after their consumers use the combined repository.
   Retain their published history, releases, and issue URLs; do not delete them.

Historical issue links retain their original repository URLs.
