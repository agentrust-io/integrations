# Retained execution evidence

`tested_against` is a declaration. A version floor check alone does not show
that a command ran against those versions. The opt-in recorder links an
explicit command to a source revision, installed distribution versions,
manifest digest, timestamps, exit status and the digest of its retained log.

Run from a clean checkout in the same environment that runs the test:

```sh
python scripts/test_evidence.py capture \
  --integration integrations/<name> \
  --output /tmp/integration-evidence \
  --evidence-class synthetic \
  -- python -m pytest integrations/<name>/tests -q
python scripts/test_evidence.py check /tmp/integration-evidence
```

The output directory must be new and outside the checkout (or ignored by Git).
Use a unique directory per run. Only explicitly requested Python commands run;
the tool does not discover or execute vendor code. Dependencies are installed
by the caller from existing released-package locks. It records installed
metadata, so tests that switch environments or install dependencies internally
are outside its supported model. Use the same interpreter throughout.

In an integration's existing GitHub workflow, wrap its current Python test
command, then upload the entire directory with `if: always()` and an explicit
retention period. All three files, `receipt.json`, `evidence.json` and `output.log`, are needed. The recorder
captures the Actions run URL when running in Actions. A timeout or failed test
still produces a receipt and a failing command status. Do not upload logs that
contain credentials or sensitive workload data. The full command argv is retained
in both JSON files: never pass secrets as command-line arguments, and inspect
all artifacts before uploading.

The check returns `consistent` only for a clean matching revision, unchanged
manifest, exact declared/installed versions, successful command and matching
log digest. Version 2 also binds the command, log digest and extra-package
observations in the hashed `evidence.json` payload; changing only the receipt
command or substituting a log and updating only its receipt hash fails. Missing
evidence, missing/mismatched declared distributions, failed runs and stale or
mismatched content fail the check. The recorder observes only distributions
listed in `tested_against` or explicitly requested with repeatable
`--observe-package NAME`; it does not discover undeclared dependencies. A declaration without a receipt remains
declaration-only; absence does not prove the integration was never tested.
Evidence expiry after artifact retention likewise requires a new run.

Evidence class is explicitly chosen: synthetic fixtures, captured evidence,
or live operation. The tool cannot independently verify that classification.
Receipts are unsigned local observations, not attestations: a digest catches
accidental substitution but not someone rewriting the receipt, evidence payload
and log together. A payload hash does not authenticate what command executed.
Review command coverage and trusted CI provenance separately. A successful
command can run zero tests; the tool does not infer conformance or completeness.
Neither a consistent receipt nor a passing test changes community/verified
tiers, compatibility floors, or maintainer approval requirements.

The recorder tests exercise real subprocess success, failure and timeout plus
missing evidence, changed manifests, mismatched versions/revisions and log
substitution. Run `python -m pytest tests/test_test_evidence.py -q`.

## Dependency observation scope

The compatibility floor is a separate repository policy. This checker deliberately
requires exact equality with `tested_against` to check the claimed run; meeting a
minimum version floor is insufficient. It neither raises nor changes that floor.

`--observe-package langchain-core --observe-package langgraph` records the installed
framework versions separately from the schema-limited `tested_against` block.
The LangChain workflow requests both observations (its existing lock pins
langchain-core 1.6.3 and langgraph 1.2.12). Extra observations do not declare a
supported version range, establish compatibility or measure dependency usage.
A requested distribution with no installed metadata is inconsistent. Unrequested
framework/transitive distributions remain outside this receipt's observation.

Version 1 receipts lack the command/log payload and are not accepted by this
checker; retain them as historical observations and capture a fresh version 2
receipt when current consistency is required.
