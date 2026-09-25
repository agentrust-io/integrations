# Fuzzing

Coverage-guided fuzzing via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/),
running Atheris against the untrusted input the two first-party packages read.

| Target | Surface |
| --- | --- |
| `fuzz_openshell_transcript.py` | `build_transcript()`: the OpenShell OCSF JSONL export, committed by digest as the tool transcript. |
| `fuzz_openshell_bundle.py` | `verify_bundle()`: manifest, detached signature and files of an OpenShell evidence bundle, including manifests validly signed by the pinned key. |
| `fuzz_capture_state.py` | `load_state()` and `check_seal()`: the baseline file every capture engine reads at session start. |

Each target asserts the function's documented contract rather than only "does
not crash": failures stay inside the declared error type, a committed
transcript is strict canonical JSON with one event per JSONL line, nothing
verifies under an unpinned key, and a corrupt baseline reads as absent.

## Standing of the targets when added

Driven locally with a stand-in for atheris over 3,000 seeded and mutated inputs
each (atheris does not build on the Windows machine used). Against the code
before this change, `fuzz_capture_state.py` raised `UnicodeDecodeError`,
`ValueError` (integer digit limit) and `RecursionError` out of `load_state()`,
and `fuzz_openshell_transcript.py` raised `RecursionError` and found one JSONL
line accepted as two events. All are fixed, with regression tests in
`packages/*/tests`. `fuzz_openshell_bundle.py` found nothing.

## Running locally

```
git clone https://github.com/google/clusterfuzzlite --depth 1 /tmp/clusterfuzzlite
python /tmp/clusterfuzzlite/infra/helper.py build_image --external $PWD
python /tmp/clusterfuzzlite/infra/helper.py build_fuzzers --external --sanitizer address $PWD
python /tmp/clusterfuzzlite/infra/helper.py run_fuzzer --external $PWD fuzz_openshell_transcript
```

## In CI

`cflite_pr.yml` fuzzes code a pull request touched, for five minutes.
`cflite_batch.yml` runs every target nightly. Both are read-only and report
through the job log and the crash artifact.
