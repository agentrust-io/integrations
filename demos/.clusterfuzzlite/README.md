# Fuzzing

Coverage-guided fuzzing via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/),
running Atheris against the parts of this repo that take input from a network
peer or a browser.

The demos are mostly scripts that drive cMCP Runtime and the WCM SDK, and those
packages are fuzzed in their own repos. What is ours here is three small HTTP
servers, so that is what these targets cover.

| Target | Surface | Property |
| --- | --- | --- |
| `fuzz_console_requests.py` | `web-console/webserver.py` POST handling: Host, Origin, Content-Type, Content-Length and the JSON body | One response per request, nothing escapes the handler, and the example agent only runs when every gate passed |
| `fuzz_demo_servers.py` | `server/server.py` JSON-RPC tool calls, and the demo 10 `endpoint.py` chat request | Always a well-formed response; no file is touched outside the workspace; only a data class the Cedar bundle names is forwarded; the forwarded prompt matches none of the endpoint's own identifier patterns |

The agent run, the policy-bundle hashing and the gateway hop are stubbed. They
start subprocesses or need ports, and the properties above have to hold
whatever they would have returned.

## Standing when added

Neither target has run under libFuzzer yet; the first CI run is the first real
one. Before that, each target's `TestOneInput` was driven in plain Python over
3,000 random and dictionary-built inputs plus a seeded grid (every Host, Origin,
Content-Type, path and Content-Length combination for the console; traversal
paths and overlapping identifier shapes for the servers), with no failures. Both
were also bundled with PyInstaller using the same `--paths` flags as `build.sh`
and run from outside the source tree.

Each property was checked against a deliberately broken build: with the console's
Host gate removed the first target fails on a rebound Host, and with the file
server's path containment removed the second fails on `../`.

The request-level bugs these targets guard (cross-origin and rebinding requests
reaching `/api/run` and `write_file`, unhandled exceptions on malformed bodies,
an unknown data class going out of region) were found by review and are pinned
by `tests/test_request_hardening.py`.

## Running locally

```
git clone https://github.com/google/clusterfuzzlite --depth 1 /tmp/clusterfuzzlite
python /tmp/clusterfuzzlite/infra/helper.py build_image --external $PWD
python /tmp/clusterfuzzlite/infra/helper.py build_fuzzers --external --sanitizer address $PWD
python /tmp/clusterfuzzlite/infra/helper.py run_fuzzer --external $PWD fuzz_demo_servers
```

## In CI

`cflite_pr.yml` fuzzes code a pull request touched for five minutes.
`cflite_batch.yml` runs both targets for 30 minutes, nightly. Both are read-only
and report through the job log and the crash artifact.
