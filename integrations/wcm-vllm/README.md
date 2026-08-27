# Attestation-gated weight loading for vLLM

Two jobs. Before the model loads, obtain the weight key through a WCM key broker,
which happens only if this workload's attestation satisfies the manifest. While
the server runs, keep the lease alive and stop serving the moment it lapses.

## Read this first: termination is the wipe

WCM Layer 3 says a runtime that loses authorization wipes the key and stops
serving. In a Python inference server, only half of that is achievable, and this
integration is explicit about which half.

`EnclaveSession.zeroize()` overwrites the SDK's own key buffer, and the SDK
already documents that as best-effort in a managed runtime. Once the **weights**
are decrypted and handed to a tensor library, they exist in process-heap copies,
in pinned host buffers, and in GPU device memory. No Python code reaches any of
that. There is no `del` and no `gc.collect()` that constitutes erasure.

So `on_lapse` defaults to terminating the process, and the honest description of
wipe-on-lapse here is:

> The server stops serving and the process exits, so the operating system
> reclaims the memory.

That is a real control and it is enforceable. It is weaker than zeroization. If
your deployment needs true zeroization it belongs in the enclave runtime below
Python, not here.

The default handler uses `os._exit`, not `sys.exit`. A lapsed lease means this
process is no longer authorized, and an exception propagating through a request
handler can be caught by a framework, logged, and followed by the next request
being served anyway. Interpreter shutdown also runs `atexit` handlers, which is
more code running while unauthorized than there needs to be. The reason is logged
and handlers flushed first, because the cost is losing buffered logs.

## This does not make vLLM an enclave

Everything gained here depends on the process running inside a confidential VM
whose measurement is what the broker verified. Run it on an ordinary host and the
broker refuses. That is the correct outcome, not a bug to work around.

## The lease is checked per request, not per token

vLLM offers no cheap hook on each forward pass. A lapse detected mid-generation
stops the **next** request, not the current one, so a lease deadline is accurate
to roughly one request's duration.

Size the cadence accordingly. A 30-second cadence on a workload with 90-second
generations is a lease that means very little.

## Two failures that are not the same

| Condition | Meaning | What happens |
|---|---|---|
| Wall-clock lease lapsed | Authorization expired; the key is gone | `on_lapse` fires, process exits |
| Operation budget exhausted | Still authorized, needs re-attestation | `ServingHalted` raised, process keeps running |

Conflating them would take a healthy server down for a condition that a
re-attestation fixes.

## Run it

```bash
pip install weight-custody-manifest
```

```python
from wcm_serving_guard import CustodyGuard

guard = CustodyGuard(broker=kbs, manifest=manifest, provider=provider)

key = guard.acquire()      # raises ReleaseRefused, listing the failed checks
weights = decrypt(encrypted_weights, key)
guard.start()              # background lease clock, daemon thread
```

Then, once per inference request:

```python
guard.authorize_request()
```

Raising is not by itself the control, since a framework can catch it. It exists
so a caller wrapping requests gets a clean error, while `on_lapse` does the part
that cannot be caught.

`acquire()` returns the key rather than stashing it on the guard. One copy is
already more than can be erased later; a second held for convenience would be one
nobody remembers to drop. There is a test asserting the guard holds none.

## Wiring, and why it is thin

`CustodyGuard` imports nothing from vLLM. It is testable without a GPU and is
unaffected when vLLM's plugin surface moves, which it does.

Wire `acquire()` ahead of engine construction and `authorize_request()` into your
serving entry point. For the OpenAI-compatible server that means an ASGI
middleware around the app; for offline batch use it means a call before each
`generate`. Both are a few lines, and both are yours rather than something this
module guesses at across vLLM versions.

`Broker` is a Protocol covering the two methods used, so a deployment can put its
own transport in front of a remote broker without subclassing anything.

## Serving image inference

The guard infers `serving_image_measurement` from the manifest when exactly one
accepted measurement is `current`. Zero or several raises, because a workload
that cannot say which serving image it is has nothing to attest to, and inventing
one produces evidence the broker rejects with a message about measurements rather
than about configuration.

Pass `serving_image_measurement` explicitly to override.

## Scope

Confidential computing does not hold against an operator who physically owns the
hardware (WCM `SPEC.md` section 3.6). This gates loading and serving against a
software adversary and a remote attacker, inside a CVM. It does not defend
against the machine's owner, and the memory it cannot erase is the same memory
those published attacks read.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
