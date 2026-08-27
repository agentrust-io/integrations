#!/usr/bin/env python3
"""Attestation-gated weight loading and lease-bound serving for vLLM.

Two jobs. Before the model loads, obtain the weight key through a WCM key
broker, which happens only if this workload's attestation satisfies the
manifest. While the server runs, keep the lease alive and stop serving the
moment it lapses.

**Read this before deploying it. Termination is the wipe.**

WCM Layer 3 says a runtime that loses authorization wipes the key and stops
serving. In a Python inference server, only half of that is achievable.

``EnclaveSession.zeroize()`` overwrites the SDK's own key buffer, and the SDK
already documents that as best-effort in a managed runtime. Once the weights
themselves are decrypted and handed to a tensor library, they exist in
process-heap copies, in pinned host buffers, and in GPU device memory. No Python
code reaches any of that. There is no ``del`` and no ``gc.collect()`` that
constitutes erasure, and any integration claiming otherwise is claiming
something it cannot do.

So ``on_lapse`` defaults to terminating the process, and the honest description
of wipe-on-lapse here is: **the server stops serving and the process exits, so
the operating system reclaims the memory.** That is a real control, it is
enforceable, and it is weaker than zeroization. If your deployment needs true
zeroization, it belongs in the enclave runtime below Python, not here.

**This does not make vLLM an enclave.** Everything gained depends on the process
running inside a confidential VM whose measurement is what the broker verified.
Run this on an ordinary host and the broker will refuse, which is the correct
outcome and not a bug to work around.

**The lease is checked per request, not per token.** vLLM offers no cheap hook on
each forward pass. A lapse detected mid-generation stops the next request, not
the current one, so a lease deadline is accurate to roughly one request's
duration. Size the cadence accordingly; a 30-second cadence on a workload with
90-second generations is a lease that means very little.

**Signed receipts, and the one ordering constraint that matters.** Pass a
``runtime_signing_key`` and the guard emits ``wcm.runtime_records``: an
Ed25519-signed, hash-chained account of the lease, verifiable by anyone holding
the public key. The SDK's terminal-chain contract is exact, and it is
``lease_started``, then any number of ``renewal_succeeded``, then one boundary
(``lapse_detected`` or ``revocation_detected``), then ``wipe_requested``,
``wipe_completed`` and ``process_terminated`` in that order.

That last record has to be written *before* the process leaves, which means
before ``on_lapse`` runs, because the default ``on_lapse`` calls ``os._exit``
and nothing after it executes. So ``process_terminated`` attests the intent to
terminate, recorded immediately before the call that does it. A process killed
from outside, by SIGKILL or a power cut, leaves a chain ending earlier, which
verifies as a valid *partial* chain and not as a terminal one. That distinction
is the useful part: a truncated chain says the runtime stopped without
completing its own wipe sequence.

The chain proves the runtime said these things, in this order, with nothing
removed from the middle. It does not prove the runtime was attested at each
step. Attestation happened once, at release, and the broker verified it there.

**The wiring is deliberately thin.** ``CustodyGuard`` depends on nothing from
vLLM, so it can be tested without a GPU and is unaffected when vLLM's plugin
surface moves. The README shows the wiring against public entry points.

Usage::

    pip install weight-custody-manifest

    from wcm_serving_guard import CustodyGuard

    guard = CustodyGuard(broker=kbs, manifest=manifest, provider=provider)
    key = guard.acquire()          # raises ReleaseRefused if the gate says no
    guard.start()                  # background lease renewal
    ...
    guard.authorize_request()      # per request; raises when the lease lapsed
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from wcm import (
    AttestationProvider,
    CompositeEvidence,
    EnclaveSession,
    KeyWipedError,
    ReattestationRequired,
    ReleaseDecision,
    RuntimeEvent,
    RuntimeRecord,
    SessionState,
    WeightCustodyManifest,
    canonical_hash,
    parse_cadence,
    runtime_public_key,
    sign_runtime_record,
    verify_runtime_record_chain,
)

__all__ = [
    "CustodyGuard",
    "ReleaseRefused",
    "ServingHalted",
    "GuardState",
    "Broker",
    "lease_id_for",
]

logger = logging.getLogger("wcm.serving")


class ReleaseRefused(RuntimeError):
    """The broker declined to release the key. Carries the failed check names."""

    def __init__(self, decision: ReleaseDecision) -> None:
        self.decision = decision
        self.failed_checks = sorted(check.name for check in decision.failures)
        super().__init__(
            "key release refused: " + (", ".join(self.failed_checks) or "no checks passed")
        )


class ServingHalted(RuntimeError):
    """The lease lapsed or its budget ran out; this server must not serve."""


class Broker(Protocol):
    """The subset of ``KeyBrokerService`` this guard uses.

    A Protocol rather than the concrete class so a deployment can put its own
    transport in front of a remote broker without subclassing anything.
    """

    def issue_challenge(self) -> Any: ...

    def verify_and_release(
        self, manifest: WeightCustodyManifest, evidence: CompositeEvidence
    ) -> ReleaseDecision: ...


@dataclass
class GuardState:
    """What the guard will tell an operator, with no key material in it."""

    acquired: bool = False
    state: str = "not-acquired"
    requests_authorized: int = 0
    lapses: int = 0
    last_error: str | None = None
    failed_checks: tuple[str, ...] = field(default_factory=tuple)
    #: How many signed runtime records exist. Zero when no signing key was given.
    records_written: int = 0
    #: The lease identifier the records are bound to, derived from the challenge.
    lease_id: str | None = None


def lease_id_for(nonce: str) -> str:
    """Derive a lease identifier from the KBS challenge nonce.

    The lease is the thing the attestation created, so identifying it by that
    challenge is the honest binding. The nonce itself is not republished: a
    runtime record is meant to be handed to a third party, and a single-use
    replay-protection value is not something to scatter into artifacts that
    outlive it. A digest correlates for anyone who holds the nonce and reveals
    nothing to anyone who does not.
    """
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()[:32]


def _terminate(reason: str) -> None:
    """Default lapse handler: leave the process, hard.

    ``os._exit`` rather than ``sys.exit`` on purpose. A lapsed lease means this
    process is no longer authorized to serve, and an exception propagating up
    through a request handler can be caught by a framework, logged, and followed
    by the next request being served anyway. Interpreter shutdown also runs
    ``atexit`` handlers and flushes buffers, which is more code running while
    unauthorized than there needs to be.

    The cost is that logs may be lost, so the reason is logged first.
    """
    logger.critical("wcm: halting, %s", reason)
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:  # pragma: no cover - flushing must not block the exit
            pass
    os._exit(70)


class CustodyGuard:
    """Gates weight loading on attestation, and serving on a live lease."""

    def __init__(
        self,
        *,
        broker: Broker,
        manifest: WeightCustodyManifest,
        provider: AttestationProvider,
        serving_image_measurement: str | None = None,
        on_lapse: Callable[[str], None] = _terminate,
        max_operations: int | None = None,
        clock: Callable[[], Any] | None = None,
        runtime_signing_key: Any = None,
    ) -> None:
        self._broker = broker
        self._manifest = manifest
        self._provider = provider
        self._on_lapse = on_lapse
        self._max_operations = max_operations
        self._clock = clock
        self._session: EnclaveSession | None = None
        self._signing_key = runtime_signing_key
        self._records: list[RuntimeRecord] = []
        self._lease_id: str | None = None
        self._manifest_hash = canonical_hash(manifest.model_dump(mode="json", exclude_none=True))
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.state = GuardState()

        # Default to the first accepted measurement that is current. A workload
        # that cannot say which serving image it is has nothing to attest to, and
        # inventing one would produce evidence the broker rejects with a message
        # about measurements rather than about configuration.
        if serving_image_measurement is None:
            accepted = manifest.release_policy.required_serving_image.accepted_measurements
            current = [entry for entry in accepted if entry.status.value == "current"]
            if len(current) != 1:
                raise ValueError(
                    f"the manifest lists {len(current)} current serving images, so which "
                    "one this workload is cannot be inferred. Pass "
                    "serving_image_measurement explicitly."
                )
            serving_image_measurement = current[0].measurement
        self._serving_image_measurement = serving_image_measurement

    @property
    def session(self) -> EnclaveSession | None:
        return self._session

    @property
    def records(self) -> tuple[RuntimeRecord, ...]:
        """The signed chain so far. Empty when no signing key was supplied."""
        return tuple(self._records)

    @property
    def runtime_public_key(self) -> str | None:
        """The key a verifier needs. None when the guard is not signing."""
        if self._signing_key is None:
            return None
        return runtime_public_key(self._signing_key)

    def verify_chain(self, *, require_terminal_sequence: bool = False) -> tuple[bool, str]:
        """Verify the guard's own chain.

        ``require_terminal_sequence`` defaults to False, because a running
        server has not lapsed yet and a live chain is legitimately partial.
        Pass True when checking a chain collected after a process ended.
        """
        public_key = self.runtime_public_key
        if public_key is None:
            return False, "no runtime signing key was supplied, so no chain exists"
        return verify_runtime_record_chain(
            self._records, public_key, require_terminal_sequence=require_terminal_sequence
        )

    def _record(self, event: RuntimeEvent, **detail: Any) -> None:
        """Append one signed record. A no-op when the guard is not signing.

        Called with ``self._lock`` already held everywhere it matters, so the
        sequence numbers cannot interleave between the lease thread and a
        request thread. A gap or a repeat would make the chain unverifiable.
        """
        if self._signing_key is None or self._lease_id is None:
            return
        record = sign_runtime_record(
            signing_key=self._signing_key,
            sequence=len(self._records),
            event=event,
            occurred_at=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            weights_hash=self._manifest.weights_hash,
            manifest_hash=self._manifest_hash,
            lease_id=self._lease_id,
            previous=self._records[-1] if self._records else None,
            detail=detail or None,
        )
        self._records.append(record)
        self.state.records_written = len(self._records)

    def _record_terminal(self, reason: str, boundary: RuntimeEvent) -> None:
        """Write the whole terminal sequence, then hand over to on_lapse.

        Order is not a style choice. The SDK's terminal contract is boundary,
        wipe_requested, wipe_completed, process_terminated, and the default
        on_lapse calls os._exit, after which nothing runs. So every record is
        written first and process_terminated attests the intent to terminate.

        A process killed from outside leaves the chain short, which verifies as
        a valid partial chain rather than a terminal one. That is the signal:
        the runtime stopped without completing its own wipe sequence.
        """
        self._record(boundary, reason=reason)
        self._record(RuntimeEvent.wipe_requested, reason=reason)
        if self._session is not None:
            self._session.zeroize()
        self._record(RuntimeEvent.wipe_completed)
        self._record(RuntimeEvent.process_terminated)
        self._on_lapse(reason)

    def acquire(self) -> bytes:
        """Attest, request release, and return the key. Raises rather than degrading.

        The key is returned so the caller can decrypt weights with it. It is
        deliberately not stashed on the guard beyond the session's own buffer:
        one copy is already more than can be erased later, and a second held for
        convenience would be a second copy nobody remembers to drop.
        """
        challenge = self._broker.issue_challenge()
        evidence = self._provider.produce(
            challenge, serving_image_measurement=self._serving_image_measurement
        )
        decision = self._broker.verify_and_release(self._manifest, evidence)
        if not decision.released or decision.key is None:
            self.state.failed_checks = tuple(sorted(c.name for c in decision.failures))
            self.state.last_error = "release refused"
            raise ReleaseRefused(decision)

        self._session = EnclaveSession.from_release(
            self._manifest, decision, max_operations=self._max_operations, now=self._clock
        )
        self._lease_id = lease_id_for(challenge.nonce)
        self.state.acquired = True
        self.state.state = SessionState.holding.value
        self.state.lease_id = self._lease_id
        self._record(
            RuntimeEvent.lease_started,
            cadence=self._manifest.custody.attestation_cadence,
            serving_image=self._serving_image_measurement,
        )
        logger.info(
            "wcm: key released for weights %s, lease cadence %s",
            self._manifest.weights_hash,
            self._manifest.custody.attestation_cadence,
        )
        return decision.key

    def authorize_request(self) -> None:
        """Call once per inference request. Raises ``ServingHalted`` when refused.

        Raising is not by itself the control: a framework can catch it. It exists
        so a caller that wraps requests gets a clean error, while ``on_lapse``
        does the part that cannot be caught.
        """
        with self._lock:
            if self._session is None:
                raise ServingHalted("no key has been acquired; acquire() first")
            try:
                self._session.authorize_operation()
            except KeyWipedError as exc:
                self.state.lapses += 1
                self.state.state = SessionState.wiped.value
                self.state.last_error = str(exc)
                self._record_terminal(f"lease lapsed: {exc}", RuntimeEvent.lapse_detected)
                raise ServingHalted(str(exc)) from exc
            except ReattestationRequired as exc:
                self.state.last_error = str(exc)
                raise ServingHalted(str(exc)) from exc
            self.state.requests_authorized += 1

    def tick(self) -> SessionState:
        """Advance the lease clock once and act on a lapse. Returns the state."""
        with self._lock:
            if self._session is None:
                return SessionState.wiped
            state = self._session.tick()
            self.state.state = state.value
            if state is SessionState.wiped:
                self.state.lapses += 1
                self._record_terminal("lease lapsed while idle", RuntimeEvent.lapse_detected)
            return state

    def renew(self, decision: Any) -> None:
        """Apply a signed KBS renewal decision and record it.

        Kept separate from ``tick`` because a renewal is something the broker
        granted, not something the clock did. ``renewal_succeeded`` is only
        written after ``apply_renewal`` returns, so a rejected renewal leaves no
        record claiming one happened.
        """
        with self._lock:
            if self._session is None:
                raise ServingHalted("no key has been acquired; acquire() first")
            self._session.apply_renewal(self._manifest, decision)
            self.state.state = self._session.state.value
            self._record(RuntimeEvent.renewal_succeeded)

    def revoke(self, reason: str = "revocation received") -> None:
        """Stop serving because the weights were revoked, not because time ran out.

        Records ``revocation_detected`` rather than ``lapse_detected``. Both are
        valid chain boundaries and they mean different things: a lapse is a lease
        nobody renewed, a revocation is an authority withdrawing the release.
        Collapsing them would lose that in the one artifact meant to explain what
        happened.
        """
        with self._lock:
            if self._session is None:
                raise ServingHalted("no key has been acquired; acquire() first")
            self.state.state = SessionState.wiped.value
            self.state.last_error = reason
            self._record_terminal(reason, RuntimeEvent.revocation_detected)

    def start(self, interval_seconds: float | None = None) -> None:
        """Run the lease clock in a daemon thread.

        ``interval_seconds`` defaults to a fifth of the manifest's attestation
        cadence, so a lapse is noticed well inside the window rather than up to a
        full cadence late. A daemon thread on purpose: it must never be the
        reason a halted process stays alive.
        """
        if self._thread is not None:
            raise RuntimeError("lease loop already started")
        if interval_seconds is None:
            interval_seconds = max(
                1.0, parse_cadence(self._manifest.custody.attestation_cadence) / 5
            )
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval_seconds):
                if self.tick() is SessionState.wiped:
                    return

        self._thread = threading.Thread(target=loop, name="wcm-lease", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the lease loop and zeroize the session's own key buffer.

        This is shutdown, not a security boundary. See the module docstring: the
        decrypted weights are not reachable from here.

        Deliberately writes no terminal records. An orderly shutdown is not a
        lapse and not a revocation, and manufacturing a boundary event for one
        would put a wipe-on-lapse story into the chain of every server that was
        simply restarted. The chain ends where serving ended, and verifies as
        partial, which is what happened.
        """
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        with self._lock:
            if self._session is not None:
                self._session.zeroize()
                self.state.state = SessionState.wiped.value

    def __enter__(self) -> "CustodyGuard":
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
