#!/usr/bin/env python3
"""Weight Custody Manifest custody lifecycle -> OpenTelemetry spans and metrics.

A key broker refusing a release, and a runtime wiping a key after a lease lapse,
are the two events an on-call engineer most needs to see and currently cannot.
They surface as an inference service that stopped working. This emits them as
ordinary OTel signals so they land in whatever the deployment already runs.

**Telemetry is not evidence, and this module will not let you confuse them.**
Spans are unsigned. Anything holding the collector endpoint can write one, an
exporter reports what it chose to report, and a dropped span is
indistinguishable from an event that did not happen. Nothing here is a custody
record. When you need an artifact to hand a third party, use the TRACE adapter
in ``integrations/wcm-trace``: it produces a signed record over the same
decision. Use both; they answer different questions.

**The attributes are ours, not upstream conventions.** OpenTelemetry's GenAI
semantic conventions cover model calls and have no vocabulary for weight
custody, key release or lease state. Rather than bend ``gen_ai.*`` attributes
into meanings their authors did not give them, everything here lives under
``wcm.*`` and is listed in ``ATTRIBUTES``. If OTel later defines custody
conventions, this module should adopt them and keep ``wcm.*`` as aliases for a
release or two.

**What never becomes an attribute.** Key material, sealed or otherwise. Weight
bytes. Nonces. The transport public key. Anything a span could carry into a
logging backend that a custody agreement says stays in the enclave. The
exclusions are enumerated in ``NEVER_EXPORTED`` and there is a test that greps
every emitted attribute set for them.

Usage::

    pip install weight-custody-manifest opentelemetry-api

    from wcm_otel import CustodyInstrumentation

    telemetry = CustodyInstrumentation()
    decision = telemetry.observe_release(kbs, manifest, evidence)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Callable, Iterator, Sequence

from wcm import (
    CompositeEvidence,
    KeyBrokerService,
    ReleaseDecision,
    SessionState,
    WeightCustodyManifest,
    canonical_hash,
)

__all__ = [
    "ATTRIBUTES",
    "NEVER_EXPORTED",
    "INSTRUMENTATION_NAME",
    "CustodyInstrumentation",
    "release_attributes",
    "custody_attributes",
]

INSTRUMENTATION_NAME = "agentrust-io/wcm"

#: Every attribute this module emits, with what it means. There is a test
#: asserting nothing is emitted that is not listed here, so an attribute added
#: without a description fails the build rather than shipping undocumented.
ATTRIBUTES = {
    "wcm.manifest.hash": "canonical hash of the manifest the decision was made under",
    "wcm.manifest.version": "manifest_version from the document",
    "wcm.weights.hash": "weights_hash the manifest binds. A digest, not the weights",
    "wcm.builder.identity": "builder.identity from the manifest",
    "wcm.custodian": "custody.custodian from the manifest",
    "wcm.custodian.type": "opaque-hosted or customer-self-custody",
    "wcm.deployment.model": "builder-to-customer or byom-symmetric",
    "wcm.release.released": "whether the key was released",
    "wcm.release.checks.total": "how many checks the broker ran",
    "wcm.release.checks.failed": "how many failed",
    "wcm.release.failed_checks": "names of the failed checks, in sorted order",
    "wcm.release.sealed": "whether the key was sealed to an attested transport key",
    "wcm.evidence.cpu.platform": "platform the CPU quote claimed",
    "wcm.evidence.cpu.verified": "whether the broker cryptographically verified that quote",
    "wcm.evidence.gpu.present": "whether a GPU report accompanied the CPU quote",
    "wcm.evidence.gpu.verified": "whether the broker verified the GPU report",
    "wcm.evidence.attestation_key.id": "VCEK id or platform equivalent, an identifier not a key",
    "wcm.evidence.attestation_key.cache_age_seconds": "staleness of the cached attestation key",
    "wcm.custody.state": "holding or wiped",
    "wcm.custody.operations_used": "operations authorized against this lease",
    "wcm.custody.operations_remaining": "operations left before re-attestation, when capped",
    "wcm.custody.remaining_seconds": "seconds left on the lease",
    "wcm.custody.trusted_time_source": "what the lease deadline is measured against",
}

#: Never exported, in any signal, for any reason.
NEVER_EXPORTED = (
    "key",
    "sealed_key",
    "transport_public_key",
    "nonce",
    "nonce_echo",
    "quote_b64",
    "readback_hash",
    "private",
    "secret",
)

_RELEASE_SPAN = "wcm.release"
_CUSTODY_SPAN = "wcm.custody"


def _tracer(provided: Any) -> Any:
    if provided is not None:
        return provided
    try:
        from opentelemetry import trace
    except ModuleNotFoundError:
        return None
    return trace.get_tracer(INSTRUMENTATION_NAME)


def _meter(provided: Any) -> Any:
    if provided is not None:
        return provided
    try:
        from opentelemetry import metrics
    except ModuleNotFoundError:
        return None
    return metrics.get_meter(INSTRUMENTATION_NAME)


def _manifest_attributes(manifest: WeightCustodyManifest) -> dict[str, Any]:
    return {
        "wcm.manifest.hash": canonical_hash(manifest.model_dump(mode="json", exclude_none=True)),
        "wcm.manifest.version": manifest.manifest_version,
        "wcm.weights.hash": manifest.weights_hash,
        "wcm.builder.identity": manifest.builder.identity,
        "wcm.custodian": manifest.custody.custodian,
        "wcm.custodian.type": manifest.custody.custodian_type.value,
        "wcm.deployment.model": manifest.deployment_model.value,
    }


def release_attributes(
    manifest: WeightCustodyManifest,
    decision: ReleaseDecision,
    evidence: CompositeEvidence | None = None,
) -> dict[str, Any]:
    """Attributes for one release decision.

    ``wcm.evidence.cpu.platform`` is what the quote *claimed*;
    ``wcm.evidence.cpu.verified`` is whether the broker checked it. Both are
    exported because a dashboard showing only the first would present a claim as
    a fact, and the gap between them is exactly what an operator needs to see
    when a fleet starts failing closed.
    """
    checks = list(decision.checks)
    failed = sorted(check.name for check in decision.failures)
    by_name = {check.name: check.passed for check in checks}

    attributes: dict[str, Any] = {
        **_manifest_attributes(manifest),
        "wcm.release.released": decision.released,
        "wcm.release.checks.total": len(checks),
        "wcm.release.checks.failed": len(failed),
        "wcm.release.sealed": decision.sealed_key is not None,
    }
    if failed:
        attributes["wcm.release.failed_checks"] = failed
    if "cpu_quote_verified" in by_name:
        attributes["wcm.evidence.cpu.verified"] = by_name["cpu_quote_verified"]
    if "gpu_report_verified" in by_name:
        attributes["wcm.evidence.gpu.verified"] = by_name["gpu_report_verified"]
    if evidence is not None:
        attributes["wcm.evidence.cpu.platform"] = evidence.cpu.platform
        attributes["wcm.evidence.gpu.present"] = evidence.gpu is not None
        attributes["wcm.evidence.attestation_key.id"] = evidence.cpu.attestation_key_id
        attributes["wcm.evidence.attestation_key.cache_age_seconds"] = (
            evidence.cpu.attestation_key_cache_age_seconds
        )
    return attributes


def custody_attributes(manifest: WeightCustodyManifest, session: Any) -> dict[str, Any]:
    """Attributes for a Layer 3 session at a point in time.

    Reads the ``EnclaveSession`` accessors rather than its internals, so a
    session implementation that is not the reference one works as long as it
    presents the same surface.
    """
    attributes: dict[str, Any] = {
        **_manifest_attributes(manifest),
        "wcm.custody.state": session.state.value
        if isinstance(session.state, SessionState)
        else str(session.state),
        "wcm.custody.operations_used": session.operations_used,
        "wcm.custody.trusted_time_source": manifest.release_policy.trusted_time_source.value,
    }
    # operations_remaining() and remaining_seconds() are methods on
    # EnclaveSession while state and operations_used are properties. Calling them
    # explicitly rather than reading an attribute keeps a bound method from being
    # stringified into a span, which is how "operations_remaining" ends up in a
    # dashboard as "<bound method ...>".
    remaining_operations = session.operations_remaining()
    if remaining_operations is not None:
        attributes["wcm.custody.operations_remaining"] = remaining_operations
    remaining = session.remaining_seconds()
    if remaining is not None:
        attributes["wcm.custody.remaining_seconds"] = remaining
    return attributes


class CustodyInstrumentation:
    """Emits custody spans and metrics, and works with OTel absent.

    Every method is a no-op when ``opentelemetry`` is not installed, so a library
    that instruments itself with this does not force the dependency on its users.
    The attribute builders stay pure functions either way, which is why the tests
    can assert on exactly what would be exported without a collector.
    """

    def __init__(self, *, tracer: Any = None, meter: Any = None) -> None:
        self._tracer = _tracer(tracer)
        self._meter = _meter(meter)
        self._release_counter = None
        self._wipe_counter = None
        self._release_duration = None
        if self._meter is not None:
            self._release_counter = self._meter.create_counter(
                "wcm.release.decisions",
                unit="{decision}",
                description="Key release decisions, by outcome.",
            )
            self._wipe_counter = self._meter.create_counter(
                "wcm.custody.wipes",
                unit="{wipe}",
                description="Sessions that reached the wiped state.",
            )
            self._release_duration = self._meter.create_histogram(
                "wcm.release.duration",
                unit="s",
                description="Wall-clock time the broker took to reach a decision.",
            )

    def record_release(
        self,
        manifest: WeightCustodyManifest,
        decision: ReleaseDecision,
        evidence: CompositeEvidence | None = None,
        *,
        duration_seconds: float | None = None,
    ) -> ReleaseDecision:
        """Emit a span and metrics for a decision that already happened."""
        attributes = release_attributes(manifest, decision, evidence)
        _assert_safe(attributes)

        if self._tracer is not None:
            with self._tracer.start_as_current_span(_RELEASE_SPAN) as span:
                span.set_attributes(_flatten(attributes))
                if not decision.released:
                    # A refusal is the gate working. It is recorded as an error
                    # span because it is what an operator is looking for, and
                    # marked with the check names so the dashboard does not
                    # require reading the message.
                    _set_error(span, "release refused: " + ", ".join(
                        sorted(check.name for check in decision.failures)
                    ))
        if self._release_counter is not None:
            self._release_counter.add(1, _metric_attributes(attributes))
        if self._release_duration is not None and duration_seconds is not None:
            self._release_duration.record(duration_seconds, _metric_attributes(attributes))
        return decision

    def observe_release(
        self,
        broker: KeyBrokerService,
        manifest: WeightCustodyManifest,
        evidence: CompositeEvidence,
    ) -> ReleaseDecision:
        """Call the broker, time it, and emit the signals. Returns the decision.

        The decision is returned unchanged and unwrapped. Telemetry that could
        alter a release decision would be a security control masquerading as
        observability, and this is not one.
        """
        started = time.perf_counter()
        decision = broker.verify_and_release(manifest, evidence)
        return self.record_release(
            manifest, decision, evidence, duration_seconds=time.perf_counter() - started
        )

    def record_custody(self, manifest: WeightCustodyManifest, session: Any) -> None:
        """Emit a point-in-time custody span, and count a wipe when one happened."""
        attributes = custody_attributes(manifest, session)
        _assert_safe(attributes)

        if self._tracer is not None:
            with self._tracer.start_as_current_span(_CUSTODY_SPAN) as span:
                span.set_attributes(_flatten(attributes))
                if attributes["wcm.custody.state"] == SessionState.wiped.value:
                    _set_error(span, "key wiped: the session can no longer serve these weights")
        if self._wipe_counter is not None and attributes["wcm.custody.state"] == (
            SessionState.wiped.value
        ):
            self._wipe_counter.add(1, _metric_attributes(attributes))


def _flatten(attributes: dict[str, Any]) -> dict[str, Any]:
    """OTel attribute values are scalars or homogeneous sequences of scalars."""
    flattened: dict[str, Any] = {}
    for key, value in attributes.items():
        if isinstance(value, (list, tuple)):
            flattened[key] = tuple(str(item) for item in value)
        else:
            flattened[key] = value
    return flattened


def _metric_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """The low-cardinality subset. Metrics keyed by manifest hash would explode.

    ``wcm.weights.hash`` and ``wcm.manifest.hash`` are high-cardinality by
    design: they change whenever anything changes. Putting them on a counter
    would create one time series per manifest revision, which is the classic way
    to take a metrics backend down. They stay on spans, where cardinality is not
    a billing event.
    """
    keep = (
        "wcm.release.released",
        "wcm.custody.state",
        "wcm.builder.identity",
        "wcm.custodian.type",
        "wcm.deployment.model",
        "wcm.evidence.cpu.platform",
        "wcm.evidence.cpu.verified",
    )
    return {key: attributes[key] for key in keep if key in attributes}


def _assert_safe(attributes: dict[str, Any]) -> None:
    """Refuse to emit anything named after key material or raw evidence.

    A belt-and-braces check on the attribute *names*, not the values, because the
    realistic failure is somebody adding an attribute in good faith rather than
    smuggling a key out deliberately.
    """
    for key in attributes:
        lowered = key.lower()
        for banned in NEVER_EXPORTED:
            if lowered.endswith(f".{banned}") or lowered.endswith(f"_{banned}"):
                raise ValueError(
                    f"attribute {key!r} names {banned!r}, which is on NEVER_EXPORTED. "
                    "Telemetry backends are not custody boundaries."
                )
        if key not in ATTRIBUTES:
            raise ValueError(
                f"attribute {key!r} is not described in ATTRIBUTES. Add it there with "
                "what it means before emitting it; an undocumented attribute in a "
                "dashboard is a field nobody can interpret under pressure."
            )


def _set_error(span: Any, message: str) -> None:
    try:
        from opentelemetry.trace import Status, StatusCode
    except ModuleNotFoundError:  # pragma: no cover - only when OTel is absent
        return
    span.set_status(Status(StatusCode.ERROR, message))


def main(argv: Sequence[str] | None = None) -> int:
    """Print the attributes that would be exported for a manifest, without a collector."""
    parser = argparse.ArgumentParser(description="Show WCM OpenTelemetry attributes")
    parser.add_argument("manifest", type=argparse.FileType("r", encoding="utf-8"))
    parser.add_argument("--describe", action="store_true", help="print the attribute reference")
    args = parser.parse_args(argv)

    if args.describe:
        print(json.dumps(ATTRIBUTES, indent=2, sort_keys=True))
        return 0

    manifest = WeightCustodyManifest.model_validate_json(args.manifest.read())
    print(json.dumps(_manifest_attributes(manifest), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
