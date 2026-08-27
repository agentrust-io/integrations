"""Tests for the serving custody guard.

The lapse handler is injected in every test. The default one calls os._exit,
which is correct in production and would take the test runner with it, and the
fact that it cannot be caught is exactly the property under test elsewhere.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import (  # noqa: E402
    CheckResult,
    Challenge,
    CompositeEvidence,
    CpuQuote,
    ReleaseDecision,
    RuntimeEvent,
    SessionState,
    SoftwareProvider,
    WeightCustodyManifest,
    generate_ed25519,
    verify_runtime_record_chain,
)

from wcm_serving_guard import (  # noqa: E402
    CustodyGuard,
    ReleaseRefused,
    ServingHalted,
    lease_id_for,
)

WEIGHTS = "sha256:" + "4a1c" * 16
CURRENT = "sha256:" + "5e2d" * 16
OTHER_CURRENT = "sha256:" + "6f3e" * 16
KEY = b"k" * 32


def make_manifest(*, cadence: str = "5m", measurements: list[dict] | None = None):
    accepted = measurements or [{"measurement": CURRENT, "status": "current"}]
    return WeightCustodyManifest.model_validate(
        {
            "manifest_version": "0.1",
            "weights_hash": WEIGHTS,
            "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
            "release_terms": {
                "license": "customer-deployment-agreement-ref:CDA-2026-0091",
                "permitted_derivatives": "fine-tune-only",
                "permitted_environments": ["attested-enclave"],
            },
            "release_policy": {
                "required_assurance_tier": "hardware-attested",
                "physical_hardening": "not-required",
                "trusted_time_source": "secure-tsc",
                "memory_fingerprint_challenge": "not-required",
                "required_hw_platform": ["amd-sev-snp"],
                "tenancy": "shared",
                "required_serving_image": {
                    "signer": "ed25519:builder-key",
                    "release_rule": "prefer-current",
                    "accepted_measurements": accepted,
                },
                "key_release_mode": "attestation-gated",
                "replay_protection": "kbs-nonce-required",
                "revocation_authority": "builder-and-opaque-joint",
            },
            "custody": {
                "custodian": "example-custodian",
                "custodian_type": "opaque-hosted",
                "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs"},
                "enclave_id": "did:example:enclave-04",
                "attestation_cadence": cadence,
            },
            "signatures": [],
        }
    )


class FakeBroker:
    def __init__(self, *, released: bool = True, failures: tuple[str, ...] = ()) -> None:
        self.released = released
        self.failures = failures
        self.releases = 0
        self.challenges = 0

    def issue_challenge(self) -> Challenge:
        self.challenges += 1
        now = dt.datetime.now(dt.timezone.utc)
        return Challenge(nonce="a" * 64, issued_at=now, expires_at=now + dt.timedelta(minutes=5))

    def verify_and_release(self, manifest, evidence) -> ReleaseDecision:  # noqa: ANN001
        self.releases += 1
        checks = [CheckResult("nonce_fresh", True)]
        checks += [CheckResult(name, False) for name in self.failures]
        return ReleaseDecision(
            released=self.released, key=KEY if self.released else None, checks=checks
        )


class Clock:
    """An injectable clock, so a lease can lapse without anything sleeping."""

    def __init__(self) -> None:
        self.now = dt.datetime(2026, 8, 27, tzinfo=dt.timezone.utc)

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += dt.timedelta(seconds=seconds)


def guard(**kwargs: object) -> tuple[CustodyGuard, list[str]]:
    lapses: list[str] = []
    base: dict = {
        "broker": FakeBroker(),
        "manifest": make_manifest(),
        "provider": SoftwareProvider(),
        "on_lapse": lapses.append,
    }
    base.update(kwargs)
    return CustodyGuard(**base), lapses  # type: ignore[arg-type]


def test_acquire_returns_the_key_and_starts_a_session() -> None:
    subject, _ = guard()

    key = subject.acquire()

    assert key == KEY
    assert subject.state.acquired
    assert subject.session is not None
    assert subject.state.state == SessionState.holding.value


def test_refused_release_raises_with_the_failed_checks() -> None:
    subject, _ = guard(broker=FakeBroker(released=False, failures=("serving_image", "gpu")))

    with pytest.raises(ReleaseRefused) as exc:
        subject.acquire()

    assert exc.value.failed_checks == ["gpu", "serving_image"]
    assert not subject.state.acquired
    assert subject.state.failed_checks == ("gpu", "serving_image")


def test_the_guard_does_not_keep_a_second_copy_of_the_key() -> None:
    """One copy is already more than can be erased; a convenience copy is worse."""
    subject, _ = guard()

    subject.acquire()

    assert not any(
        isinstance(value, (bytes, bytearray)) and bytes(value) == KEY
        for value in vars(subject).values()
    )


def test_authorize_request_counts_and_permits_while_holding() -> None:
    subject, _ = guard()
    subject.acquire()

    subject.authorize_request()
    subject.authorize_request()

    assert subject.state.requests_authorized == 2


def test_authorize_request_before_acquire_is_refused() -> None:
    subject, _ = guard()

    with pytest.raises(ServingHalted, match="acquire"):
        subject.authorize_request()


def test_lapsed_lease_halts_serving_and_calls_on_lapse() -> None:
    clock = Clock()
    subject, lapses = guard(manifest=make_manifest(cadence="5m"), clock=clock)
    subject.acquire()
    subject.authorize_request()

    clock.advance(400)

    with pytest.raises(ServingHalted):
        subject.authorize_request()
    assert lapses and "lease lapsed" in lapses[0]
    assert subject.state.lapses == 1
    assert subject.state.state == SessionState.wiped.value


def test_operation_budget_exhaustion_asks_for_reattestation_not_a_wipe() -> None:
    """Different failure, different meaning: the key is still held."""
    subject, lapses = guard(max_operations=2)
    subject.acquire()
    subject.authorize_request()
    subject.authorize_request()

    with pytest.raises(ServingHalted, match="re-attest"):
        subject.authorize_request()
    assert lapses == [], "an exhausted budget is not a lapse and must not halt the process"
    assert subject.state.state == SessionState.holding.value


def test_tick_detects_a_lapse_while_idle() -> None:
    clock = Clock()
    subject, lapses = guard(manifest=make_manifest(cadence="5m"), clock=clock)
    subject.acquire()

    clock.advance(400)

    assert subject.tick() is SessionState.wiped
    assert lapses and "while idle" in lapses[0]


def test_tick_before_acquire_reports_wiped_without_calling_on_lapse() -> None:
    subject, lapses = guard()

    assert subject.tick() is SessionState.wiped
    assert lapses == []


def test_lease_loop_runs_and_stops() -> None:
    subject, _ = guard()
    subject.acquire()

    subject.start(interval_seconds=0.01)
    assert subject._thread is not None and subject._thread.daemon
    subject.stop()

    assert subject._thread is None


def test_lease_loop_cannot_be_started_twice() -> None:
    subject, _ = guard()
    subject.acquire()
    subject.start(interval_seconds=10)

    try:
        with pytest.raises(RuntimeError, match="already started"):
            subject.start()
    finally:
        subject.stop()


def test_default_interval_is_a_fraction_of_the_cadence() -> None:
    """A lapse should be noticed inside the window, not up to a cadence late."""
    subject, _ = guard(manifest=make_manifest(cadence="5m"))
    subject.acquire()

    subject.start()
    try:
        assert subject._thread is not None
    finally:
        subject.stop()


def test_stop_zeroizes_the_session_buffer() -> None:
    subject, _ = guard()
    subject.acquire()

    subject.stop()

    assert subject.session is not None and subject.session.is_wiped


def test_context_manager_stops_on_exit() -> None:
    subject, _ = guard()
    with subject:
        subject.acquire()

    assert subject.session is not None and subject.session.is_wiped


def test_serving_image_is_inferred_when_exactly_one_is_current() -> None:
    subject, _ = guard()

    assert subject._serving_image_measurement == CURRENT


def test_ambiguous_current_images_must_be_disambiguated() -> None:
    with pytest.raises(ValueError, match="cannot be inferred"):
        guard(
            manifest=make_manifest(
                measurements=[
                    {"measurement": CURRENT, "status": "current"},
                    {"measurement": OTHER_CURRENT, "status": "current"},
                ]
            )
        )


def test_explicit_serving_image_overrides_inference() -> None:
    subject, _ = guard(serving_image_measurement=OTHER_CURRENT)

    assert subject._serving_image_measurement == OTHER_CURRENT


def test_no_current_image_is_refused_rather_than_guessed() -> None:
    with pytest.raises(ValueError, match="cannot be inferred"):
        guard(
            manifest=make_manifest(
                measurements=[{"measurement": CURRENT, "status": "retiring",
                               "retire_after": "2026-12-01T00:00:00Z"}]
            )
        )


def test_evidence_is_produced_over_the_broker_challenge() -> None:
    broker = FakeBroker()
    subject, _ = guard(broker=broker)

    subject.acquire()

    assert broker.challenges == 1
    assert broker.releases == 1


def test_state_report_carries_no_key_material() -> None:
    subject, _ = guard()
    subject.acquire()
    subject.authorize_request()

    rendered = repr(subject.state)

    assert "k" * 32 not in rendered
    assert subject.state.requests_authorized == 1


def test_a_custom_broker_only_needs_the_protocol_surface() -> None:
    """The Protocol exists so a remote transport needs no subclassing."""

    class Remote:
        def issue_challenge(self):
            now = dt.datetime.now(dt.timezone.utc)
            return Challenge(nonce="b" * 64, issued_at=now, expires_at=now + dt.timedelta(minutes=1))

        def verify_and_release(self, manifest, evidence):  # noqa: ANN001
            assert isinstance(evidence, CompositeEvidence)
            assert isinstance(evidence.cpu, CpuQuote)
            return ReleaseDecision(released=True, key=KEY, checks=[CheckResult("remote", True)])

    subject, _ = guard(broker=Remote())

    assert subject.acquire() == KEY


# --------------------------------------------------------------------------
# Signed runtime records (weight-custody-manifest 0.27.0)
# --------------------------------------------------------------------------


def signing_guard(**kwargs: object):
    """A guard that signs, plus the keypair a verifier would hold."""
    keypair = generate_ed25519()
    subject, lapses = guard(runtime_signing_key=keypair.private_key, **kwargs)
    return subject, keypair, lapses


def events(subject: CustodyGuard) -> list[str]:
    return [record.event for record in subject.records]


def test_sdk_requires_a_terminal_chain_by_default_and_the_guard_does_not() -> None:
    """A difference worth pinning, since both defaults are deliberate.

    The SDK's caller is usually auditing a finished lease. The guard's caller is
    usually a running server, which has legitimately not lapsed.
    """
    import inspect

    from wcm import verify_runtime_record_chain as sdk

    assert inspect.signature(sdk).parameters["require_terminal_sequence"].default is True
    assert (
        inspect.signature(CustodyGuard.verify_chain)
        .parameters["require_terminal_sequence"]
        .default
        is False
    )


def test_no_signing_key_means_no_chain() -> None:
    """The receipts are opt-in; nothing else changes without a key."""
    subject, _ = guard()
    subject.acquire()
    subject.authorize_request()

    assert subject.records == ()
    assert subject.runtime_public_key is None
    assert subject.state.records_written == 0
    assert subject.verify_chain()[0] is False


def test_acquire_opens_the_chain_with_lease_started() -> None:
    subject, keypair, _ = signing_guard()

    subject.acquire()

    assert events(subject) == [RuntimeEvent.lease_started.value]
    assert subject.records[0].sequence == 0
    assert subject.records[0].previous_record_hash is None
    assert subject.records[0].verify(subject.runtime_public_key)


def test_lease_id_is_derived_from_the_challenge_not_the_raw_nonce() -> None:
    """A single-use replay value should not outlive its challenge in an artifact."""
    subject, _, _ = signing_guard()

    subject.acquire()

    assert subject.state.lease_id == lease_id_for("a" * 64)
    assert "a" * 64 not in str(subject.records[0])


def test_records_bind_the_manifest_and_the_weights() -> None:
    subject, _, _ = signing_guard()

    subject.acquire()

    assert subject.records[0].weights_hash == WEIGHTS
    assert len(subject.records[0].manifest_hash) > 0


def test_live_chain_verifies_as_partial_not_terminal() -> None:
    """A server that is still running has legitimately not lapsed."""
    subject, _, _ = signing_guard()
    subject.acquire()

    assert subject.verify_chain()[0] is True
    assert subject.verify_chain(require_terminal_sequence=True)[0] is False


def test_lapse_writes_the_complete_terminal_sequence() -> None:
    clock = Clock()
    subject, keypair, lapses = signing_guard(manifest=make_manifest(cadence="5m"), clock=clock)
    subject.acquire()
    subject.authorize_request()
    clock.advance(400)

    with pytest.raises(ServingHalted):
        subject.authorize_request()

    assert events(subject) == [
        RuntimeEvent.lease_started.value,
        RuntimeEvent.lapse_detected.value,
        RuntimeEvent.wipe_requested.value,
        RuntimeEvent.wipe_completed.value,
        RuntimeEvent.process_terminated.value,
    ]
    ok, reason = subject.verify_chain(require_terminal_sequence=True)
    assert ok, reason


def test_every_record_is_written_before_on_lapse_runs() -> None:
    """The default on_lapse calls os._exit; anything after it never happens."""
    clock = Clock()
    subject, _, _ = signing_guard(manifest=make_manifest(cadence="5m"), clock=clock)
    seen: list[int] = []
    subject._on_lapse = lambda reason: seen.append(len(subject.records))
    subject.acquire()
    clock.advance(400)

    subject.tick()

    assert seen == [5], "on_lapse must observe the finished chain, not a partial one"


def test_wipe_completed_follows_an_actual_zeroize() -> None:
    clock = Clock()
    subject, _, _ = signing_guard(manifest=make_manifest(cadence="5m"), clock=clock)
    subject.acquire()
    clock.advance(400)

    subject.tick()

    assert subject.session is not None and subject.session.is_wiped


def test_revocation_is_a_different_boundary_from_a_lapse() -> None:
    """A lease nobody renewed and an authority withdrawing release are not the same."""
    subject, _, _ = signing_guard()
    subject.acquire()

    subject.revoke("builder revoked the release")

    assert events(subject)[1] == RuntimeEvent.revocation_detected.value
    assert RuntimeEvent.lapse_detected.value not in events(subject)
    ok, reason = subject.verify_chain(require_terminal_sequence=True)
    assert ok, reason


def test_renewals_appear_between_start_and_boundary() -> None:
    subject, _, _ = signing_guard()
    subject.acquire()

    applied = []
    subject._session.apply_renewal = lambda manifest, decision: applied.append(decision)
    subject.renew(object())
    subject.renew(object())
    subject.revoke()

    assert events(subject) == [
        RuntimeEvent.lease_started.value,
        RuntimeEvent.renewal_succeeded.value,
        RuntimeEvent.renewal_succeeded.value,
        RuntimeEvent.revocation_detected.value,
        RuntimeEvent.wipe_requested.value,
        RuntimeEvent.wipe_completed.value,
        RuntimeEvent.process_terminated.value,
    ]
    assert len(applied) == 2
    ok, reason = subject.verify_chain(require_terminal_sequence=True)
    assert ok, reason


def test_a_rejected_renewal_writes_no_record() -> None:
    subject, _, _ = signing_guard()
    subject.acquire()

    def refuse(manifest, decision):  # noqa: ANN001
        raise ValueError("renewal decision did not verify")

    subject._session.apply_renewal = refuse

    with pytest.raises(ValueError):
        subject.renew(object())

    assert events(subject) == [RuntimeEvent.lease_started.value]


def test_ordinary_shutdown_writes_no_terminal_records() -> None:
    """A restart is not a lapse; manufacturing a boundary would fake one."""
    subject, _, _ = signing_guard()
    subject.acquire()

    subject.stop()

    assert events(subject) == [RuntimeEvent.lease_started.value]
    assert subject.verify_chain(require_terminal_sequence=True)[0] is False
    assert subject.verify_chain()[0] is True


def test_a_truncated_chain_is_partial_and_says_so() -> None:
    """What a SIGKILL leaves behind. The absence is the signal."""
    subject, _, _ = signing_guard()
    subject.acquire()
    subject.revoke()
    killed = subject.records[:3]

    # The SDK requires a terminal chain by default; CustodyGuard.verify_chain
    # deliberately does not, because a running server has not lapsed yet.
    assert (
        verify_runtime_record_chain(
            killed, subject.runtime_public_key, require_terminal_sequence=False
        )[0]
        is True
    )
    assert (
        verify_runtime_record_chain(
            killed, subject.runtime_public_key, require_terminal_sequence=True
        )[0]
        is False
    )


def test_a_removed_middle_record_breaks_the_chain() -> None:
    subject, _, _ = signing_guard()
    subject.acquire()
    subject.revoke()
    tampered = [subject.records[0], *subject.records[2:]]

    ok, reason = verify_runtime_record_chain(
        tampered, subject.runtime_public_key, require_terminal_sequence=False
    )

    assert not ok, "a gap must fail structurally, not only on the terminal shape"
    assert "contiguous" in reason or "previous hash" in reason


def test_another_key_cannot_verify_the_chain() -> None:
    from wcm import runtime_public_key

    subject, _, _ = signing_guard()
    subject.acquire()
    subject.revoke()
    other = generate_ed25519()

    ok, _ = verify_runtime_record_chain(
        subject.records, runtime_public_key(other.private_key), require_terminal_sequence=True
    )

    assert not ok


def test_records_written_is_reported_in_state() -> None:
    subject, _, _ = signing_guard()
    subject.acquire()
    subject.revoke()

    assert subject.state.records_written == 5
