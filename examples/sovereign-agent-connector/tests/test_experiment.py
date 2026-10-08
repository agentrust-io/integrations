from __future__ import annotations

import copy

import pytest
from ca2a_runtime.errors import CA2AError

from agentrust_auc import BundleError, build_experiment, verify_bundle


def test_allowed_route_dispatches_and_forbidden_route_does_not() -> None:
    calls: list[str] = []
    result = build_experiment(lambda action: calls.append(action["action_id"]))

    assert calls == ["urn:uuid:action-allowed-001"]
    assert result.dispatched == ("urn:uuid:action-allowed-001",)
    assert [receipt["decision"] for receipt in result.bundle["receipts"]] == [
        "allow",
        "deny",
    ]
    assert result.bundle["receipts"][1]["dispatch_state"] == "not_dispatched"
    verify_bundle(result.bundle, result.trust_anchors)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda bundle: bundle["agreement"]["odrl"]["permission"][0]["constraints"][
                "jurisdictions"
            ].append("US"),
            "signature",
        ),
        (
            lambda bundle: bundle["delegation_chain"][1]["scope"].append("patient:export"),
            "scope exceeds parent grant|signature",
        ),
        (
            lambda bundle: bundle["appraisal"].update({"workload_key": "00" * 32}),
            "signature",
        ),
        (
            lambda bundle: bundle["receipts"][1].update({"dispatch_state": "dispatched"}),
            "signature|decision",
        ),
        (
            lambda bundle: bundle["receipts"][1].update({"boundaries": ["agreement"]}),
            "signature|incomplete",
        ),
        (
            lambda bundle: bundle["registry"]["proofs"][1].update(
                {"audit_path": ["sha256:" + "00" * 32]}
            ),
            "not included",
        ),
    ],
)
def test_bundle_fails_closed_on_tampering(mutation, message: str) -> None:
    result = build_experiment()
    bundle = copy.deepcopy(result.bundle)
    mutation(bundle)
    with pytest.raises((BundleError, CA2AError, ValueError), match=message):
        verify_bundle(bundle, result.trust_anchors)


def test_missing_receipt_fails_boundary_completeness() -> None:
    result = build_experiment()
    bundle = copy.deepcopy(result.bundle)
    bundle["receipts"].pop()
    with pytest.raises(BundleError, match="exactly two"):
        verify_bundle(bundle, result.trust_anchors)


def test_internally_consistent_bundle_is_rejected_under_another_trust_domain() -> None:
    trusted = build_experiment()
    attacker = build_experiment()

    with pytest.raises(BundleError, match="out-of-band trust anchors"):
        verify_bundle(attacker.bundle, trusted.trust_anchors)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda bundle: bundle["delegation_chain"][0].update({"scope": ["other:scope"]}),
        lambda bundle: bundle["registry"].update({"root": "sha256:zz"}),
        lambda bundle: bundle["receipts"].__setitem__(0, "not-a-receipt"),
        lambda bundle: bundle["appraisal"].update({"evaluated_at": 10**30}),
    ],
)
def test_malformed_bundle_raises_only_bundle_error(mutation) -> None:
    result = build_experiment()
    bundle = copy.deepcopy(result.bundle)
    mutation(bundle)
    with pytest.raises(BundleError):
        verify_bundle(bundle, result.trust_anchors)
