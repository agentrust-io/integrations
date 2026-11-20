"""Shared fixtures for the WIMSE CTA MCP guard tests. TEST keys only."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import time
from typing import Any

import cta_trace_guard as g
import cta_trace_verify as v
import pytest
from agentrust_trace import key_to_jwk, sign_record
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NOW = 1_800_000_000

TOOL = "delete_demo_marker"
READ_TOOL = "read_inbox"
CONFIG_TOOL = "read_config"
UNPINNED_TOOL = "unpinned_tool"
ARGS = {"path": "marker.txt"}

HARNESS = "urn:wimse-cta:integration:cta-trace-test-harness"
ARTIFACT_STORE = "urn:wimse-cta:integration:cta-trace-test-artifact-store"
APPROVER = "urn:wimse-cta:integration:cta-trace-test-policy-engine"
OBSERVER = "cta-trace-test-observer"


def _test_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"cta-trace-test/{label}".encode()).digest())


BRIDGE_KEY = _test_key("bridge-key")
RECORD_KEY = _test_key("trace-record-key")
POLICY_KEY = _test_key("policy-engine-key")
OTHER_KEY = _test_key("some-other-key")


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


POLICY_KID = v.key_id(raw_public(POLICY_KEY))
POLICY = {
    "profile": "cta-gate-policy/v1",
    "step_up_key_id": POLICY_KID,
    "tools": {
        TOOL: {"effect_class": "STATE_MUTATING", "output_trust": "trusted"},
        READ_TOOL: {"effect_class": "READ_ONLY", "output_trust": "untrusted"},
        CONFIG_TOOL: {"effect_class": "READ_ONLY", "output_trust": "trusted"},
    },
}
POLICY_BYTES = (json.dumps(POLICY, indent=2) + "\n").encode("utf-8")


def policy_bytes(**changes: Any) -> bytes:
    return (json.dumps({**POLICY, **changes}, indent=2) + "\n").encode("utf-8")


class Clock:
    def __init__(self, t: Any = NOW) -> None:
        self.t = t

    def __call__(self) -> Any:
        return self.t


def seq_clock(values):
    """Return each value once, then the last value forever."""
    it = iter(values)
    last = {"v": values[-1]}

    def _clock():
        try:
            last["v"] = next(it)
        except StopIteration:
            pass
        return last["v"]

    return _clock


def public_policy_jwk() -> dict[str, Any]:
    return key_to_jwk(POLICY_KEY)


def make_config(**changes: Any) -> g.CtaConfig:
    config = g.CtaConfig(
        authorizer=HARNESS,
        bridge_key=BRIDGE_KEY,
        record_key=RECORD_KEY,
        policy_engine_jwk=public_policy_jwk(),
        policy_bundle=POLICY_BYTES,
        model_provider="wimse-cta-test",
        model_id="deterministic-tool-calling-model-v1",
        data_class="public",
        workload_digest="sha256:" + hashlib.sha256(b"cta-trace-test").hexdigest(),
        resolver=ARTIFACT_STORE,
    )
    return dataclasses.replace(config, **changes)


def make_observe(
    request_id: str, *, tool_name: str = TOOL, args: Any = None, count: Any = 1,
    observed_at: Any = NOW, verdict: str = "established", mutate: Any = None,
):
    """An observer that returns a document naming the exact call. `mutate` edits it."""
    call_args = ARGS if args is None else args

    def observe(result: Any) -> g.Observation:
        document = {
            "observation": {
                "request_id": request_id, "tool_name": tool_name,
                "args_digest": v.digest_jcs(call_args), "tool_call_count": count,
            },
            "observer": OBSERVER,
            "observed_at": int(time.time()) if observed_at == "now" else observed_at,
        }
        if mutate is not None:
            mutate(document)
        return g.Observation(verdict=verdict, document=document, response_projection=result)

    return observe


@dataclasses.dataclass
class Run:
    harness: Any
    outcome: g.CtaOutcome

    @property
    def guard(self) -> g.CtaGuard:
        return self.harness.guard


class Harness:
    """A guard with a fixed clock, a counting tool, and receipt/observer builders."""

    def __init__(self, clock: Any = None, **config_changes: Any) -> None:
        self.clock = Clock() if clock is None else clock
        self.guard = g.CtaGuard(make_config(**config_changes), clock=self.clock)
        self.calls: list[dict] = []

    def tool(self, **kwargs: Any) -> dict:
        self.calls.append(kwargs)
        return {"ok": True}

    def receipt(
        self, *, session: str = "s1", request: str = "r1", tool_name: str = TOOL, args: Any = None,
        iat: Any = NOW, exp: Any = NOW + 300, key: Ed25519PrivateKey = POLICY_KEY,
        mutate: Any = None, **overrides: Any,
    ) -> dict:
        body = {
            "receipt_id": f"receipt-{request}", "session_id": session, "request_id": request,
            "tool_name": tool_name, "args_digest": v.digest_jcs(ARGS if args is None else args),
            "approver": APPROVER, "kid": POLICY_KID, "iat": iat, "exp": exp,
        }
        body.update(overrides)
        if mutate is not None:
            mutate(body)
        return g.sign_envelope(v.RECEIPT_PROFILE, "receipt", body, key)

    def run(
        self, *, session: str = "s1", request: str = "r1", tool_name: str = TOOL, args: Any = None,
        receipt: Any = None, observe: Any = None, fn: Any = None, **kwargs: Any,
    ) -> g.CtaOutcome:
        call_args = dict(ARGS) if args is None else args
        return self.guard.run(
            session_id=session, request_id=request, tool_name=tool_name,
            tool_fn=fn or self.tool, arguments=call_args,
            observe=observe or make_observe(request, tool_name=tool_name, args=call_args),
            step_up_receipt=receipt, **kwargs,
        )


@pytest.fixture
def harness() -> Harness:
    return Harness()


@pytest.fixture
def trusted_run() -> Run:
    """A STATE_MUTATING call in a TRUSTED_ONLY session that emitted a record."""
    h = Harness()
    outcome = h.run()
    assert outcome.status == "record-emitted", (outcome.status, outcome.reason, outcome.detail)
    return Run(h, outcome)


@pytest.fixture
def stepup_run() -> Run:
    """A STATE_MUTATING call in a tainted session, allowed by a StepUpReceipt, with a record."""
    h = Harness()
    h.guard.ingest_untrusted("s1")
    outcome = h.run(receipt=h.receipt())
    assert outcome.status == "record-emitted", (outcome.status, outcome.reason, outcome.detail)
    return Run(h, outcome)


def verify_all(run: Run, **overrides: Any) -> dict:
    artifacts = run.outcome.record_artifacts
    authz = artifacts.authorization
    kwargs: dict[str, Any] = {
        "record": artifacts.record, "bridge": authz.bridge, "declaration": authz.declaration,
        "tool_call": authz.tool_call, "authorizer_jwk": authz.authorizer_jwk,
        "record_jwk": run.guard.record_jwk, "verification_time": NOW, "receipt": authz.step_up_receipt,
        "policy_jwk": authz.policy_engine_jwk, "policy_bundle": POLICY_BYTES,
        "transcript": artifacts.transcript,
    }
    kwargs.update(overrides)
    return v.verify_adapter_artifacts(**kwargs)


def forge_bridge(bridge: dict, edit: Any = None, *, reid: bool = True, key: Ed25519PrivateKey = BRIDGE_KEY) -> dict:
    """Re-sign a bridge with edited authorization content, so only the semantic check can fail."""
    authorization = copy.deepcopy(bridge["authorization"])
    if edit is not None:
        edit(authorization)
    if reid:
        authorization["authorization_id"] = v.authorization_id_for(authorization)
    return g.sign_envelope(v.BRIDGE_PROFILE, "authorization", authorization, key)


def resign_record(record: dict, mutate: Any, key: Ed25519PrivateKey = RECORD_KEY) -> dict:
    """A validly signed copy of `record` with `mutate` applied, so only semantic checks can fail."""
    edited = copy.deepcopy(record)
    edited.pop("signature")
    mutate(edited)
    return sign_record(edited, key)
