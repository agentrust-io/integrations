"""Regression tests for the stack-trace-exposure fix in sentinel/server.py.

Each endpoint below has a code path that raises internally. Before the fix,
the handler returned ``str(exception)`` straight to the caller, which can
carry field names, types, or other internals depending on what raised. These
tests trigger each path and assert the response carries only a generic
message, never the exception text.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.server import app


@pytest.fixture
def client():
    return TestClient(app)


def _assert_no_internals_leaked(body: dict) -> None:
    text = str(body).lower()
    for leaky in ("validationerror", "traceback", "pydantic", "attributeerror", "typeerror"):
        assert leaky not in text


class TestEvaluateEndpoint:
    def test_single_input_validation_error_returns_generic_message(self, client):
        # tool_calls must be a list of dicts; a bare string fails coercion.
        response = client.post("/evaluate", json={"tool_calls": "not-a-list"})
        assert response.status_code == 400
        body = response.json()
        assert body == {"error": "Invalid input"}
        _assert_no_internals_leaked(body)

    def test_malformed_json_body_returns_generic_message(self, client):
        response = client.post(
            "/evaluate", content=b"{not valid json", headers={"content-type": "application/json"}
        )
        assert response.status_code == 400
        body = response.json()
        assert body == {"error": "Invalid input"}
        _assert_no_internals_leaked(body)


class TestExportIncidentEndpoint:
    def test_validation_error_returns_generic_message(self, client):
        # risk_score must coerce to float; this value cannot.
        response = client.post(
            "/export/incident/claim-1", json={"risk_score": "not-a-number"}
        )
        assert response.status_code == 500
        body = response.json()
        assert body == {"error": "Internal error"}
        _assert_no_internals_leaked(body)


class TestReplayEndpoint:
    def test_missing_trace_returns_generic_message(self, client):
        response = client.post("/replay", json={})
        assert response.status_code == 400
        body = response.json()
        assert body == {"error": "Invalid input"}
        _assert_no_internals_leaked(body)


class TestVerifyIncidentEndpoint:
    def test_malformed_report_returns_generic_message(self, client):
        # report present (so the explicit "missing" branch is skipped) but
        # not a mapping, so .items() raises inside the handler.
        response = client.post("/verify/claim-1", json={"report": "not-a-dict"})
        assert response.status_code == 500
        body = response.json()
        assert body == {"error": "Internal error"}
        _assert_no_internals_leaked(body)
