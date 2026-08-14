"""Isolated local test entry points for first-party repository code."""

from __future__ import annotations

import nox


nox.options.default_venv_backend = "venv"
nox.options.sessions = ["capture_core", "trace_adapters", "capture_engines", "framework_adapters", "shadow_ai"]


def pytest(session: nox.Session, *paths: str) -> None:
    """Run pytest with repository-local temp state (reliable on locked-down Windows)."""
    session.run("python", "-m", "pytest", *paths, "-q", f"--basetemp=.nox/pytest-{session.name}")


@nox.session(python=["3.11", "3.12", "3.13"])
def capture_core(session: nox.Session) -> None:
    session.install("-e", "packages/agentrust-capture-core", "pytest>=8")
    pytest(session, "packages/agentrust-capture-core/tests")


@nox.session(python=["3.11", "3.12", "3.13"])
def trace_adapters(session: nox.Session) -> None:
    session.install("-e", "packages/agentrust-trace-adapters", "pytest>=8")
    pytest(session, "packages/agentrust-trace-adapters/tests")


@nox.session(python="3.12")
def capture_engines(session: nox.Session) -> None:
    session.install("-e", "packages/agentrust-capture-core", "pytest>=8")
    for requirements in ("claude-code/requirements.txt", "scheduled-agents/requirements.txt", "copilot/requirements.txt", "plugins/agentrust-codex/requirements.txt"):
        session.install("-r", requirements)
    pytest(session, "claude-code/tests", "scheduled-agents/tests", "copilot/tests", "plugins/agentrust-codex/tests")


@nox.session(python="3.12")
def framework_adapters(session: nox.Session) -> None:
    session.install("-e", "packages/agentrust-trace-adapters", "pytest>=8")
    pytest(session, "integrations/otel-genai/test_otel_to_trace.py", "integrations/langchain/test_langchain_to_trace.py", "integrations/llamaindex/test_llamaindex_to_trace.py")


@nox.session(python="3.12")
def shadow_ai(session: nox.Session) -> None:
    session.install("pytest>=8", "pyyaml")
    session.env["PYTHONPATH"] = "integrations/shadow-ai/src"
    pytest(session, "integrations/shadow-ai/tests")
