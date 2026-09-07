"""Isolated local test entry points for first-party repository code."""

from __future__ import annotations

import nox


nox.options.default_venv_backend = "venv"
nox.options.sessions = ["capture_core", "trace_adapters", "capture_engines", "framework_adapters", "openai_agents_adapter", "google_adk_adapter", "shadow_ai", "wcm_integrations"]


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
    pytest(
        session,
        "integrations/otel-genai/test_otel_to_trace.py",
        "integrations/langchain/test_langchain_to_trace.py",
        "integrations/llamaindex/test_llamaindex_to_trace.py",
    )
    session.install("langchain-core==1.6.0", "langgraph==1.2.11")
    pytest(session, "integrations/langchain/test_langgraph_interop.py")

    # Modern LlamaIndex agents deliver tool requests on a per-run workflow
    # stream, not through the legacy instrumentation event tested above.
    session.install("-r", "integrations/llamaindex/requirements-interop.txt")
    pytest(session, "integrations/llamaindex/test_llamaindex_interop.py")

    # Pydantic AI needs no adapter: it instruments through OpenTelemetry and
    # emits the GenAI conventions otel-genai already maps. Verified against the
    # released package rather than asserted, the same treatment LangGraph got.
    session.install("pydantic-ai-slim==2.35.1", "opentelemetry-sdk>=1.25")
    pytest(session, "integrations/otel-genai/test_pydantic_ai_interop.py")


@nox.session(python="3.12")
def openai_agents_adapter(session: nox.Session) -> None:
    """The OpenAI Agents SDK adapter, unit tests then a real released run.

    Two passes on purpose. The first runs without the SDK installed, because
    record construction is where the honesty rules live and they should be
    testable on their own. The second installs the pinned SDK and runs a real
    agent, which is what catches a renamed span field.
    """
    session.install("agentrust-trace==0.9.0", "pytest>=8")
    pytest(session, "integrations/openai-agents/test_openai_agents_to_trace.py")
    session.install("openai-agents==0.22.0")
    pytest(session, "integrations/openai-agents")


@nox.session(python="3.12")
def google_adk_adapter(session: nox.Session) -> None:
    session.install("agentrust-trace==0.9.0", "pytest>=8")
    pytest(session, "integrations/google-adk/test_google_adk_to_trace.py")
    session.install("google-adk==2.7.1", "agentrust-trace-tests==0.5.0")
    pytest(
        session,
        "integrations/google-adk/test_google_adk_to_trace.py",
        "integrations/google-adk/test_google_adk_interop.py",
    )


@nox.session(python="3.12")
def shadow_ai(session: nox.Session) -> None:
    session.install("pytest>=8", "pyyaml")
    session.env["PYTHONPATH"] = "integrations/shadow-ai/src"
    pytest(session, "integrations/shadow-ai/tests")


@nox.session(python=["3.11", "3.12", "3.13"])
def wcm_integrations(session: nox.Session) -> None:
    """The Weight Custody Manifest integrations, against the published SDK.

    Pinned to an exact release rather than a floor. These adapters are sensitive
    to what the published package actually exports, and 0.27.0 is the release
    that first published wcm.artifact_digest, runtime_records and memory_sweep.
    A silent upgrade should show up as a failing pin here, where the reason is
    written down, rather than as a behaviour change nobody attributed to a
    dependency.

    pyyaml and opentelemetry-api are test-only. The Kyverno generator emits YAML
    without PyYAML on purpose and the OTel module is a no-op when the API is
    absent; both are installed here so the tests can check the real thing rather
    than a fake.
    """
    session.install(
        "weight-custody-manifest==0.27.0",
        "agent-manifest>=0.11.1",
        "pytest>=8",
        "pyyaml",
        "opentelemetry-api>=1.25",
    )
    pytest(
        session,
        "integrations/wcm-agent-manifest",
        "integrations/wcm-azure-skr",
        "integrations/wcm-coco-trustee",
        "integrations/wcm-cyclonedx",
        "integrations/wcm-gcp-confidential-space",
        "integrations/wcm-huggingface",
        "integrations/wcm-in-toto",
        "integrations/wcm-kyverno",
        "integrations/wcm-nvidia-nras",
        "integrations/wcm-oci",
        "integrations/wcm-opentelemetry",
        "integrations/wcm-trace",
        "integrations/wcm-triton",
        "integrations/wcm-vllm",
    )
