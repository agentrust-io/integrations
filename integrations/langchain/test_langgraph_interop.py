"""Regression coverage against released LangGraph and LangChain packages."""

from __future__ import annotations

import pathlib
import sys
from typing import NotRequired, TypedDict

from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import generate_key, sign_record
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from langchain_to_trace import TraceCallbackHandler

PAYLOAD = "customer-account-reference-that-must-not-enter-the-record"
DIGEST = "sha256:" + "e" * 64


class GraphState(TypedDict):
    payload: str
    character_count: NotRequired[int]


@tool
def count_characters(payload: str) -> int:
    """Count characters without returning the input."""
    return len(payload)


def _use_tool(state: GraphState, config: RunnableConfig) -> dict[str, int]:
    count = count_characters.invoke({"payload": state["payload"]}, config=config)
    return {"character_count": count}


def test_langgraph_tool_run_emits_a_valid_trace_record() -> None:
    builder = StateGraph(GraphState)
    builder.add_node("use_tool", _use_tool)
    builder.add_edge(START, "use_tool")
    builder.add_edge("use_tool", END)
    graph = builder.compile()
    handler = TraceCallbackHandler()

    result = graph.invoke({"payload": PAYLOAD}, config={"callbacks": [handler]})

    assert isinstance(handler, BaseCallbackHandler)
    assert result["character_count"] == len(PAYLOAD)
    assert [(call.name, call.outcome) for call in handler.tool_calls] == [
        ("count_characters", "ok")
    ]
    assert handler.tool_calls[0].parent_run_id is not None
    assert PAYLOAD.encode() not in handler.transcript_bytes()

    signed = sign_record(
        handler.build_record(
            subject="spiffe://example.org/agent/langgraph",
            policy_bundle=b'{"rules":["no-payload-egress"]}',
            workload_digest=DIGEST,
            data_class="confidential",
            model_provider="test-provider",
            model_id="test-model",
            iat=1_700_000_000,
        ),
        generate_key(),
    )
    parsed = TrustRecord.model_validate(signed)
    assert parsed.tool_transcript is not None
    assert parsed.tool_transcript.call_count == 1
    assert parsed.appraisal.status == "none"
