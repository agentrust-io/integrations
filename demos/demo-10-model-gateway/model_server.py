"""Model backend for the model-gateway demo.

Plain HTTP JSON-RPC 2.0, the shape the gateway's proxy posts to. Exposes one tool,
``model.chat_completion``, which stands in for the upstream inference call.

The completion text is generated locally so the demo runs with no API key and no
network. Set MODEL_API_KEY and MODEL_BASE_URL to forward to a real provider
instead; the governed path either side of this file is unchanged.
"""
import json
import os
import pathlib

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

HERE = pathlib.Path(__file__).parent

# In-region models are the ones a regulated customer can already reach. The rest
# are the ones this demo exists to unblock.
MODELS = {
    "regional-small":    {"region": "in-region",     "cloud": "shared"},
    "regional-isolated": {"region": "in-region",     "cloud": "dedicated"},
    "frontier-large":    {"region": "out-of-region", "cloud": "shared"},
    "frontier-mini":     {"region": "out-of-region", "cloud": "shared"},
}

UPSTREAM_KEY = os.environ.get("MODEL_API_KEY")
UPSTREAM_BASE = os.environ.get("MODEL_BASE_URL", "https://api.openai.com/v1")


def _synthesise(model: str, prompt: str) -> str:
    """Stand-in for inference. Deterministic, so the demo reads the same every time."""
    head = prompt.strip().splitlines()[0][:110] if prompt.strip() else "(empty prompt)"
    return (
        f"[{model}] Draft response to: “{head}”\n\n"
        "Eligibility for the requested benefit is confirmed against the submitted "
        "documents. Two items need manual follow-up before payment is released: "
        "proof of residence is older than 90 days, and the declared dependants do "
        "not match the registry extract."
    )


def _upstream(model: str, messages: list) -> str | None:
    """Forward to a real provider when a key is present."""
    if not UPSTREAM_KEY:
        return None
    try:
        from openai import OpenAI

        client = OpenAI(base_url=UPSTREAM_BASE,
                        default_headers={"api-key": UPSTREAM_KEY},
                        api_key=UPSTREAM_KEY)
        resp = client.chat.completions.create(model=model, messages=messages)
        return resp.choices[0].message.content
    except Exception as exc:  # a demo must not die because upstream is unhappy
        return f"[upstream call failed: {exc}]"


def _ok(id_, result) -> dict:
    return {"jsonrpc": "2.0", "id": id_,
            "result": {"content": [{"type": "text", "text": json.dumps(result)}]}}


def _err(id_, code: int, msg: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}}


# The catalog's approved_definition is the contract. cMCP hashes description +
# input schema + output schema on both sides and fail-closes on any difference,
# so this dict and catalog.json's approved_definition must stay identical: an
# argument the endpoint sends but this schema omits reads as a rug pull.
TOOL = {
    "name": "model.chat_completion",
    "description": "Run a chat completion against a model in the catalog",
    "inputSchema": {
        "type": "object",
        "required": ["model", "prompt"],
        "properties": {
            "model": {"type": "string"},
            "prompt": {"type": "string"},
            "model_region": {"type": "string"},
            "model_cloud": {"type": "string"},
            "data_class": {"type": "string"},
            "contains_identifiers": {"type": "boolean"},
            "redacted": {"type": "boolean"},
            "redaction_count": {"type": "number"},
        },
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "model": {"type": "string"},
            "region": {"type": "string"},
            "cloud": {"type": "string"},
            "content": {"type": "string"},
            "upstream": {"type": "string"},
        },
    },
}


async def handle(request: Request) -> JSONResponse:
    if request.method == "GET":
        return JSONResponse({"status": "ok"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_err(None, -32700, "parse error"), status_code=400)

    id_ = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": id_, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo-model-backend", "version": "0.1.0"},
        }})

    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": id_, "result": {"tools": [TOOL]}})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name != "model.chat_completion":
            return JSONResponse(_err(id_, -32601, f"unknown tool: {name}"))

        model = args.get("model", "gpt-oss-20b")
        prompt = args.get("prompt", "")
        messages = [{"role": "user", "content": prompt}]

        text = _upstream(model, messages) or _synthesise(model, prompt)
        return JSONResponse(_ok(id_, {
            "model": model,
            "region": MODELS.get(model, {}).get("region", "unknown"),
            "cloud": MODELS.get(model, {}).get("cloud", "unknown"),
            "content": text,
            "upstream": "provider" if UPSTREAM_KEY else "local-stand-in",
        }))

    return JSONResponse(_err(id_, -32601, f"method not found: {method}"))


app = Starlette(routes=[Route("/mcp", handle, methods=["GET", "POST"])])

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9010, log_level="warning")
