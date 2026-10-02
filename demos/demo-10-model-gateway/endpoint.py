"""An OpenAI-compatible endpoint that governs the model call and signs what happened.

Model and data protection at the model boundary: what data may reach which model,
in which region, on what infrastructure, with the outcome signed. An existing
OpenAI client is pointed at it by changing one line, and every call is routed
through cMCP, where Cedar decides, the audit chain records, and the session closes
into a signed TRACE claim.

What is real here: policy enforcement, the audit chain, the signed record, and
offline verification. What stands in: the inference itself (see model_server.py)
and the redaction ruleset, which is a small demonstrative pattern set rather
than a production DLP engine.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

GATEWAY = os.environ.get("CMCP_GATEWAY", "http://127.0.0.1:8444")

# The catalogue spans regions *and* infrastructure tenancy. Both dimensions matter:
# confidential stays in the jurisdiction, and PHI also stays off shared hardware.
MODELS = {
    "regional-small":    {"region": "in-region",     "cloud": "shared"},
    "regional-isolated": {"region": "in-region",     "cloud": "dedicated"},
    "frontier-large":    {"region": "out-of-region", "cloud": "shared"},
    "frontier-mini":     {"region": "out-of-region", "cloud": "shared"},
}

# Demonstrative identifier patterns. A production deployment would drive this
# from the customer's classification policy, not a literal list.
REDACTIONS = [
    ("NATIONAL_ID", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("ACCOUNT_NO", re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")),
]

# The classes policies/allow.cedar knows, lowest to highest.
DATA_CLASSES = frozenset({"public", "pii", "confidential", "hipaa_phi"})

# Sessions we have opened on the gateway, and the records they produced.
STATE = {"session_id": None, "records": []}


def _post(url, payload, timeout=20):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return json.loads(raw), exc.code
        except Exception:
            return {"error": raw.decode(errors="replace")}, exc.code


def redact(text):
    """Strip identifiers before anything leaves the boundary. Returns (text, hits)."""
    hits = []
    for label, pattern in REDACTIONS:
        text, n = pattern.subn(f"[{label} REDACTED]", text)
        if n:
            hits.extend([label] * n)
    return text, hits


def _bad_request(message):
    return JSONResponse({"error": {"message": message, "type": "invalid_request_error",
                                   "code": "INVALID_REQUEST"}}, status_code=400)


def _prompt_of(messages):
    return "\n".join(m.get("content", "") for m in messages if isinstance(m, dict))


async def chat_completions(request: Request) -> JSONResponse:
    """The OpenAI surface. Same request and response shape the SDK expects."""
    try:
        body = await request.json()
    except Exception:
        return _bad_request("request body is not valid JSON")
    if not isinstance(body, dict):
        return _bad_request("request body must be a JSON object")
    model = body.get("model", "regional-small")
    messages = body.get("messages", [])
    if not isinstance(model, str) or not isinstance(messages, list) or not all(
            isinstance(m, dict) and isinstance(m.get("content", ""), str) for m in messages):
        return _bad_request("model must be a string and messages a list of "
                            "{role, content} objects with string content")

    # The class is decided by the routing layer, not by the caller: an upstream
    # classifier decides, this endpoint receives that decision and enforces it.
    data_class = (request.headers.get("x-data-class")
                  or body.get("data_class") or "confidential")
    # The Cedar bundle forbids by naming classes, so a label it does not name
    # (a typo, a different case) would match no forbid and leave the region
    # under the permit. Refuse it here rather than fail open.
    if data_class not in DATA_CLASSES:
        return _bad_request(f"unknown data class {data_class!r}; "
                            f"expected one of {sorted(DATA_CLASSES)}")
    placement = MODELS.get(model, {"region": "unknown", "cloud": "unknown"})
    region, cloud = placement["region"], placement["cloud"]

    prompt = _prompt_of(messages)
    contains_identifiers = any(p.search(prompt) for _, p in REDACTIONS)
    safe_prompt, hits = redact(prompt)

    args = {
        "model": model,
        "prompt": safe_prompt,
        "model_region": region,
        "model_cloud": cloud,
        "data_class": data_class,
        "contains_identifiers": contains_identifiers,
        "redacted": bool(hits),
        "redaction_count": len(hits),
    }

    result, status = _post(f"{GATEWAY}/mcp", {
        "jsonrpc": "2.0", "id": int(time.time() * 1000),
        "method": "tools/call",
        "params": {"name": "model.chat_completion", "arguments": args,
                   "_cmcp": {"workflow_id": "model-gateway-demo"}},
    })

    if "error" in result:
        err = result["error"]
        data = err.get("data", {}) if isinstance(err, dict) else {}
        advice = data.get("advice", {}) or {}
        # Deny is returned in the shape an OpenAI client already understands.
        return JSONResponse({"error": {
            "message": advice.get("reason") or err.get("message", "denied by policy")
            if isinstance(err, dict) else str(err),
            "type": "policy_denied",
            "code": data.get("error_code", "POLICY_DENY"),
            "governance": {
                "decision": "deny",
                "advice": advice,
                "data_class": data_class,
                "model_region": region,
                "model_cloud": cloud,
                "redactions": hits,
            },
        }}, status_code=403)

    payload = result.get("result", {})
    inner = payload.get("content", [{}])[0].get("text", "{}")
    try:
        upstream = json.loads(inner)
    except Exception:
        upstream = {"content": inner}
    STATE["session_id"] = payload.get("_cmcp", {}).get("session_id") or STATE["session_id"]

    return JSONResponse({
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": upstream.get("content", "")},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": len(prompt.split()),
                  "completion_tokens": len(upstream.get("content", "").split()),
                  "total_tokens": len(prompt.split()) + len(upstream.get("content", "").split())},
        # The addition. Everything above is an ordinary OpenAI response.
        "governance": {
            "decision": "allow",
            "data_class": data_class,
            "model_region": region,
            "model_cloud": cloud,
            "redactions": hits,
            "session_id": STATE["session_id"],
            "trace_claim": "/v1/trust-record",
        },
    })


async def models(request: Request) -> JSONResponse:
    return JSONResponse({"object": "list", "data": [
        {"id": m, "object": "model", "owned_by": "demo", **v}
        for m, v in MODELS.items()
    ]})


async def trust_record(request: Request) -> JSONResponse:
    """Close the session and return the signed record for it."""
    sid = STATE.get("session_id")
    if not sid:
        return JSONResponse({"error": "no session yet -- make a call first"}, 404)
    record, status = _post(f"{GATEWAY}/sessions/{sid}/close", {})
    if status >= 400:
        return JSONResponse({"error": record}, status)
    STATE["records"].append(record)
    STATE["session_id"] = None
    return JSONResponse(record)


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "gateway": GATEWAY})


app = Starlette(routes=[
    Route("/v1/chat/completions", chat_completions, methods=["POST"]),
    Route("/v1/models", models, methods=["GET"]),
    Route("/v1/trust-record", trust_record, methods=["GET", "POST"]),
    Route("/health", health, methods=["GET"]),
])

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8500, log_level="warning")
