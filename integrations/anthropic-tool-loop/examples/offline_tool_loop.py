"""Offline end-to-end run: no network, no API key.

A scripted stand-in for `anthropic.Anthropic()` drives a two-turn purchasing conversation through
an ordinary Messages API tool loop:

    turn 1  a requester without purchasing rights asks for stock and a purchase order.
            The stock lookup runs; the gate denies the purchase order (WRITERS_ONLY).
    turn 2  a buyer confirms. The purchase order is created (an allowed write).

The recorder then turns the spool into AgenTrust events, signs one TRACE record per turn, verifies
both, and shows that an edited copy fails verification.

    python examples/offline_tool_loop.py [--out record.json] [--keep DIR]

--out writes the signed record of turn 2 for `trace-tests verify --record record.json --level 0`.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import inspect
import json
import pathlib
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from agentrust_trace import generate_key  # noqa: E402

from anthropic_tool_loop_trace import Run, ToolCatalog, ToolInfo  # noqa: E402
from anthropic_tool_loop_trace.recorder import Recorder  # noqa: E402

MODEL = "claude-sonnet-5-5"
AGENT_ID = "spiffe://example.org/agent/purchasing"
WRITERS = {"buyer"}
READ_VERBS = {"get", "list"}

TOOLS = [
    {"name": "inventory_lookup", "description": "Units on hand for a SKU.",
     "input_schema": {"type": "object", "properties": {"sku": {"type": "string"}}, "required": ["sku"]}},
    {"name": "purchase_orders", "description": "Get, list or create purchase orders.",
     "input_schema": {"type": "object", "properties": {
         "action": {"type": "string", "enum": ["get", "list", "create"]},
         "supplier": {"type": "string"}, "sku": {"type": "string"}, "qty": {"type": "integer"}},
         "required": ["action"]}},
]

CATALOG = ToolCatalog(
    {
        "inventory_lookup": ToolInfo("inventory-db", "database", "internal"),
        "purchase_orders": ToolInfo("erp", "erp", "confidential", write=lambda verb: verb not in READ_VERBS),
    },
    taxonomy="example.v1",
    order=("public", "internal", "confidential"),
)


# --- the application's own tools and gate -------------------------------------------------
def inventory_lookup(args):
    return {"sku": args["sku"], "on_hand": 14}


def purchase_orders(args):
    return {"po": "PO-0001", "status": "draft", "qty": args.get("qty")}


FUNCTIONS = {"inventory_lookup": inventory_lookup, "purchase_orders": purchase_orders}


def gate(tool, requester, args):
    """The application's own rule: only listed writers may create purchase orders.
    Returns a reason code for a deny, None to allow."""
    if tool == "purchase_orders" and args.get("action") not in READ_VERBS and requester not in WRITERS:
        return "WRITERS_ONLY"
    return None


# --- the tool loop; the recording lines are numbered -------------------------------------------
def answer(client, requester, text, spool):
    messages = [{"role": "user", "content": text}]
    run = Run(AGENT_ID, "purchasing", MODEL, toolset=[t["name"] for t in TOOLS],      # 1
              action_field="action", spool=spool)
    for round_no in range(10):
        t0 = time.time_ns()
        response = client.messages.create(model=MODEL, max_tokens=1024, tools=TOOLS, messages=messages)
        run.model_call(round_no, t0, response)                                          # 2
        if response.stop_reason != "tool_use":
            run.end(response.stop_reason)                                               # 3
            return "".join(b.text for b in response.content if b.type == "text")
        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            t0 = time.time_ns()
            denied = gate(block.name, requester, block.input)
            gate_ns = time.time_ns() - t0
            result, error = None, None
            if not denied:
                try:
                    result = FUNCTIONS[block.name](block.input)
                except Exception as exc:
                    error = exc
            run.tool_call(round_no, block, t0, decision="deny" if denied else "allow",     # 4
                          policy="purchasing_gate", reason=denied, result=result,
                          error_type=type(error).__name__ if error else None, gate_ns=gate_ns)
            if denied or error:
                content = "Only buyers can create purchase orders." if denied else str(error)
                results.append({"type": "tool_result", "tool_use_id": block.id, "is_error": True,
                                "content": content})
            else:
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(result)})
        messages += [{"role": "assistant", "content": response.content}, {"role": "user", "content": results}]
    run.end("max_rounds")                                                               # 5
    return "Stopped after too many rounds."


# --- a scripted stand-in for anthropic.Anthropic() -----------------------------------------
def _message(stop_reason, *content, usage=(410, 60, 0, 0)):
    i, o, r, w = usage
    return SimpleNamespace(
        id="msg_scripted", model=MODEL, role="assistant", stop_reason=stop_reason, content=list(content),
        usage=SimpleNamespace(input_tokens=i, output_tokens=o, cache_read_input_tokens=r,
                              cache_creation_input_tokens=w))


def _text(text):
    return SimpleNamespace(type="text", text=text)


def _tool_use(tool_id, name, args):
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=args)


class ScriptedClient:
    """Answers messages.create from a fixed script. Same call shape as the SDK, nothing leaves the process."""

    def __init__(self, script):
        self._script = list(script)
        self.messages = self
        self.calls = 0

    def create(self, **kwargs):
        assert kwargs["model"] and kwargs["messages"] and kwargs["tools"], "called like messages.create"
        self.calls += 1
        return self._script.pop(0)


SUPPLIER = "Northwind Supply, account 55-0193"  # appears in tool inputs; must never reach the spool

SCRIPT = [
    # turn 1, round 0: look up stock and try to create a purchase order
    _message("tool_use", _text("Checking stock and drafting the order."),
             _tool_use("toolu_01", "inventory_lookup", {"sku": "SKU-118"}),
             _tool_use("toolu_02", "purchase_orders",
                       {"action": "create", "supplier": SUPPLIER, "sku": "SKU-118", "qty": 20})),
    # turn 1, round 1: the gate refused; the model explains
    _message("end_turn", _text("14 on hand. A buyer has to create the purchase order."), usage=(520, 40, 400, 0)),
    # turn 2, round 0: the buyer confirms
    _message("tool_use", _tool_use("toolu_03", "purchase_orders",
                                   {"action": "create", "supplier": SUPPLIER, "sku": "SKU-118", "qty": 20})),
    # turn 2, round 1
    _message("end_turn", _text("Created PO-0001 as a draft."), usage=(480, 20, 400, 0)),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="write the signed TRACE record of turn 2 here")
    ap.add_argument("--keep", help="use this directory for spool and records instead of a temp dir")
    args = ap.parse_args(argv)

    work = pathlib.Path(args.keep or tempfile.mkdtemp(prefix="anthropic-tool-loop-"))
    work.mkdir(parents=True, exist_ok=True)
    spool = work / "spool.jsonl"
    client = ScriptedClient(SCRIPT)

    print("turn 1:", answer(client, "requester", "How many SKU-118 do we have? Order 20 more.", str(spool)))
    print("turn 2:", answer(client, "buyer", "Go ahead with the 20.", str(spool)))

    recorder = Recorder(
        spool=spool, data_dir=work / "data", signing_key=generate_key(), catalog=CATALOG,
        enforcement_mode="enforce",
        policy_bundle_digest="sha256:" + hashlib.sha256(inspect.getsource(gate).encode()).hexdigest(),
        build_digest="sha256:" + hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        prompt_classification="internal",
    )
    recorded = recorder.poll()
    print(f"\nrecorded {len(recorded)} run(s) in {work / 'data'}")

    stored = [recorder.run(run_id) for run_id in recorded]
    for n, rec in enumerate(stored, 1):
        s = rec["run"]
        print(f"turn {n}: {s['verdict']:<16} signed={s['signed']} tool_calls={s['tool_calls']} "
              f"denies={s['denies']} writes={s['writes']} data_class={s['data_class']} "
              f"events={s['events']} verify={recorder.verify(rec['trace'])['ok'] if rec['trace'] else '-'}")
        if s["trace_error"]:
            print(f"    not signed: {s['trace_error']}")
        for t in s["tools"]:
            print(f"    {t['tool']:<17} {t['action'] or '-':<7} {t['decision']:<5} {t['outcome']:<8} "
                  f"{'write' if t['write'] else 'read':<5} {t['reason'] or ''}")

    tampered = copy.deepcopy(stored[1]["trace"])
    tampered["data_class"] = "public"
    check = recorder.verify(tampered)
    print(f"\ntampered copy (data_class -> public): verify ok={check['ok']} ({check.get('error', '')[:80]})")

    leaked = [p.name for p in work.rglob("*") if p.is_file() and SUPPLIER.split(",")[0] in p.read_text()]
    print(f"supplier name found in spool/records: {leaked or 'nowhere'}")

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(stored[1]["trace"], indent=1))
        print(f"wrote {args.out}")
    ok = (stored[0]["run"]["verdict"] == "contraindicated" and stored[1]["run"]["verdict"] == "affirming"
          and all(recorder.verify(r["trace"])["ok"] for r in stored) and not check["ok"] and not leaked)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
