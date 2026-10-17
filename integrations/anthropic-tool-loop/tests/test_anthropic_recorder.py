"""The recorder: spool rows become AgenTrust events, OpenTelemetry spans and one signed TRACE record
per finished run. A denied call is visible in the appraisal, an unfinished run is never signed, and
an edited record fails verification."""

from __future__ import annotations

import copy
import json
import pathlib
import sys
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("agentrust_telemetry")
pytest.importorskip("agentrust_trace")

from agentrust_trace import generate_key  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from anthropic_tool_loop_trace import Run, ToolCatalog, ToolInfo  # noqa: E402
from anthropic_tool_loop_trace.recorder import Recorder, source_digest, verify  # noqa: E402

SECRET = "Acme Wholesale PO 4471 card 4111-1111-1111-1111"
MODEL = "claude-sonnet-5-5"
AGENT = "spiffe://example.org/agent/purchasing"
CATALOG = ToolCatalog(
    {"inventory_lookup": ToolInfo("inventory-db", "database", "internal"),
     "purchase_orders": ToolInfo("erp", "erp", "confidential", write=lambda verb: verb not in {"get", "list"}),
     "crm_*": ToolInfo("crm", "crm", "confidential")},
    taxonomy="example.v1", order=("public", "internal", "confidential"))


def _response(stop, i=100, o=50, r=1000, w=200):
    return SimpleNamespace(model=MODEL, stop_reason=stop, usage=SimpleNamespace(
        input_tokens=i, output_tokens=o, cache_read_input_tokens=r, cache_creation_input_tokens=w))


def _block(name, args, tool_id):
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=args)


@pytest.fixture
def env(tmp_path):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    spool = tmp_path / "spool.jsonl"

    def make(**overrides):
        kwargs = dict(spool=spool, data_dir=tmp_path / "data", signing_key=key, catalog=CATALOG,
                      enforcement_mode="enforce", policy_bundle_digest="sha256:" + "ab" * 32,
                      build_digest="sha256:" + "cd" * 32, prompt_classification="internal",
                      tracer_provider=provider,
                      prices={MODEL: (3.0, 15.0, 0.30, 3.75)}, pricing_version="example-2026-10")
        kwargs.update(overrides)
        return Recorder(**kwargs)

    key = generate_key()
    return SimpleNamespace(rec=make(), make=make, exporter=exporter, spool=str(spool), tmp=tmp_path)


def _run(env, **kw):
    return Run(AGENT, "purchasing", MODEL, toolset=["inventory_lookup", "purchase_orders"],
               action_field="action", spool=env.spool, **kw)


def _clean_run(env):
    run = _run(env, workflow_id="ticket-12")
    t = time.time_ns
    run.model_call(0, t(), _response("tool_use"))
    run.tool_call(0, _block("inventory_lookup", {"sku": SECRET}, "toolu_1"), t(), policy="purchasing_gate",
                  result={"rows": [SECRET]}, gate_ns=1200)
    run.model_call(1, t(), _response("end_turn"))
    run.end("end_turn")
    return run


def _events(rec, event_type):
    return [e for e in rec["events"] if e["event_type"] == event_type]


def test_clean_run_is_signed_affirming_and_verifies(env):
    run = _clean_run(env)
    assert env.rec.poll() == [run.id]
    rec = env.rec.run(run.id)
    s = rec["run"]
    assert s["verdict"] == "affirming" and s["signed"] and s["complete"]
    assert s["rounds"] == 2 and s["tool_calls"] == 1 and s["systems"] == ["inventory-db"]
    assert s["data_class"] == "internal" and s["sent_to_model"] == "internal"
    assert s["cost_usd"] == pytest.approx(2 * (100 * 3 + 50 * 15 + 1000 * 0.30 + 200 * 3.75) / 1e6)
    assert env.rec.verify(rec["trace"])["ok"] is True
    assert verify(rec["trace"], env.rec.public_jwk)["ok"] is True
    trace = rec["trace"]
    assert trace["origin"]["kind"] == "log-import" and trace["subject"] == AGENT
    assert trace["model"] == {"provider": "anthropic", "model_id": MODEL}
    assert trace["policy"] == {"bundle_hash": "sha256:" + "ab" * 32, "enforcement_mode": "enforce"}
    assert trace["runtime"]["platform"] == "software-only"

    types = [e["event_type"] for e in rec["events"]]
    assert types.count("usage.recorded") == 3  # two rounds + the agent_run rollup
    assert types.count("policy.decision") == 2  # toolset + the tool call's gate
    assert {"action.executed", "data_flow.observed"} <= set(types)
    assert all(e.get("workflow_id") == "ticket-12" for e in rec["events"])
    toolset = [e for e in _events(rec, "policy.decision") if e["policy"]["policy_id"] == "toolset"][0]
    assert toolset["decision"] == "allow" and toolset["action_type"] == "agent.invoke"
    gate = [e for e in _events(rec, "policy.decision") if e["policy"]["policy_id"] == "purchasing_gate"][0]
    assert gate["evaluation_duration_ns"] == 1200
    action = _events(rec, "action.executed")[0]
    assert action["policy_event_id"] == gate["event_id"] and action["operation"] == "read"

    sent = [e for e in _events(rec, "data_flow.observed") if e["direction"] == "send"][0]
    assert sent["destination"] == {"kind": "model-provider", "id": "anthropic"}
    assert sent["policy_decision"] == "not_evaluated"

    spans = env.exporter.get_finished_spans()
    names = {sp.name for sp in spans}
    assert {"invoke_agent purchasing", f"chat {MODEL}", "execute_tool inventory_lookup"} <= names
    assert len({sp.context.trace_id for sp in spans}) == 1
    assert s["otel_trace_id"] == f"{spans[0].context.trace_id:032x}"


def test_denied_call_is_contraindicated_with_reason(env):
    run = _run(env)
    t = time.time_ns
    run.model_call(0, t(), _response("tool_use"))
    run.tool_call(0, _block("purchase_orders", {"action": "create", "supplier": SECRET}, "toolu_9"), t(),
                  decision="deny", policy="purchasing_gate", reason="WRITERS_ONLY", gate_ns=900)
    run.model_call(1, t(), _response("end_turn"))
    run.end("end_turn")
    env.rec.poll()
    rec = env.rec.run(run.id)
    s = rec["run"]
    assert s["signed"] and s["verdict"] == "contraindicated"
    assert rec["trace"]["appraisal"]["status"] == "contraindicated"
    assert s["denies"] == 1 and s["writes"] == 0
    assert s["tools"][0]["write"] is True and s["tools"][0]["reason"] == "WRITERS_ONLY"
    deny = [e for e in _events(rec, "policy.decision") if e["decision"] == "deny"][0]
    assert deny["reason_codes"] == ["WRITERS_ONLY"] and deny["action_type"] == "erp.write"
    assert _events(rec, "action.executed")[0]["outcome"] == "denied"
    assert not [e for e in _events(rec, "data_flow.observed") if e["direction"] == "write"]


def test_allowed_write_is_a_write_flow(env):
    run = _run(env)
    t = time.time_ns
    run.model_call(0, t(), _response("tool_use"))
    run.tool_call(0, _block("purchase_orders", {"action": "create"}, "toolu_3"), t(), result={"po": 1})
    run.model_call(1, t(), _response("end_turn"))
    run.end("end_turn")
    env.rec.poll()
    rec = env.rec.run(run.id)
    flow = [e for e in _events(rec, "data_flow.observed") if e["direction"] == "write"][0]
    assert flow["destination"] == {"kind": "erp", "id": "erp"} and flow["classification"]["value"] == "confidential"
    assert rec["run"]["writes"] == 1 and rec["trace"]["data_class"] == "confidential"
    assert _events(rec, "action.executed")[0]["operation"] == "create"


def test_chat_only_run_is_signed(env):
    run = _run(env)
    run.model_call(0, time.time_ns(), _response("end_turn"))
    run.end("end_turn")
    env.rec.poll()
    s = env.rec.run(run.id)["run"]
    assert s["signed"] and s["verdict"] == "affirming" and s["tool_calls"] == 0, s["trace_error"]


def test_unfinished_run_is_sealed_incomplete_and_unsigned(env):
    run = _run(env)
    run.model_call(0, time.time_ns(), _response("tool_use"))
    assert env.rec.poll() == []  # still running
    assert env.rec.poll(final=True) == [run.id]
    rec = env.rec.run(run.id)
    assert rec["trace"] is None
    s = rec["run"]
    assert s["signed"] is False and s["complete"] is False and s["verdict"] == "unsigned"
    assert "never finished" in s["trace_error"]


def test_idle_run_is_sealed_unsigned(env):
    rec = env.make(idle_seconds=0)
    run = _run(env)
    run.model_call(0, 1, _response("tool_use"))  # started long ago
    assert rec.poll() == [run.id]
    assert rec.run(run.id)["run"]["signed"] is False


def test_tampered_record_fails_verification(env):
    run = _clean_run(env)
    env.rec.poll()
    original = env.rec.run(run.id)["trace"]
    for path, value in ((("appraisal", "status"), "warning"), (("data_class",), "public"),
                        (("policy", "enforcement_mode"), "advisory"), (("subject",), "spiffe://example.org/x")):
        record = copy.deepcopy(original)
        target = record
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        assert env.rec.verify(record)["ok"] is False, path
    other = generate_key()
    assert env.make(signing_key=other).verify(original)["ok"] is False  # someone else's key


def test_metadata_only_end_to_end(env):
    run = _clean_run(env)
    env.rec.poll()
    everything = [pathlib.Path(env.spool)] + [p for p in (env.tmp / "data").rglob("*") if p.is_file()]
    for path in everything:
        assert "Acme" not in path.read_text(), path
    for sp in env.exporter.get_finished_spans():
        assert "Acme" not in json.dumps(dict(sp.attributes), default=str)
    assert env.rec.run(run.id)["run"]["signed"]


def test_state_survives_a_restart_mid_run(env):
    run = _run(env)
    run.model_call(0, time.time_ns(), _response("end_turn"))
    env.rec.poll()
    again = env.make()
    assert run.id in again.pending
    run.end("end_turn")
    assert again.poll() == [run.id]
    assert again.run(run.id)["run"]["signed"] is True


def test_half_written_line_waits(env):
    run = _clean_run(env)
    with open(env.spool, "a") as fh:
        fh.write('{"run_id":"run-' + "a" * 32 + '","kind":"run.st')
    assert env.rec.poll() == [run.id]
    assert env.rec.pending == {}
    with open(env.spool, "a") as fh:
        fh.write('art","t":%d,"agent_id":"x","agent_name":"x","model":"m","toolset":[]}\n' % time.time_ns())
    env.rec.poll()
    assert "run-" + "a" * 32 in env.rec.pending


def test_late_rows_do_not_reopen_a_sealed_record(env):
    run = _clean_run(env)
    env.rec.poll()
    signed = env.rec.run(run.id)["trace"]
    run.ended = False
    run.end("end_turn")  # a duplicate end arrives later
    assert env.rec.poll() == []
    assert env.rec.run(run.id)["trace"] == signed


def test_without_opentelemetry_provider_events_still_record(env):
    rec = env.make(tracer_provider=None)
    run = _clean_run(env)
    rec.poll()
    stored = rec.run(run.id)
    assert stored["run"]["signed"] and stored["run"]["otel_trace_id"] is None
    assert all("trace_id" not in e for e in stored["events"])


def test_configuration_is_explicit(env, tmp_path):
    with pytest.raises(ValueError):
        env.make(enforcement_mode="sometimes")
    with pytest.raises(ValueError):
        env.make(policy_bundle_digest="abc")
    with pytest.raises(ValueError):
        env.make(prompt_classification="secret")
    with pytest.raises(TypeError):
        Recorder(spool=env.spool, data_dir=tmp_path, signing_key=generate_key(), catalog=CATALOG,
                 policy_bundle_digest="sha256:" + "ab" * 32, build_digest="sha256:" + "cd" * 32,
                 prompt_classification="internal")  # no enforcement_mode


def test_source_digest_changes_with_code(tmp_path):
    (tmp_path / "gate.py").write_text("ALLOW = True\n")
    first = source_digest(tmp_path)
    (tmp_path / "gate.py").write_text("ALLOW = False\n")
    assert source_digest(tmp_path) != first and first.startswith("sha256:")


def test_signed_record_passes_trace_conformance_level_0(env, tmp_path):
    runner = pytest.importorskip("click.testing")
    cli = pytest.importorskip("trace_tests.cli")
    run = _clean_run(env)
    env.rec.poll()
    path = tmp_path / "record.json"
    path.write_text(json.dumps(env.rec.run(run.id)["trace"]))
    result = runner.CliRunner().invoke(cli.main, ["verify", "--record", str(path), "--level", "0"])
    assert result.exit_code == 0, result.output
    assert "Ed25519 signature verified" in result.output


def test_a_malformed_run_is_logged_and_does_not_stop_the_others(env, caplog):
    bad = "run-" + "b" * 32
    with open(env.spool, "a") as fh:
        fh.write(json.dumps({"run_id": bad, "kind": "run.start", "t": time.time_ns(), "agent_id": AGENT}) + "\n")
        fh.write(json.dumps({"run_id": bad, "kind": "tool.call", "start": time.time_ns(), "end": time.time_ns(),
                             "tool": "purchase_orders"}) + "\n")  # no decision, digest or outcome
        fh.write(json.dumps({"run_id": bad, "kind": "run.end", "t": time.time_ns(), "stop": "end_turn"}) + "\n")
        fh.write("not json\n")
    good = _clean_run(env)
    with caplog.at_level("ERROR", logger="anthropic_tool_loop_trace.recorder"):
        done = env.rec.poll()
    assert set(done) == {bad, good.id}
    assert env.rec.run(good.id)["run"]["signed"] and env.rec.run(bad) is None
    assert any(bad in r.getMessage() for r in caplog.records)
