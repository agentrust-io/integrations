"""A live CHAP review workspace, driven through `chap-coordinator`.

Used by the examples and tests. Needs the `chap-coordinator` package; `chap_trace`
itself does not.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from chap_coordinator import Coordinator, CoordinatorOptions
from chap_coordinator.canonical import content_hash

WORKSPACE = "wsp_refund_review"
RESOLVER = "https://chap.example.org/workspaces/wsp_refund_review"
REVIEWER = "human:alice@example.org"
AGENT = "agent:refund-bot"


@dataclass
class Workspace:
    coordinator: Coordinator
    ids: dict = field(default_factory=dict)
    _counter: int = 0

    def send(self, method: str, actor: str | None = None, **params) -> dict:
        self._counter += 1
        body = {"workspace": WORKSPACE, **params}
        if actor is not None:
            body["from"] = actor
        response = self.coordinator.dispatch({"jsonrpc": "2.0", "id": str(self._counter),
                                              "method": method, "params": body})
        if "error" in response:
            raise RuntimeError(f"{method}: {response['error']}")
        return response["result"]

    def pending_digest(self, task_id: str) -> str:
        task = self.coordinator.get_workspace(WORKSPACE).tasks[task_id]
        return content_hash(task.pending_artefact)

    def review(self, draft: dict) -> str:
        task_id = self.send("task.create", actor=AGENT, kind="refund_decision",
                            input={"order": draft["order"]}, assignee=AGENT)["task_id"]
        self.send("review.request", actor=AGENT, task_id=task_id, artefact=draft,
                  to=REVIEWER)
        return task_id

    def export(self) -> dict:
        """The log as `audit.read` returns it, with CHAP's own chain verdict."""
        verdict = self.send("audit.verify_chain")
        if verdict.get("status") != "verified":
            sys.exit(f"CHAP did not verify its own chain: {verdict}")
        return {"chain_head": verdict["chain_head"], "chap_verify_chain": verdict,
                "entries": self.send("audit.read")["entries"]}


def refund_review() -> Workspace:
    """One workspace: a refund approved, a refund rejected, a refund overridden."""
    ws = Workspace(Coordinator(CoordinatorOptions(
        default_profiles=["core/1.0", "review/1.0", "audit-scitt/1.0"])))
    ws.send("workspace.create")
    ws.send("participant.join", actor=REVIEWER, type="human", role="reviewer")
    ws.send("participant.join", actor=AGENT, type="agent", role="drafter")

    approved = ws.review({"order": "1042", "action": "refund", "amount_minor": 1250})
    rejected = ws.review({"order": "1043", "action": "refund", "amount_minor": 98000})
    overridden = ws.review({"order": "1044", "action": "refund", "amount_minor": 4000})

    ws.send("decide.approve", actor=REVIEWER, task_id=approved, comment="Within policy.",
            tags=[], approved_artefact_digest=ws.pending_digest(approved))
    ws.send("decide.reject", actor=REVIEWER, task_id=rejected,
            comment="Above the refund limit.", reason="Above the refund limit.", tags=[],
            approved_artefact_digest=ws.pending_digest(rejected))
    ws.send("decide.override", actor=REVIEWER, task_id=overridden,
            rationale="Partial refund only.", comment="Partial refund only.", tags=[],
            diff=[{"op": "replace", "path": "/amount_minor", "value": 2000}],
            approved_artefact_digest=ws.pending_digest(overridden))
    ws.ids = {"approved": approved, "rejected": rejected, "overridden": overridden}
    return ws


def entry_for(log: dict, method: str) -> dict:
    (entry,) = [e for e in log["entries"] if e["envelope"].get("method") == method]
    return entry
