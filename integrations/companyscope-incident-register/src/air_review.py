"""Pre-deployment review against the AI Agent Incident Register.

Reads an Agent Manifest, looks at what the manifest actually declares, and returns the
decided incidents that bear on those declarations, each with the liability allocation the
register assigned. Output is a review checklist, in markdown or JSON.

The register is an evidence source. This tool issues no records, verifies no manifests and
makes no assertion about whether a deployment is compliant. It tells a reviewer which
incidents to read before signing off, and why each one was selected.

Register feed: https://companyscope.io/api/register (CC BY 4.0).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

FEED_URL = "https://companyscope.io/api/register"
ATTRIBUTION = (
    "Source: AI Agent Incident Register, Michael K. Onyekwere "
    "(companyscope.io/register), CC BY 4.0."
)


# --------------------------------------------------------------------------- feed


def load_feed(source: str = FEED_URL, timeout: int = 30) -> dict[str, Any]:
    """Fetch the register feed from the network, or read it from a local file."""
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"User-Agent": "air-review"})
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    return json.loads(Path(source).read_text(encoding="utf-8"))


def entries(feed: dict[str, Any]) -> list[dict[str, Any]]:
    return list(feed.get("entries", []))


# --------------------------------------------------------------------------- selectors


def select(
    pool: Iterable[dict[str, Any]],
    *,
    incident_class: str | None = None,
    owasp: str | None = None,
    locus: str | None = None,
    keywords: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Select register entries on feed fields, and optionally on words in the title or summary.

    Selection runs against the live feed rather than a pinned list of IDs, so entries
    published after this integration was written are picked up without a code change.
    """
    found = []
    for entry in pool:
        if incident_class and entry.get("incident_class") != incident_class:
            continue
        if owasp and owasp.lower() not in str(entry.get("owasp_asi", "")).lower():
            continue
        if locus and locus.lower() not in str(entry.get("liability_locus", "")).lower():
            continue
        if keywords:
            haystack = f"{entry.get('title', '')} {entry.get('summary', '')}".lower()
            if not any(word in haystack for word in keywords):
                continue
        found.append(entry)
    return found


# --------------------------------------------------------------------------- rules


@dataclass(frozen=True)
class Rule:
    key: str
    question: str
    trigger: Callable[[Any], str | None]
    selector: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


def _get(obj: Any, *path: str) -> Any:
    for name in path:
        if obj is None:
            return None
        obj = getattr(obj, name, None)
    return obj


def _tool_names(manifest: Any) -> list[str]:
    tools = _get(manifest, "artifacts", "tool_manifest", "tools") or []
    names = []
    for tool in tools:
        name = getattr(tool, "name", None) or getattr(tool, "tool_name", None)
        if name:
            names.append(str(name))
    return names


RULES: list[Rule] = [
    Rule(
        key="dynamic-tool-registration",
        question="Can the agent gain tools after the manifest was signed?",
        trigger=lambda m: (
            "tool_manifest.allow_dynamic_registration is true, so the tool set at run time "
            "is not the tool set that was reviewed"
            if _get(m, "artifacts", "tool_manifest", "allow_dynamic_registration")
            else None
        ),
        selector=lambda pool: select(pool, owasp="ASI02"),
    ),
    Rule(
        key="policy-not-enforced",
        question="Is the policy bundle actually enforced?",
        trigger=lambda m: (
            f"policy_bundle.enforcement_mode is "
            f"{getattr(_get(m, 'artifacts', 'policy_bundle', 'enforcement_mode'), 'value', None)}, "
            "so the policy observes rather than blocks"
            if str(
                getattr(
                    _get(m, "artifacts", "policy_bundle", "enforcement_mode"), "value", ""
                )
            )
            in {"advisory", "audit-only"}
            else None
        ),
        selector=lambda pool: select(pool, incident_class="autonomous-agent-breach"),
    ),
    Rule(
        key="no-declared-scope",
        question="Does anything state where the agent may and may not act?",
        trigger=lambda m: (
            "policy_bundle.scope is empty, so no boundary is declared in the manifest"
            if _get(m, "artifacts", "policy_bundle") is not None
            and not (_get(m, "artifacts", "policy_bundle", "scope") or [])
            else None
        ),
        selector=lambda pool: select(pool, incident_class="autonomous-agent-breach"),
    ),
    Rule(
        key="no-human-approval",
        question="Is a human in the loop before consequential actions?",
        trigger=lambda m: (
            "hitl_record is absent or not required, so no human approval gate is recorded"
            if not _get(m, "hitl_record") or not _get(m, "hitl_record", "required")
            else None
        ),
        selector=lambda pool: select(pool, locus="deployer"),
    ),
    Rule(
        key="personal-data",
        question="Does the agent process personal data?",
        trigger=lambda m: (
            "data_scope.personal_data_categories is populated: "
            + ", ".join(_get(m, "data_scope", "personal_data_categories") or [])
            if (_get(m, "data_scope", "personal_data_categories") or [])
            else None
        ),
        selector=lambda pool: select(
            pool, keywords=("personal data", "gdpr", "data protection", "privacy")
        ),
    ),
    Rule(
        key="automated-decisions",
        question="Does the agent make automated decisions about people?",
        trigger=lambda m: (
            "data_scope.automated_decision_making is true"
            if _get(m, "data_scope", "automated_decision_making")
            else None
        ),
        selector=lambda pool: select(pool, incident_class="legal-crystallized"),
    ),
    Rule(
        key="delegated-authority",
        question="Does the agent act on someone else's authority?",
        trigger=lambda m: (
            f"delegation_chain has {len(_get(m, 'delegation_chain') or [])} hop(s)"
            if (_get(m, "delegation_chain") or [])
            else None
        ),
        selector=lambda pool: select(pool, owasp="ASI03"),
    ),
    Rule(
        key="third-party-model",
        question="Who runs the model, and what happens in their testing?",
        trigger=lambda m: (
            f"model_identity.deployment_type is "
            f"{getattr(_get(m, 'artifacts', 'model_identity', 'deployment_type'), 'value', None)}, "
            "so part of the chain sits with the provider"
            if str(
                getattr(
                    _get(m, "artifacts", "model_identity", "deployment_type"), "value", ""
                )
            )
            in {"api", "third-party-api"}
            else None
        ),
        selector=lambda pool: select(pool, locus="vendor"),
    ),
    Rule(
        key="code-and-packages",
        question="Can the agent write code or publish artefacts other systems consume?",
        trigger=lambda m: (
            "tool_manifest declares tools matching code or package operations: "
            + ", ".join(
                n
                for n in _tool_names(m)
                if any(
                    word in n.lower()
                    for word in (
                    "code",
                    "exec",
                    "shell",
                    "package",
                    "publish",
                    "commit",
                    "pull_request",
                    "merge",
                    "deploy",
                    "npm",
                    "pypi",
                )
                )
            )
            if any(
                any(
                    word in n.lower()
                    for word in (
                    "code",
                    "exec",
                    "shell",
                    "package",
                    "publish",
                    "commit",
                    "pull_request",
                    "merge",
                    "deploy",
                    "npm",
                    "pypi",
                )
                )
                for n in _tool_names(m)
            )
            else None
        ),
        selector=lambda pool: select(pool, incident_class="coding-agent"),
    ),
    Rule(
        key="unbound-artifacts",
        question="Which defining artefacts are not bound by the manifest?",
        trigger=lambda m: (
            "unbound_artifacts: "
            + ", ".join(str(getattr(a, "value", a)) for a in (_get(m, "unbound_artifacts") or []))
            if (_get(m, "unbound_artifacts") or [])
            else None
        ),
        selector=lambda pool: [],
    ),
]


# --------------------------------------------------------------------------- review


@dataclass
class Finding:
    key: str
    question: str
    because: str
    entries: list[dict[str, Any]] = field(default_factory=list)


def review(manifest: Any, feed: dict[str, Any]) -> list[Finding]:
    pool = entries(feed)
    findings = []
    for rule in RULES:
        because = rule.trigger(manifest)
        if because is None:
            continue
        findings.append(
            Finding(key=rule.key, question=rule.question, because=because, entries=rule.selector(pool))
        )
    return findings


def as_markdown(manifest: Any, feed: dict[str, Any], findings: list[Finding]) -> str:
    agent_id = getattr(manifest, "agent_id", "(unknown agent)")
    lines = [
        f"# Pre-deployment review: {agent_id}",
        "",
        f"Checked against {feed.get('count', len(entries(feed)))} decided incidents "
        f"in the AI Agent Incident Register, as at {feed.get('updated', 'unknown date')}.",
        "",
        "This is a reading list, not a compliance verdict. Each item says what the manifest",
        "declares and which incidents bear on it.",
        "",
    ]
    if not findings:
        lines += ["Nothing in this manifest matched a rule in this pack.", ""]
    for finding in findings:
        lines += [f"## {finding.question}", "", f"**Because:** {finding.because}", ""]
        if finding.entries:
            lines.append("| Entry | Liability | Read |")
            lines.append("|---|---|---|")
            for entry in finding.entries:
                lines.append(
                    f"| {entry.get('id')} {entry.get('title', '')} "
                    f"| {entry.get('liability_locus', '')} | {entry.get('url', '')} |"
                )
        else:
            lines.append("No register entry is selected for this item. It is a manifest gap to close.")
        lines.append("")
    lines.append(ATTRIBUTION)
    return "\n".join(lines)


def as_json(manifest: Any, feed: dict[str, Any], findings: list[Finding]) -> str:
    payload = {
        "agent_id": getattr(manifest, "agent_id", None),
        "register": {
            "url": feed.get("url"),
            "updated": feed.get("updated"),
            "count": feed.get("count"),
            "license": feed.get("license"),
            "attribution": ATTRIBUTION,
        },
        "findings": [
            {
                "rule": f.key,
                "question": f.question,
                "because": f.because,
                "entries": [
                    {
                        "id": e.get("id"),
                        "title": e.get("title"),
                        "liability_locus": e.get("liability_locus"),
                        "owasp_asi": e.get("owasp_asi"),
                        "url": e.get("url"),
                    }
                    for e in f.entries
                ],
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def load_manifest(path: str) -> Any:
    from agent_manifest import Manifest

    return Manifest.model_validate_json(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="path to an Agent Manifest JSON document")
    parser.add_argument("--feed", default=FEED_URL, help="register feed URL or local JSON file")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    feed = load_feed(args.feed)
    findings = review(manifest, feed)
    renderer = as_markdown if args.format == "markdown" else as_json
    print(renderer(manifest, feed, findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
