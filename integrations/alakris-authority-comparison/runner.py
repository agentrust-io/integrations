"""Appraise public authority evidence; no unsigned input becomes attested TRACE."""

import argparse
import hashlib
import json
from pathlib import Path

STATES = {"measured", "not_applicable", "not_emitted", "not_measured"}
CASES = ("binding_veto", "revoked_stale", "unreachable", "post_dispatch_revoke")
REQUIRED_FIELDS = frozenset(
    json.loads(Path(__file__).with_name("comparison-contract.json").read_text())[
        "required_fields"
    ]
)


def field(state, value=None, reason=None):
    if state not in STATES:
        raise ValueError("unknown evidence state")
    if state == "measured" and value is None:
        raise ValueError("measured fields require an observation")
    if state != "measured" and value is not None:
        raise ValueError("missing/inapplicable fields cannot carry a measured value")
    if reason is None and state != "measured":
        reason = {
            "not_applicable": "no equivalent on this implementation path",
            "not_emitted": "not present in the public adapter input",
            "not_measured": "measurement/appraisal not performed",
        }[state]
    return {"state": state, "value": value, "reason": reason}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative_file(base, name):
    path = (base / name).resolve()
    if not path.is_relative_to(base.resolve()) or not path.is_file():
        raise ValueError("missing file or unsafe artifact path: " + str(name))
    return path


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def hash_check(base, name, expected):
    actual = digest(relative_file(base, name))
    return {
        "file": name,
        "expected": expected,
        "actual": actual,
        "match": actual == expected,
    }


def reference(path, uri):
    # Proposed comparison evidence relation, not a registered TRACE relation.
    return {
        "uri": uri,
        "digest": {"alg": "sha-256", "value": digest(path)},
        "signature_appraisal": "not_measured",
        "attestation_claim": False,
    }


def refusal_observation(path):
    """Keep observed refusal time separate from formula, bound unit and t0."""
    first = path.get("first_refused") or {}
    emergency = path["path"] == "emergency"
    seconds = first.get("seconds_after_t0")
    bound = path.get("bound_seconds")
    root = path.get("root_carrying_revocation") or {}
    heights = {
        "refusal_chain_height_after": first.get("chain_height_after"),
        "root_carrying_revocation_finalized_height": root.get("finalized_height"),
    }
    return {
        "path": path["path"],
        "agent": path.get("agent"),
        "observed_seconds_after_t0": field("measured", seconds)
        if seconds is not None
        else field("not_emitted"),
        "seconds_bound": field(
            "not_applicable", reason="publisher defines this emergency bound in blocks"
        )
        if emergency
        else (field("measured", bound) if bound is not None else field("not_emitted")),
        "bound_unit": "blocks" if emergency else "seconds",
        "bound_formula": path.get("bound_formula"),
        "t0_definition": path.get("t0_definition"),
        "block_observations": field("measured", heights)
        if any(v is not None for v in heights.values())
        else field("not_emitted"),
    }


def unobserved_context_fields():
    """Adapters explicitly disclose unavailable context before validation."""
    return {
        key: field(
            "not_measured"
            if key in {"independent_effect_witness", "retry_count", "duplicate_count"}
            else "not_emitted",
            reason="appraisal not performed"
            if key in {"independent_effect_witness", "retry_count", "duplicate_count"}
            else "not exposed by this public adapter input",
        )
        for key in (
            "action_digest",
            "target_identity",
            "original_deadline",
            "fallback_scope",
            "independent_effect_witness",
            "retry_count",
            "duplicate_count",
        )
    }


def validate_report(report):
    ids = [c["case_id"] for c in report["cases"]]
    if len(ids) != 4 or set(ids) != set(CASES):
        raise ValueError("exactly four unique case IDs are required")
    for case in report["cases"]:
        if case["case_id"] not in CASES:
            raise ValueError("unknown case")
        missing = REQUIRED_FIELDS.difference(case["fields"])
        if missing:
            raise ValueError(
                "missing required fields for "
                + case["case_id"]
                + ": "
                + ", ".join(sorted(missing))
            )
        for key, item in case["fields"].items():
            field(item["state"], item["value"], item.get("reason"))
        if (
            case.get("independent_live_reproduction")
            and case["basis"] != "independent_run"
        ):
            raise ValueError("author records cannot establish independent reproduction")
    return report


def proofable(base):
    manifest = json.loads((base / "manifest.json").read_text())
    trace = rows(base / "trace.jsonl")
    checks = []
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        checks.append(hash_check(base, name.lstrip("* "), expected))
    checks.append(
        hash_check(
            base, manifest["public_trace"]["file"], manifest["public_trace"]["sha256"]
        )
    )
    envelope_path = base / "portable-proofs.json"
    envelope_report = {
        "state": "not_measured",
        "reason": "no public envelope file",
        "valid": None,
    }
    if envelope_path.exists():
        from portable_envelope import verify

        envelopes = json.loads(envelope_path.read_text())
        expected = set()
        for row in trace:
            receipt = row.get("terminal_receipt") or {}
            if receipt.get("qHash"):
                expected.add(receipt["qHash"])
            expected.update(row.get("authority_decision_qHashes", []))
            for key in ("authority_decision_qHash", "next_authority_decision_qHash"):
                if row.get(key):
                    expected.add(row[key])
        actual = [e.get("qHash") for e in envelopes]
        refs = [
            r.get("qHash")
            for r in manifest.get("portable_proofs", {}).get("references", [])
        ]
        verdicts = [{"qHash": e.get("qHash"), **verify(e)} for e in envelopes]
        bound = (
            len(envelopes)
            == len(set(actual))
            == len(refs)
            == len(set(refs))
            == manifest.get("portable_proofs", {}).get("count")
            == len(expected)
            and bool(expected)
            and set(actual) == set(refs) == expected
        )
        envelope_report = {
            "state": "measured",
            "valid": bound and all(v["valid"] for v in verdicts),
            "qhash_set_bound": bound,
            "verdicts": verdicts,
            "scope": "historical EIP-191 receipt integrity; freshness not appraised",
        }
    ids = [r["case_id"] for r in trace]
    consistent = len(ids) == len(set(ids)) == manifest["public_trace"][
        "record_count"
    ] and set(ids) == {
        "hosted_allow",
        "binding_veto",
        "revoke_before_dispatch",
        "expiry_before_dispatch",
        "stale_authority",
        "post_dispatch_revoke",
    }
    cases = []
    source_cases = {
        "binding_veto": ["binding_veto"],
        "revoked_stale": [
            "hosted_allow",
            "revoke_before_dispatch",
            "expiry_before_dispatch",
            "stale_authority",
        ],
        "unreachable": [],
        "post_dispatch_revoke": ["post_dispatch_revoke"],
    }
    for case in CASES:
        relevant = [r for r in trace if r["case_id"] in source_cases[case]]

        def missing(why):
            return field("not_emitted", reason=why)

        fields = {
            **unobserved_context_fields(),
            "authority": field(
                "measured", [r.get("delegation_qHash") for r in relevant]
            )
            if relevant
            else (
                field("not_applicable", reason="current authority evaluated locally")
                if case == "unreachable"
                else field("not_emitted")
            ),
            "decision": field("measured", [r["observed"] for r in relevant])
            if relevant
            else (
                field(
                    "not_applicable",
                    reason="no remote authority dependency on this path",
                )
                if case == "unreachable"
                else field("not_emitted")
            ),
            "dispatch": field(
                "not_emitted", reason="explicit dispatch event/time not in public trace"
            ),
            "platform_observation": field(
                "measured",
                [
                    {"attempt": r["case_id"], "observation": r["observed"]}
                    for r in relevant
                ],
            )
            if relevant
            else (
                field("not_applicable")
                if case == "unreachable"
                else field("not_emitted")
            ),
            "committed_effect": field(
                "not_emitted",
                reason="public trace has platform outcomes, not target-side committed effects",
            ),
            "task_outcome": field(
                "not_emitted",
                reason="platform observations do not establish the target task result",
            ),
            "receipt": field(
                "measured",
                [
                    {
                        "attempt": r["case_id"],
                        "receipt": field("measured", r["terminal_receipt"])
                        if r.get("terminal_receipt")
                        else field(
                            "not_emitted", reason="no receipt exposed for this attempt"
                        ),
                    }
                    for r in relevant
                ],
            )
            if relevant
            else (
                field("not_applicable")
                if case == "unreachable"
                else field("not_emitted")
            ),
            "receipt_signature_material": field(
                "measured",
                {"file": "portable-proofs.json", "sha256": digest(envelope_path)},
            )
            if relevant and envelope_path.exists()
            else missing("no envelope material for this case"),
            "receipt_signature_verification": field("measured", envelope_report)
            if relevant and envelope_report["state"] == "measured"
            else field("not_measured", reason="no envelope verification for this case"),
            "policy_digest": missing(
                "policy version is an identifier, not a canonical digest"
            ),
            "revocation_latency_seconds": field("not_measured"),
            "root_age_seconds": field(
                "not_applicable", reason="local authority-state path"
            ),
            "useful_work_lost": field("not_measured"),
        }
        cases.append(
            {
                "case_id": case,
                "basis": "author_record",
                "publisher_claim": manifest["results"][case],
                "independent_live_reproduction": False,
                "fields": fields,
            }
        )
    data = (base / "trace.jsonl").read_bytes()
    crlf = hashlib.sha256(
        data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    ).hexdigest()
    ok = (
        all(c["match"] for c in checks)
        and consistent
        and envelope_report["valid"] is not False
    )
    return validate_report(
        {
            "implementation": "Proofable",
            "run_id": manifest["run_id"],
            "evidence_custody": {
                "producer": "Proofable author/operator",
                "public_artifact": "sanitized trace",
                "appraiser": "Alakris evidence runner",
                "independent_target_observer": False,
            },
            "deployed_revision_claim": manifest["deployed_revision"],
            "checks": checks,
            "integrity": "PASS" if ok else "FAIL",
            "record_count_consistent": consistent,
            "envelope_appraisal": envelope_report,
            "newline_diagnostic": {
                "crlf_hash_matches_published": crlf
                == manifest["public_trace"]["sha256"],
                "strict_byte_check_unchanged": True,
            },
            "cases": cases,
        }
    )


def mintid(base, name):
    manifest = json.loads(relative_file(base, name + ".manifest.json").read_text())
    required = {name + ".jsonl", name + ".md"}
    if not required.issubset(manifest.get("files", {})):
        raise ValueError("MintID manifest must cover JSONL and summary bytes")
    checks = []
    for filename, expected in manifest["files"].items():
        if (
            not isinstance(expected, str)
            or len(expected) != 64
            or any(c not in "0123456789abcdef" for c in expected)
        ):
            raise ValueError("invalid publisher digest")
        checks.append(hash_check(base, filename, expected))
    rows(relative_file(base, name + ".jsonl"))
    basis = "author_record"
    paths = manifest.get("paths", [])
    revocation_paths = [p for p in paths if p["path"] != "unreachable"]
    outage_paths = [p for p in paths if p["path"] == "unreachable"]
    cases = []
    for case in CASES:

        def na(why):
            return field("not_applicable", reason=why)

        fields = {
            **unobserved_context_fields(),
            "dispatch": na("MintID has no executor"),
            "committed_effect": na("relying-party boundary"),
            "task_outcome": na("relying-party task outcome is outside MintID"),
            "receipt": field("not_emitted"),
            "receipt_signature_verification": field("not_measured"),
            "policy_digest": field("measured", manifest["policy"]["sha256"])
            if manifest.get("policy", {}).get("sha256") is not None
            else field("not_emitted"),
            "authority": field("measured", manifest["policy"]["claim_policy"])
            if manifest.get("policy", {}).get("claim_policy") is not None
            else field("not_emitted"),
            "full_delegated_scope": field(
                "not_emitted", reason="privacy-preserving predicate disclosure"
            ),
            "useful_work_lost": field("not_measured"),
        }
        if case == "revoked_stale" and revocation_paths:
            fields["decision"] = field("measured", revocation_paths)
            fields["first_refusal_observations"] = field(
                "measured", [refusal_observation(p) for p in revocation_paths]
            )
            fields["revocation_latency_seconds"] = field(
                "not_measured",
                reason="first presentation refusal is not an end-to-end revocation latency or general SLA",
            )
            roots = [
                {
                    "path": p["path"],
                    "epoch": (
                        (p.get("first_refused") or {}).get("decision_log") or {}
                    ).get("root_epoch"),
                    "height": (
                        (p.get("first_refused") or {}).get("decision_log") or {}
                    ).get("root_height"),
                }
                for p in revocation_paths
            ]
            ages = [
                {
                    "path": p["path"],
                    "seconds": (
                        (p.get("first_refused") or {}).get("decision_log") or {}
                    ).get("root_age_seconds"),
                }
                for p in revocation_paths
            ]
            roots = [
                r for r in roots if r["epoch"] is not None or r["height"] is not None
            ]
            ages = [a for a in ages if a["seconds"] is not None]
            fields["evidence_identity"] = (
                field("measured", roots)
                if roots
                else field(
                    "not_emitted", reason="operator decision-log material unavailable"
                )
            )
            fields["root_age_seconds"] = (
                field("measured", ages) if ages else field("not_emitted")
            )
            limit = manifest.get("deployment", {}).get("max_root_age_seconds")
            fields["freshness_limit_seconds"] = (
                field("measured", limit) if limit is not None else field("not_emitted")
            )
        elif case == "unreachable" and outage_paths:
            fields["decision"] = field("measured", outage_paths)
            fields["recovery"] = field(
                "measured",
                [p.get("first_accepted_after_restore") for p in outage_paths],
            )
            fields["evidence_identity"] = field(
                "not_applicable", reason="no root behind unavailable-state refusal"
            )
            fields["revocation_latency_seconds"] = field("not_applicable")
            fields["root_age_seconds"] = field(
                "not_applicable", reason="no decision root on disconnected path"
            )
        else:
            fields["decision"] = field(
                "not_emitted",
                reason="no published observation for this case in this record",
            )
            fields["evidence_identity"] = field("not_emitted")
            fields["revocation_latency_seconds"] = field("not_measured")
            fields["root_age_seconds"] = field("not_measured")
        cases.append(
            {
                "case_id": case,
                "basis": basis,
                "independent_live_reproduction": False,
                "fields": fields,
            }
        )
    return validate_report(
        {
            "implementation": "MintID",
            "run_id": name,
            "integrity": "PASS" if all(c["match"] for c in checks) else "FAIL",
            "evidence_custody": {
                "producer": "MintID author/operator",
                "public_artifact": "operator trace and summary",
                "appraiser": "Alakris evidence runner",
                "independent_target_observer": False,
            },
            "record_revision": manifest["source"],
            "deployment": manifest.get("deployment"),
            "checks": checks,
            "cases": cases,
        }
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation", choices=["proofable", "mintid"])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--record")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.implementation == "mintid" and not args.record:
        parser.error("--record is required")
    report = (
        proofable(args.evidence)
        if args.implementation == "proofable"
        else mintid(args.evidence, args.record)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "implementation": report["implementation"],
                "integrity": report["integrity"],
                "output": str(args.output),
            }
        )
    )
    return 0 if report["integrity"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
