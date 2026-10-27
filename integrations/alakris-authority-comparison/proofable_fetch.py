"""Bounded offline appraisal of one immutable, publisher-operated positive fetch.

Packet integrity and signed statements are distinct from scenario conformance,
service-key attribution, independent execution and target-side effect evidence.
No downloaded code, packet URL, vendor API or target is invoked by this module.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

from portable_envelope import verify
from runner import CASES, REQUIRED_FIELDS, digest, field, validate_report

PUBLICATION = "e6eb5b9307be24a5d82cc7490f647f0c98e2d24a"
SOURCE_PATH = "public/evidence/aaif/authority-at-dispatch/2026-10-24-fetch-route"
SOURCE_URL = (
    f"https://raw.githubusercontent.com/proofable/docs/{PUBLICATION}/{SOURCE_PATH}"
)
MAX_FILE_BYTES = 1_048_576
# Independently retained pins, including the publisher's checksum inventory itself.
PINS = {
    "1-invocation.json": "566b2cc841a1c4966bf56ca98f21c4a479476a97172e3287c1572a2f0a59c871",
    "2-request-arguments.json": "8dd4cf11e11a29347ba1d73921a2b2fce0a8ac3ccac56aea860bbf6778d95da7",
    "3-create-response.txt": "2db3795531b68a1f627d5e38d0a99783a2c789fcea0802629a6e4d85466fa1a8",
    "4-dispatch-decision.json": "2970e1c6a1e7291d36bcb752e1b7b2c9416c24eb6e6c699c1dcfd19c2b2e6b5f",
    "5-job-record.json": "40e0bb4a7d75396182b026884f83c350316fa3be6b00bff2ce9ea3cac146d415",
    "6-terminal-receipt.json": "34688c283148a0524b550666fa74839b38410c26fd63425734a2753ba89f040c",
    "README.md": "57dcce249c71c083f43f70f25bae4bf24d0904a201a664da3f4c181c43aeceed",
    "SHA256SUMS": "0a47e2b25bdf5959a774df690098a0d22f73e7d31453099ae53b45c370858f5a",
    "health-at-run.json": "b6849d19f65356cb3da0a1d0d4e840c1e1244830c9c2a637641f0cf7cf468616",
    "verify.mjs": "d1919890e1d5ff3c5da0f552c90e09ef672e514c7f2dc3e35c91276358c926a6",
}
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
HASH = re.compile(r"0x[0-9a-f]{64}\Z")
MODULE_ROOT = Path(__file__).resolve().parent


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(label + " must be a JSON object")
    return value


def _text(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(label + " must be a nonempty string")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous JSON: duplicate key " + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("invalid JSON constant: " + value)


def _json(text, label):
    try:
        value = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 64:
                raise ValueError("JSON nesting exceeds the bounded profile")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("nonfinite JSON number")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except (ValueError, RecursionError) as error:
        raise ValueError(label + ": " + str(error)) from error


def _create_response(text):
    lines = [line for line in text.splitlines() if line]
    if (
        len(lines) != 2
        or lines[0] != "event: message"
        or not lines[1].startswith("data: ")
    ):
        raise ValueError(
            "create response must contain exactly one retained SSE message"
        )
    return _object(_json(lines[1][6:], "create response"), "create response")


def _records(raw):
    records = {}
    for name, content in raw.items():
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(name + ": invalid UTF-8") from error
        if name.endswith(".json"):
            records[name] = _object(_json(text, name), name)
        elif name == "3-create-response.txt":
            records[name] = _create_response(text)
    return records


def _load(base):
    base = Path(base)
    if not base.is_dir() or base.is_symlink():
        raise ValueError("packet must be an existing, non-symlink directory")
    root = base.resolve()
    raw = {}
    for name in PINS:
        path = root / name
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(root)
        ):
            raise ValueError("missing file or unsafe artifact path: " + name)
        with path.open("rb") as source:
            raw[name] = source.read(MAX_FILE_BYTES + 1)
        if len(raw[name]) > MAX_FILE_BYTES:
            raise ValueError("packet file exceeds the bounded size: " + name)
    return raw


def _inventory(content):
    result = {}
    for line in content.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^\s]+)", line)
        if not match or match[2] not in PINS or match[2] == "SHA256SUMS":
            raise ValueError("invalid or unsafe publisher checksum inventory")
        if match[2] in result:
            raise ValueError("duplicate publisher checksum entry: " + match[2])
        result[match[2]] = match[1]
    return result


def _js_stringify(value):
    """JSON.stringify for this packet's string/bool/null/safe-integer profile.

    No Unicode normalization is applied to the request digest. Floating-point
    runtime inputs are outside this bounded profile and rejected, not rounded.
    """
    if value is None or isinstance(value, (str, bool)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        # JS JSON.stringify escapes lone UTF-16 surrogates (well-formed JSON).
        return "".join(
            f"\\u{ord(c):04x}" if 0xD800 <= ord(c) <= 0xDFFF else c for c in text
        )
    if type(value) is int and abs(value) <= 2**53 - 1:
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_js_stringify(item) for item in value) + "]"
    if isinstance(value, dict):

        def index(key):
            return (
                key.isascii()
                and key.isdecimal()
                and str(int(key)) == key
                and int(key) < 2**32 - 1
            )

        numeric = sorted((key for key in value if index(key)), key=int)
        keys = numeric + [key for key in value if not index(key)]
        return (
            "{"
            + ",".join(
                _js_stringify(key) + ":" + _js_stringify(value[key]) for key in keys
            )
            + "}"
        )
    raise ValueError(
        "request projection has a value outside the bounded JSON.stringify profile"
    )


def request_digest(fields):
    """Recompute the published fixed projection, not a raw-file byte digest."""
    fields = _object(fields, "request fields")
    wallet = _text(fields.get("agentWallet"), "agentWallet")
    if not ADDRESS.fullmatch(wallet):
        raise ValueError("agentWallet is not an EVM address")
    acceptance = _object(fields.get("acceptance"), "acceptance")
    approval = fields.get("requiresJobApproval", False)
    if not isinstance(approval, bool):
        raise ValueError("requiresJobApproval must be a boolean")
    projection = {
        "agentId": _text(fields.get("agentId"), "agentId"),
        "agentWallet": wallet.lower(),
        "prompt": _text(fields.get("prompt"), "prompt"),
        "runtime": fields.get("runtime"),
        "requiresJobApproval": approval,
        "acceptance": {
            "criterion": _text(acceptance.get("criterion"), "acceptance.criterion"),
            "mode": _text(acceptance.get("mode"), "acceptance.mode"),
        },
    }
    return hashlib.sha256(_js_stringify(projection).encode("utf-8")).hexdigest()


def _envelope(document, label):
    document = _object(document, label)
    proofs = _object(document.get("data"), label + ".data").get("proofs")
    if (
        document.get("success") is not True
        or not isinstance(proofs, list)
        or len(proofs) != 1
    ):
        raise ValueError(label + " must contain exactly one successful proof")
    envelope = _object(
        _object(proofs[0], label + ".proof").get("portableProof"), label + ".envelope"
    )
    for name in ("did", "walletAddress", "qHash", "signature"):
        _text(envelope.get(name), label + "." + name)
    if not ADDRESS.fullmatch(envelope["walletAddress"]) or not HASH.fullmatch(
        envelope["qHash"]
    ):
        raise ValueError(label + " has an invalid wallet or qHash")
    for name in ("chainId", "signedTimestamp"):
        if type(envelope.get(name)) is not int or not 0 < envelope[name] <= 2**53 - 1:
            raise ValueError(label + "." + name + " must be a positive safe integer")
    verifiers = envelope.get("verifierIds")
    if (
        not isinstance(verifiers, list)
        or not verifiers
        or not all(isinstance(v, str) and v for v in verifiers)
    ):
        raise ValueError(label + " has invalid verifierIds")
    if envelope.get("signatureMethod") != "eip191":
        raise ValueError(label + " is not the supported EIP-191 profile")
    data = _object(envelope.get("data"), label + ".data")
    content = _object(
        _json(
            _text(data.get("content"), label + ".content"), label + " signed content"
        ),
        label + " content",
    )
    return envelope, content


def _semantic_checks(records):
    """Diagnostic checks only; appraise() additionally requires all fixed byte pins.

    Keeping semantic checks separate lets generated-key controls test digest,
    signature and correlation failures without relying on file-hash failures.
    """
    invocation = records["1-invocation.json"]
    request = records["2-request-arguments.json"]
    response = records["3-create-response.txt"]
    result = _object(response.get("result"), "create.result")
    create = _object(result.get("structuredContent"), "create.structuredContent")
    text_content = result.get("content")
    if not isinstance(text_content, list) or len(text_content) != 1:
        raise ValueError("create response must have one text content item")
    text_item = _object(text_content[0], "create.content")
    text_create = _object(
        _json(_text(text_item.get("text"), "create.content.text"), "create text JSON"),
        "create text",
    )
    decision, statement = _envelope(
        records["4-dispatch-decision.json"], "dispatch decision"
    )
    receipt, terminal = _envelope(
        records["6-terminal-receipt.json"], "terminal receipt"
    )
    job = records["5-job-record.json"]
    health = records["health-at-run.json"]
    release = _object(health.get("release"), "health.release")
    signed_result = _object(terminal.get("result"), "terminal.result")
    zeus = _object(signed_result.get("zeus"), "terminal.result.zeus")
    activity = zeus.get("toolActivity")
    if not isinstance(activity, list) or len(activity) != 1:
        raise ValueError("positive fetch profile requires one reported tool action")
    action = _object(activity[0], "tool action")
    action_args = _object(action.get("args"), "tool action.args")
    prompt = _text(request.get("prompt"), "request.prompt")
    url_match = re.fullmatch(
        r"Fetch this exact URL once and reply with its visible text verbatim and nothing else: (https://[^\s]+)",
        prompt,
    )
    if not url_match:
        raise ValueError("request is not the retained single-URL fetch profile")
    url = url_match[1]
    checks = []

    def check(name, valid, scope):
        checks.append({"check": name, "valid": bool(valid), "scope": scope})

    verdicts = {"decision": verify(decision), "receipt": verify(receipt)}
    for name, verdict in verdicts.items():
        check(
            name + "_envelope",
            verdict["valid"],
            "EIP-191/qHash/DID-chain integrity, not service identity",
        )
    check(
        "same_declared_signer_context",
        decision["walletAddress"].lower()
        == receipt["walletAddress"].lower()
        == str(invocation.get("serviceSigner", "")).lower()
        and decision["chainId"] == receipt["chainId"]
        and decision["verifierIds"] == receipt["verifierIds"],
        "publisher-declared signer/context only",
    )
    principal = invocation.get("principal")
    for label, value in (
        ("principal", principal),
        ("decision owner", decision["data"].get("owner")),
        ("receipt owner", receipt["data"].get("owner")),
        ("signed principal", statement.get("principal")),
    ):
        if not ADDRESS.fullmatch(_text(value, label)):
            raise ValueError(label + " is not an EVM address")
    check(
        "same_principal_agent_context",
        decision["data"].get("owner")
        == receipt["data"].get("owner")
        == statement.get("principal")
        == principal
        and statement.get("agentId")
        == terminal.get("agentId")
        == request.get("agentId")
        == invocation.get("agentId")
        == job.get("agentId")
        and statement.get("agentWallet")
        == terminal.get("agentWallet")
        == request.get("agentWallet")
        == invocation.get("agentWallet")
        == job.get("agentWallet"),
        "signed principal/agent fields versus unsigned request/invocation/job",
    )
    check(
        "dispatch_allow_profile",
        statement.get("version") == 1
        and statement.get("kind") == "agent-job-authority-decision"
        and statement.get("action") == "job.dispatch"
        and statement.get("outcome") == "ALLOW"
        and statement.get("jobId") is None
        and statement.get("effect") == "none",
        "positive dispatch statement, no job/effect attestation",
    )
    check(
        "decision_reference_context",
        decision["data"].get("reference")
        == {
            "type": "agent-job-authority-decision",
            "id": str(statement.get("agentId"))
            + ":"
            + str(statement.get("requestedAtMs")),
        },
        "signed decision reference names this agent/request timestamp",
    )
    check(
        "referenced_authority_ids",
        all(
            HASH.fullmatch(str(statement.get(key, "")))
            for key in ("delegationQHash", "agentIdentityQHash")
        ),
        "references are identifiers only; grant/identity proof validation is unestablished",
    )
    check(
        "request_args_digest",
        request_digest(request) == statement.get("argsDigest"),
        "fixed request projection",
    )
    check(
        "receipt_request_digest",
        request_digest(terminal) == statement.get("argsDigest"),
        "same projected request in the signed receipt",
    )
    check(
        "receipt_request_fields",
        terminal.get("prompt") == request.get("prompt")
        and terminal.get("acceptance") == request.get("acceptance")
        and terminal.get("kind") == "agent-job"
        and terminal.get("status") == "completed",
        "signed terminal report of this request, including unsigned-digest alias consistency",
    )
    check(
        "create_response_shape",
        response.get("jsonrpc") == "2.0"
        and type(response.get("id")) is int
        and response["id"] == 1
        and result.get("isError") is False
        and text_item.get("type") == "text"
        and create == text_create
        and create.get("success") is True,
        "unsigned retained MCP response",
    )
    authority_decision = _object(
        create.get("authorityDecision"), "create.authorityDecision"
    )
    check(
        "create_decision_qhash_join",
        create.get("authorityDecisionQHash")
        == authority_decision.get("qHash")
        == decision["qHash"]
        and authority_decision.get("outcome") == statement.get("outcome"),
        "unsigned create-response correlation, not a signed decision-to-job link",
    )
    job_id = _text(terminal.get("jobId"), "terminal.jobId")
    check(
        "receipt_reference_context",
        receipt["data"].get("reference") == {"type": "job", "id": job_id},
        "signed receipt reference names this terminal job",
    )
    check(
        "create_job_join",
        create.get("jobId") == job_id == job.get("jobId") == job.get("runId"),
        "unsigned create response/job versus signed terminal jobId",
    )
    check(
        "job_receipt_consistency",
        job.get("qHash") == job.get("terminalQHash") == receipt["qHash"]
        and job.get("prompt") == terminal.get("prompt")
        and job.get("result") == signed_result
        and job.get("status") == terminal.get("status")
        and job.get("acceptance") == terminal.get("acceptance"),
        "unsigned job record versus signed terminal statement",
    )
    check(
        "reported_fetch",
        action.get("tool") == "proofable_url_fetch"
        and action_args.get("url") == url
        and action.get("ok") is True,
        "service-reported execution, not an executor or target signature",
    )
    marker = signed_result.get("response")
    check(
        "reported_marker",
        isinstance(marker, str)
        and re.fullmatch(r"target-ack [0-9a-f]{20}", marker)
        and request.get("acceptance", {}).get("criterion") == "target-ack",
        "full returned marker is signed only in the terminal statement",
    )
    check(
        "reported_release",
        invocation.get("mcpVersion")
        == release.get("mcpVersion")
        == release.get("imagePackageVersion")
        == "0.1.7"
        and invocation.get("serviceRevision")
        == release.get("deploySha")
        == "18433a48d74af913550de7a018f02c7c724cc1c9"
        and invocation.get("method") == "tools/call"
        and invocation.get("tool") == "proofable_job_create"
        and invocation.get("endpoint") == "https://mcp.proofable.me/mcp",
        "unsigned publisher deployment metadata, not binary attestation",
    )
    return {
        "valid": all(check["valid"] for check in checks),
        "checks": checks,
        "envelopes": verdicts,
        "job_id": job_id,
        "target_url": url,
        "returned_marker": marker,
        "declared_service_signer": decision["walletAddress"],
    }


def appraise(base):
    """Appraise only the fixed publication; no trusted-wallet or hash-bypass flag."""
    raw = _load(base)
    hash_checks = [
        {
            "file": name,
            "expected": expected,
            "actual": hashlib.sha256(raw[name]).hexdigest(),
            "match": hashlib.sha256(raw[name]).hexdigest() == expected,
        }
        for name, expected in PINS.items()
    ]
    inventory_valid = _inventory(raw["SHA256SUMS"]) == {
        name: value for name, value in PINS.items() if name != "SHA256SUMS"
    }
    semantic = _semantic_checks(_records(raw))
    integrity = all(check["match"] for check in hash_checks) and inventory_valid
    cases = []
    for case in CASES:
        reason = (
            "positive author-operated fetch does not exercise the " + case + " scenario"
        )
        cases.append(
            {
                "case_id": case,
                "basis": "author_record",
                "independent_live_reproduction": False,
                "scenario_conformance": "UNMET",
                "unmet_requirements": [reason],
                "fields": {
                    name: field("not_measured", reason=reason)
                    for name in sorted(REQUIRED_FIELDS)
                },
            }
        )
    sources = (
        "proofable_fetch.py",
        "test_proofable_fetch.py",
        "portable_envelope.py",
        "runner.py",
        "fetch_fixtures.py",
        "check_package.py",
        "comparison-contract.json",
    )
    report = {
        "schema": "aaif-authority-comparison/v1",
        "implementation": "Proofable hosted MCP fetch",
        "basis": "author_record",
        "integrity": "PASS" if integrity else "FAIL",
        "publication": {"commit": PUBLICATION, "path": SOURCE_PATH},
        "publisher_deployment_claim": {
            "mcp_version": "0.1.7",
            "service_revision": "18433a48d74af913550de7a018f02c7c724cc1c9",
        },
        "artifact_hashes": hash_checks,
        "publisher_checksum_inventory_valid": inventory_valid,
        "positive_dispatch_appraisal": "PASS"
        if integrity and semantic["valid"]
        else "FAIL",
        "positive_dispatch": semantic,
        "service_key_attribution": field(
            "not_measured",
            reason="no separately verified canonical service-key trust source; declared signer integrity is not attribution",
        ),
        "grant_and_agent_identity_validation": field(
            "not_measured",
            reason="decision names grant and identity qHashes but their proof records are absent",
        ),
        "request_binding": {
            "projection": [
                "agentId",
                "agentWallet (lowercased)",
                "prompt",
                "runtime (default null)",
                "requiresJobApproval (default false)",
                "acceptance.criterion",
                "acceptance.mode",
            ],
            "outside_digest_projection": ["runNowFirst", "acceptance.criteria"],
            "full_returned_marker_precommitted": False,
            "reason": "prompt binds the unique URL, criterion is generic target-ack; full returned marker is signed only in terminal receipt",
        },
        "correlation_only_links": [
            "decision jobId=null; unsigned create response joins decision qHash to jobId",
            "identical requests share argsDigest; URL uniqueness is correlation, not replay prevention",
            "no executor-signed GET; no retained target ingress log",
        ],
        "unmeasured": {
            name: field("not_measured", reason=reason)
            for name, reason in {
                "target_commit": "signed service completion does not establish target-side committed effects",
                "independent_target_witness": "public request-bin logs and an operator-owned observer are absent",
                "revocation_latency": "no revocation timing measurement in this positive run",
                "commit_time_authority": "dispatch-only; no authority recheck in flight or at target commit",
                "EO01_unreachable_authority": "no separately unreachable authority experiment on this locally evaluated path",
            }.items()
        },
        "evidence_custody": {
            "operator": "Proofable",
            "observer": "Proofable",
            "appraisal": "offline local reader",
            "independent_target_observer": False,
        },
        "independent_live_reproduction": False,
        "independent_comparison_completed": False,
        "scenario_conformance": "UNMET",
        "cases": cases,
        "appraiser_source_sha256": {
            name: digest(MODULE_ROOT / name) for name in sources
        },
        "trace_record_emitted": False,
    }
    return validate_report(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="directory containing the ten pinned files",
    )
    parser.add_argument(
        "--output", type=Path, help="separate appraisal JSON (stdout by default)"
    )
    args = parser.parse_args()
    try:
        report = appraise(args.input)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        output = args.output.resolve()
        packet = args.input.resolve()
        if output.is_relative_to(packet):
            parser.error("output must be outside the retained packet directory")
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=output.parent,
                prefix=".proofable-fetch-",
                delete=False,
            ) as destination:
                temporary = Path(destination.name)
                destination.write(rendered)
            # Replace the outside pathname, never write its existing inode: an
            # output hard link to a packet file must not modify retained bytes.
            os.replace(temporary, output)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    else:
        print(rendered, end="")
    return 0 if report["positive_dispatch_appraisal"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
