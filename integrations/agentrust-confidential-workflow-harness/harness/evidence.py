from __future__ import annotations
import hashlib
import json
from .model import RunResult

def canonical_json(data: object) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()

def evidence_digest(result: RunResult) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(result.to_dict())).hexdigest()

def validate_no_sensitive_values(
    result: RunResult,
    forbidden_values: tuple[str, ...],
) -> None:
    payload = canonical_json(result.to_dict()).decode()
    for value in forbidden_values:
        if value and value in payload:
            raise ValueError("public evidence contains forbidden protected material")
