"""Build a TRACE Trust Record from another system's evidence.

Three things are not parameters, because an adapter that could set them would
eventually set them wrong:

``runtime.platform`` is always ``software-only``. A record assembled from a log
has no quote to present. TRACE v0.7.0 rejects any other platform on a record
whose ``origin.kind`` is not ``self``, so this is not merely a convention here.

``appraisal.status`` is always ``none``. Transcribing a control plane's output is
not appraising it, and ``affirming`` would put a verdict in the field a consumer
reads to find out whether anybody checked. A vendor's own allow/deny is a policy
decision about a request; it is not an appraisal of the evidence for that
decision. The two get conflated constantly and the field only means the second.

``build_provenance.slsa_level`` is always ``0``. An importer has no build to
attest.

Everything else comes from bytes the caller holds, or is omitted. Nothing here
invents a digest.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from .evidence import DIGEST_RE, MissingEvidence, PolicyEvidence, SourceSystem

__all__ = ["TRACE_PROFILE", "build_record", "software_measurement"]

TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"

_SUBJECT_RE = re.compile(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$")


def software_measurement(*parts: str) -> str:
    """A content commitment over the identifying inputs, not a hardware measurement.

    ``runtime.measurement`` is required by the schema and there is no hardware
    measurement to put in it. The same shape as the sandbox adapter in
    ``agentrust-trace``: derive a deterministic digest over what the producer
    actually identified, so two records over the same inputs agree and a changed
    input is visible, and let ``platform: software-only`` carry the fact that
    nothing measured it.

    An all-zero or random value would satisfy the schema and mean nothing. This
    at least means something, and the platform field stops it being mistaken for
    a measurement.
    """
    if not parts or any(not p for p in parts):
        raise MissingEvidence(
            "software_measurement needs the identifying inputs; a measurement over "
            "nothing is a placeholder with extra steps"
        )
    return "sha256:" + hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def build_record(
    *,
    source: SourceSystem,
    subject: str,
    model_provider: str,
    model_id: str,
    policy: PolicyEvidence,
    data_class: str,
    jwk: dict[str, Any],
    model_version: str | None = None,
    model_weights_digest: str | None = None,
    transcript_bytes: bytes | None = None,
    tool_call_count: int | None = None,
    transcript_uri: str | None = None,
    workload_digest: str | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """Assemble the record. Raises rather than filling a field with a placeholder.

    ``jwk`` is the public confirmation key the record will be signed with. This
    package does not sign: signing belongs to ``agentrust_trace.sign``, and an
    adapter that both assembles and signs invites a caller to skip looking at
    what it assembled.

    ``workload_digest`` is ``build_provenance.digest``, required by the schema. If
    the producing system reports the image or artifact digest it ran, pass it. If
    it does not, the record cannot state what was built, and this raises rather
    than inventing one.
    """
    if not _SUBJECT_RE.match(subject or ""):
        raise ValueError(
            f"subject {subject!r} must be a SPIFFE URI or a DID. The identity of the "
            "workload is not something an adapter may make up."
        )
    if not model_provider or not model_id:
        raise MissingEvidence(
            "model_provider and model_id are required. If the source evidence does not "
            "identify the model, it cannot support a record that names one."
        )
    if model_weights_digest is not None and not DIGEST_RE.match(model_weights_digest):
        raise ValueError(
            f"model_weights_digest {model_weights_digest!r} is not a sha256:/sha384: "
            "digest. Omit it instead: weights_digest is optional, and an absent field is "
            "the truth where a placeholder is a claim."
        )
    if workload_digest is None:
        raise MissingEvidence(
            "build_provenance.digest is required by the schema and there is nothing "
            "truthful to default it to. Pass the artifact or image digest the producing "
            "system reports, or the digest of the deployment you are attesting."
        )
    if not DIGEST_RE.match(workload_digest):
        raise ValueError(f"workload_digest {workload_digest!r} is not a sha256:/sha384: digest")

    record: dict[str, Any] = {
        "eat_profile": TRACE_PROFILE,
        "iat": int(iat if iat is not None else time.time()),
        "subject": subject,
        "model": {"provider": model_provider, "model_id": model_id},
        "runtime": {
            "platform": "software-only",
            "measurement": software_measurement(source.producer, subject, policy.bundle_hash),
        },
        "policy": policy.to_policy(),
        "data_class": data_class,
        "origin": source.to_origin(),
        "build_provenance": {"slsa_level": 0, "digest": workload_digest},
        "appraisal": {"status": "none", "verifier": source.producer},
        "cnf": {"jwk": jwk},
    }

    if model_version is not None:
        record["model"]["version"] = model_version
    if model_weights_digest is not None:
        record["model"]["weights_digest"] = model_weights_digest

    # tool_transcript is optional. An adapter with no transcript omits the block
    # rather than emitting a hash of nothing with call_count 0, which reads as
    # "we looked and there were no tool calls".
    if transcript_bytes is not None:
        from .evidence import digest_bytes

        transcript: dict[str, Any] = {"hash": digest_bytes(transcript_bytes)}
        if tool_call_count is not None:
            transcript["call_count"] = tool_call_count
        if transcript_uri is not None:
            transcript["transcript_uri"] = transcript_uri
        record["tool_transcript"] = transcript
    elif tool_call_count is not None or transcript_uri is not None:
        raise MissingEvidence(
            "tool_call_count and transcript_uri describe a transcript, so they need the "
            "transcript bytes to hash. A count without a hash is an unbound assertion."
        )

    # transparency is omitted, not empty. The record is unanchored until something
    # anchors it, and "" is not a URI.
    return record
