#!/usr/bin/env python3
"""Weight Custody Manifest <-> in-toto Attestation Statement v1.

Supply-chain tooling already knows how to move in-toto Statements around. They
ride in OCI referrers, DSSE envelopes, Rekor entries, GitHub attestations and
`slsa-verifier`, and none of that machinery needs to learn a new document format
to carry a custody manifest. This module makes a WCM manifest travel that way.

**The predicate embeds the signed manifest verbatim.** That is the whole design
decision, and it is worth being explicit about why.

A DSSE envelope is signed by whoever built the attestation. A WCM manifest is
jointly signed by the builder and the custodian, and, under a sovereign profile,
by a quorum. Those are different trust roots answering different questions. If
this module summarized the manifest into predicate fields, a consumer verifying
only the DSSE signature would be trusting the attestation builder's transcription
of custody terms rather than the parties who actually agreed them, and the
jointly-signed original would be unrecoverable.

So the predicate carries the manifest whole, signatures included. The DSSE layer
is transport. ``verify_statement`` re-verifies the embedded manifest against
WCM's own trust context and refuses a statement whose subject digest disagrees
with the manifest's ``weights_hash``, which is the attack this shape invites:
a real manifest stapled to a different artifact.

**What an in-toto wrapper does not do.** It does not extend WCM's guarantee, add
attestation, or make an unverified manifest verified. It moves a document. A
consumer that checks the DSSE signature and stops has verified who built the
envelope, nothing about custody.

Usage::

    pip install weight-custody-manifest

    # wrap
    python wcm_in_toto.py wrap manifest.json --name example-8b > statement.json

    # verify, supplying the keys you trust for builder and custodian
    python wcm_in_toto.py verify statement.json --public-key builder.pub --public-key custodian.pub
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Any

from wcm import (
    VerificationContext,
    WeightCustodyManifest,
    canonical_hash,
    verify_manifest,
)

__all__ = [
    "STATEMENT_TYPE",
    "PREDICATE_TYPE",
    "StatementError",
    "StatementVerification",
    "build_statement",
    "verify_statement",
    "manifest_from_statement",
]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: The predicate type for a WCM manifest. Versioned separately from the manifest
#: schema: the schema is frozen at v1 and additive-only, and this URI names the
#: *wrapping*, so a future change to how the manifest is embedded gets /v2
#: without implying the manifest schema moved.
PREDICATE_TYPE = "https://wcm.agentrust-io.com/attestation/manifest/v1"

#: in-toto digest keys, by the hash WCM used. WCM permits sha256 and shake256
#: (SPEC 3.1); in-toto's digest set has no registered shake256 name, so a
#: shake256 manifest is refused rather than filed under a key no verifier reads.
_DIGEST_ALGORITHMS = {"sha256": "sha256"}


class StatementError(ValueError):
    """Raised when a statement cannot be built or trusted."""


@dataclass(frozen=True)
class StatementVerification:
    """Outcome of checking a statement, with the two questions kept apart."""

    subject_matches: bool
    manifest_verified: bool
    manifest: WeightCustodyManifest | None
    reason: str | None = None
    #: Non-blocking advisories from ``verify_manifest`` about what the manifest
    #: actually protects (an open base, a symmetric BYOM posture). They never
    #: change the verdict, and dropping them would let a statement be read as
    #: promising more than the manifest delivers.
    notes: tuple[str, ...] = ()

    @property
    def trusted(self) -> bool:
        return self.subject_matches and self.manifest_verified


def _split_hash(value: str) -> tuple[str, str]:
    algorithm, _, digest = value.partition(":")
    if algorithm not in _DIGEST_ALGORITHMS or not digest:
        raise StatementError(
            f"weights_hash uses {algorithm!r}, which has no in-toto digest-set name. "
            "in-toto subjects are keyed by algorithm, and filing a shake256 digest "
            "under 'sha256' would make every verifier compare the wrong bytes. "
            "Re-issue the manifest with sha256 to publish it as an attestation."
        )
    return _DIGEST_ALGORITHMS[algorithm], digest


def build_statement(
    manifest: WeightCustodyManifest,
    *,
    name: str,
    annotations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap a manifest as an in-toto Statement whose subject is the weights.

    ``name`` is the artifact name a consumer will see. It is required because
    in-toto subjects are (name, digest) pairs and a manifest carries no artifact
    name: WCM identifies weights by digest, deliberately, so that renaming a file
    changes nothing. Supply the name your distribution channel uses.

    ``annotations`` is passed through to a ``wcm.annotations`` block for local
    bookkeeping. It is not part of the custody agreement and is never read by
    ``verify_statement``, which is why it lives beside the manifest rather than
    inside it.
    """
    if not name or not name.strip():
        raise StatementError(
            "name is required. in-toto subjects are (name, digest) pairs and a WCM "
            "manifest deliberately carries no artifact name."
        )
    algorithm, digest = _split_hash(manifest.weights_hash)
    document = manifest.model_dump(mode="json", exclude_none=True)

    predicate: dict[str, Any] = {
        # The jointly-signed original, whole. See the module docstring.
        "manifest": document,
        # A convenience index, not an authority. Everything here is also in
        # `manifest`, and `verify_statement` reads only `manifest`.
        "summary": {
            "manifest_version": manifest.manifest_version,
            "builder": manifest.builder.identity,
            "custodian": manifest.custody.custodian,
            "custodian_type": manifest.custody.custodian_type.value,
            "deployment_model": manifest.deployment_model.value,
            "base_confidentiality": manifest.base_confidentiality.value,
            "required_hw_platform": list(manifest.release_policy.required_hw_platform),
            "key_release_mode": manifest.release_policy.key_release_mode.value,
            "signature_count": len(manifest.signatures),
            "derived_from": manifest.derived_from,
        },
        # Binds the predicate to the exact document bytes, so a statement whose
        # `manifest` block was edited after signing is detectable even before
        # the WCM signatures are checked.
        "manifest_hash": canonical_hash(document),
    }
    if annotations:
        predicate["annotations"] = annotations

    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {algorithm: digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def manifest_from_statement(statement: dict[str, Any]) -> WeightCustodyManifest:
    """Recover the embedded manifest, with the statement shape checked first."""
    if statement.get("_type") != STATEMENT_TYPE:
        raise StatementError(f"not an in-toto Statement v1: _type is {statement.get('_type')!r}")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise StatementError(
            f"predicateType is {statement.get('predicateType')!r}, not {PREDICATE_TYPE}. "
            "Another predicate may legitimately describe these weights; it is not a "
            "custody manifest and must not be read as one."
        )
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or "manifest" not in predicate:
        raise StatementError("predicate carries no manifest block")
    try:
        return WeightCustodyManifest.model_validate(predicate["manifest"])
    except Exception as exc:  # pydantic ValidationError, kept narrow at the edge
        raise StatementError(f"embedded manifest is not a valid WCM manifest: {exc}") from exc


def verify_statement(
    statement: dict[str, Any], context: VerificationContext
) -> StatementVerification:
    """Check the subject binding and the manifest's own joint signatures.

    Two independent questions, reported separately so a caller cannot collapse
    them by accident:

    1. Does the statement's subject digest equal the manifest's ``weights_hash``?
       A mismatch is the attack this format invites: a genuine, correctly signed
       manifest stapled to a different artifact.
    2. Do the manifest's builder and custodian signatures verify against keys the
       caller trusts? This is WCM's own guarantee and is untouched by any DSSE
       signature wrapped around the statement.

    A DSSE envelope's signature is deliberately not checked here. That is the
    envelope tooling's job, it answers a different question (who built this
    attestation), and conflating the two is how a consumer ends up trusting a
    transcription instead of the parties who signed the custody terms.
    """
    manifest = manifest_from_statement(statement)

    subjects = statement.get("subject") or []
    algorithm, digest = _split_hash(manifest.weights_hash)
    subject_matches = any(
        isinstance(entry, dict) and (entry.get("digest") or {}).get(algorithm) == digest
        for entry in subjects
    )

    recorded = (statement.get("predicate") or {}).get("manifest_hash")
    if recorded is not None:
        actual = canonical_hash(manifest.model_dump(mode="json", exclude_none=True))
        if recorded != actual:
            return StatementVerification(
                subject_matches=subject_matches,
                manifest_verified=False,
                manifest=manifest,
                reason="predicate.manifest_hash does not match the embedded manifest",
            )

    result = verify_manifest(manifest, context)
    reason: str | None = None
    if not subject_matches:
        reason = "subject digest does not match the manifest weights_hash"
    elif not result.ok:
        detail = "; ".join(result.errors) or "no trusted signature for a required role"
        reason = f"manifest did not verify against the supplied trust context: {detail}"
    return StatementVerification(
        subject_matches=subject_matches,
        manifest_verified=bool(result.ok),
        manifest=manifest,
        reason=reason,
        notes=tuple(result.notes),
    )


def _public_key_context(paths: list[pathlib.Path]) -> VerificationContext:
    """Trust the given raw Ed25519 PUBLIC keys, accepting hex or base64url.

    Public key material only. Nothing here reads, holds or emits a private key,
    and the parameter is named so that stays obvious to a reader and to static
    analysis.
    """
    context = VerificationContext()
    for path in paths:
        raw = path.read_bytes().strip()
        try:
            material = bytes.fromhex(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            try:
                text = raw.decode("ascii")
                material = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
            except Exception as exc:
                raise StatementError(f"{path}: not hex or base64url Ed25519 key material") from exc
        context.add_key(material)
    return context


def _report(**fields: object) -> str:
    """Serialize a CLI report from primitives only.

    Every value is coerced to bool, str or None here rather than being passed
    through from a result object. Nothing in this file puts key material in a
    result, and this makes that structural instead of a property of the current
    code: an attribute added later cannot reach stdout by being included in a
    dict comprehension somebody wrote in a hurry.
    """
    safe: dict[str, object] = {}
    for name, value in fields.items():
        if isinstance(value, bool) or value is None:
            safe[name] = value
        elif isinstance(value, (list, tuple)):
            safe[name] = [str(item) for item in value]
        else:
            safe[name] = str(value)
    return json.dumps(safe, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WCM manifest <-> in-toto Statement v1")
    sub = parser.add_subparsers(dest="command", required=True)

    wrap = sub.add_parser("wrap", help="Wrap a manifest as an in-toto Statement")
    wrap.add_argument("manifest", type=pathlib.Path)
    wrap.add_argument("--name", required=True, help="artifact name for the in-toto subject")

    check = sub.add_parser("verify", help="Verify subject binding and manifest signatures")
    check.add_argument("statement", type=pathlib.Path)
    check.add_argument(
        "--public-key",
        dest="public_key",
        type=pathlib.Path,
        action="append",
        default=[],
        help="raw Ed25519 PUBLIC key (hex or base64url); repeat for builder and custodian",
    )

    args = parser.parse_args(argv)

    if args.command == "wrap":
        manifest = WeightCustodyManifest.model_validate_json(
            args.manifest.read_text(encoding="utf-8")
        )
        print(json.dumps(build_statement(manifest, name=args.name), indent=2, sort_keys=True))
        return 0

    statement = json.loads(args.statement.read_text(encoding="utf-8"))
    outcome = verify_statement(statement, _public_key_context(args.public_key))
    print(
        _report(
            trusted=outcome.trusted,
            subject_matches=outcome.subject_matches,
            manifest_verified=outcome.manifest_verified,
            reason=outcome.reason,
            notes=outcome.notes,
        )
    )
    return 0 if outcome.trusted else 1


if __name__ == "__main__":
    sys.exit(main())
