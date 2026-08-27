#!/usr/bin/env python3
"""Bind an Agent Manifest's model identity to a Weight Custody Manifest.

An Agent Manifest declares what an agent is, and artifact #4, ``model_identity``,
names the model it runs on. For a ``confidential-inference`` deployment the spec
requires ``model_hash`` and ``model_attestation_type: hash-bound``. A Weight
Custody Manifest binds exactly that digest as ``weights_hash``.

The two grammars agree exactly: both define ``HashValue`` as
``(sha256|shake256):<64 lowercase hex>``. So the value transfers with no
conversion, no re-hashing and no width problem, which is not true of most pairs
in this repository. There is a test asserting the patterns are identical rather
than merely similar, because a divergence would be silent.

**What a matching digest does and does not mean.**

It means the two documents describe the same weights. It does **not** mean the
agent obtained those weights under custody. An Agent Manifest is signed at
deployment and says what the agent is; whether a key was ever released to an
attested workload is a WCM Layer 2 fact belonging to the broker, and whether it
is still authorized is Layer 3.

An agent whose ``model_hash`` matches a WCM manifest is an agent making a
checkable claim about which weights it runs. That is worth having, and it is a
smaller claim than "custody was enforced". ``verify_binding`` returns a result
that says so in its field names rather than collapsing to a boolean.

Usage::

    pip install weight-custody-manifest agent-manifest

    from wcm_agent_manifest import model_identity_from_wcm

    binding = model_identity_from_wcm(
        wcm_manifest,
        provider="example-labs",
        model_id="example-8b-instruct",
        version="2026-08",
    )
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from wcm import BaseConfidentiality, WeightCustodyManifest

__all__ = [
    "CUSTODY_DEPLOYMENT_TYPES",
    "BindingError",
    "BindingResult",
    "model_identity_from_wcm",
    "verify_binding",
    "hash_grammars_agree",
]

#: Deployment types for which a WCM manifest is meaningful.
#:
#: ``api`` and ``third-party-api`` are excluded by the Agent Manifest spec
#: itself: those deployments must have a null ``model_hash``, because the weights
#: are the provider's and the caller never holds them. A WCM manifest describes
#: weights somebody deployed, so pairing one with an API deployment is a category
#: error rather than a configuration choice.
CUSTODY_DEPLOYMENT_TYPES = ("local", "confidential-inference")


class BindingError(ValueError):
    """Raised rather than producing a binding that cannot mean what it says."""


@dataclass(frozen=True)
class BindingResult:
    """Deliberately not a boolean. See the module docstring."""

    #: The Agent Manifest names the digest this WCM manifest binds.
    digest_matches: bool
    #: The deployment type is one where holding weights is meaningful.
    deployment_type_is_custodial: bool
    #: The Agent Manifest declares hash-bound rather than provider-asserted.
    hash_bound: bool
    agent_model_hash: str | None
    wcm_weights_hash: str
    notes: tuple[str, ...] = ()

    @property
    def describes_the_same_weights(self) -> bool:
        """True when the documents agree on which bytes are in play.

        Named at length on purpose. It is not ``verified``, ``trusted`` or
        ``custody_enforced``: none of those follow from two documents carrying
        the same digest, and a shorter name would invite a caller to read one of
        them into it.
        """
        return self.digest_matches and self.deployment_type_is_custodial and self.hash_bound


def hash_grammars_agree() -> bool:
    """Whether the two SDKs define ``HashValue`` identically.

    Called by ``model_identity_from_wcm`` so a future divergence surfaces as a
    refusal at binding time rather than as a value that silently fails to
    validate somewhere downstream.
    """
    from agent_manifest import HashValue as AgentHashValue
    from wcm._types import HashValue as WcmHashValue

    return AgentHashValue._PATTERN.pattern == WcmHashValue._PATTERN.pattern


def model_identity_from_wcm(
    manifest: WeightCustodyManifest,
    *,
    provider: str,
    model_id: str,
    version: str,
    deployment_type: str = "confidential-inference",
    quantization: str = "none",
    bound_at: dt.datetime | None = None,
    **extra: Any,
) -> Any:
    """Build a ``ModelIdentityBinding`` whose ``model_hash`` is the bound weights.

    ``provider``, ``model_id`` and ``version`` have no source in a WCM manifest,
    which binds a digest and a builder identity rather than a catalogue entry, so
    all three are required. ``builder.identity`` is deliberately not used as a
    default: it names who signed the custody terms, which is frequently not who
    publishes the model under a product name.

    ``bound_at`` defaults to now. Unlike the OCI referrer, this document is a
    deployment record rather than a reproducible artifact, and the spec requires
    the field.
    """
    try:
        from agent_manifest import (
            DeploymentType,
            ModelAttestationType,
            ModelIdentityBinding,
        )
    except ModuleNotFoundError as exc:
        raise BindingError(
            "agent-manifest is required to build a ModelIdentityBinding. "
            "verify_binding works on an already-parsed manifest document without it."
        ) from exc

    if not hash_grammars_agree():
        raise BindingError(
            "the WCM and Agent Manifest HashValue grammars no longer match. This "
            "binding relies on a weights_hash being a valid model_hash verbatim; "
            "re-check both before copying digests between them."
        )
    if deployment_type not in CUSTODY_DEPLOYMENT_TYPES:
        raise BindingError(
            f"deployment_type {deployment_type!r} must be one of "
            f"{', '.join(CUSTODY_DEPLOYMENT_TYPES)}. An api deployment must have a null "
            "model_hash because the weights are the provider's and the caller never "
            "holds them, so there is nothing for a custody manifest to describe."
        )
    if not all((provider, model_id, version)):
        raise BindingError(
            "provider, model_id and version are required. A WCM manifest binds a digest "
            "and a builder identity, not a model catalogue entry."
        )

    return ModelIdentityBinding(
        provider=provider,
        model_id=model_id,
        version=version,
        quantization=quantization,
        deployment_type=DeploymentType(deployment_type),
        model_hash=manifest.weights_hash,
        model_attestation_type=ModelAttestationType.hash_bound,
        bound_at=bound_at or dt.datetime.now(dt.timezone.utc),
        **extra,
    )


def verify_binding(
    agent_manifest_document: dict[str, Any], manifest: WeightCustodyManifest
) -> BindingResult:
    """Check an Agent Manifest document against a WCM manifest.

    Takes a plain document rather than a parsed object, so this works on a
    manifest fetched as JSON without the Agent Manifest SDK installed, and so a
    document that fails Agent Manifest validation for unrelated reasons can still
    be checked for this one property.

    It does not verify the Agent Manifest's own signatures. That is
    ``agent_manifest.verify_manifest``'s job, answering a different question, and
    a caller must run both: an unsigned Agent Manifest naming the right digest
    proves only that somebody wrote the right digest down.
    """
    artifacts = agent_manifest_document.get("artifacts") or {}
    model_identity = artifacts.get("model_identity") or {}
    agent_hash = model_identity.get("model_hash")
    deployment_type = model_identity.get("deployment_type")
    attestation_type = model_identity.get("model_attestation_type")

    notes: list[str] = []
    if not model_identity:
        notes.append(
            "the Agent Manifest declares no model_identity artifact, so it makes no "
            "claim about which weights it runs on"
        )
    if deployment_type in ("api", "third-party-api"):
        notes.append(
            f"deployment_type is {deployment_type!r}: the weights are the provider's and "
            "the agent never holds them, so a custody manifest describes something this "
            "agent is not doing"
        )
    if manifest.base_confidentiality is BaseConfidentiality.open:
        notes.append(
            "the WCM manifest declares base_confidentiality: open, so the digest binding "
            "is an integrity claim rather than a confidentiality one"
        )

    return BindingResult(
        digest_matches=agent_hash == manifest.weights_hash,
        deployment_type_is_custodial=deployment_type in CUSTODY_DEPLOYMENT_TYPES,
        hash_bound=attestation_type == "hash-bound",
        agent_model_hash=agent_hash,
        wcm_weights_hash=manifest.weights_hash,
        notes=tuple(notes),
    )
