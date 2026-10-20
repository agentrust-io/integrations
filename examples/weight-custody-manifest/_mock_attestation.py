"""Explicit waivers for demos that run on mock attestation.

These demos use ``SoftwareProvider``: evidence with no hardware behind it and
nothing a verifier could check. From the release after 0.28.4, a manifest
requires cryptographic evidence verification unless it says otherwise, and GPU
confidential-compute mode is met only by a verified GPU report (#159). A mock
cannot meet either, so these manifests say so explicitly, the way a real
deployment on unverified evidence would have to.

On 0.28.4 and earlier the field does not exist and a manifest carrying it is
rejected, so this is a no-op there and the demos behave exactly as before.

From 0.33.0 the key broker seals every release to the enclave's attested
transport key by default (GHSA-x3w3-7mvg-hxw5), so the demos present one and
start custody with ``start_custody``. Earlier releases return the key in the
clear and ``from_release`` takes no transport key, so there it is a plain call.
"""

from __future__ import annotations

import inspect
from typing import Any

from wcm import EnclaveSession
from wcm.models import ReleasePolicy

#: True once the SDK has the requirement these waivers answer.
REQUIRES_VERIFICATION = "require_evidence_verification" in ReleasePolicy.model_fields

#: True once ``from_release`` can open a release sealed to the transport key.
OPENS_SEALED = "transport_private_key" in inspect.signature(EnclaveSession.from_release).parameters


def start_custody(manifest, decision, transport_private_key, **kwargs):
    """Start custody from a release, opening it with the enclave's transport key."""
    if OPENS_SEALED:
        kwargs["transport_private_key"] = transport_private_key
    return EnclaveSession.from_release(manifest, decision, **kwargs)


def waive_mock_verification(doc: dict[str, Any]) -> dict[str, Any]:
    """Add the two waivers to a manifest document, in place, and return it."""
    if REQUIRES_VERIFICATION:
        policy = doc["release_policy"]
        policy["require_evidence_verification"] = False
        gpu = policy.get("required_gpu_measurement")
        if gpu is not None:
            gpu["require_cc_mode"] = False
    return doc
