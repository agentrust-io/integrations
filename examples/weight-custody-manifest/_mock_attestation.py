"""Explicit waivers for demos that run on mock attestation.

These demos use ``SoftwareProvider``: evidence with no hardware behind it and
nothing a verifier could check. From the release after 0.28.4, a manifest
requires cryptographic evidence verification unless it says otherwise, and GPU
confidential-compute mode is met only by a verified GPU report (#159). A mock
cannot meet either, so these manifests say so explicitly, the way a real
deployment on unverified evidence would have to.

On 0.28.4 and earlier the field does not exist and a manifest carrying it is
rejected, so this is a no-op there and the demos behave exactly as before.
"""

from __future__ import annotations

from typing import Any

from wcm.models import ReleasePolicy

#: True once the SDK has the requirement these waivers answer.
REQUIRES_VERIFICATION = "require_evidence_verification" in ReleasePolicy.model_fields


def waive_mock_verification(doc: dict[str, Any]) -> dict[str, Any]:
    """Add the two waivers to a manifest document, in place, and return it."""
    if REQUIRES_VERIFICATION:
        policy = doc["release_policy"]
        policy["require_evidence_verification"] = False
        gpu = policy.get("required_gpu_measurement")
        if gpu is not None:
            gpu["require_cc_mode"] = False
    return doc
