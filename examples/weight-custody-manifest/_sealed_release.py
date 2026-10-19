"""Open the enclave's sealed release before starting local mock custody.

Use the public sealing API so these examples also run with SDK versions whose
``from_release`` method predates its transport-private-key argument.
"""
from __future__ import annotations

from dataclasses import replace

from wcm import EnclaveSession, open_sealed


def start_custody(manifest, decision, transport_private, **kwargs):
    if not decision.released or decision.key is not None or decision.sealed_key is None:
        raise ValueError("expected a released, sealed-only decision")
    local = replace(decision, key=open_sealed(decision.sealed_key, transport_private))
    return EnclaveSession.from_release(manifest, local, **kwargs)
