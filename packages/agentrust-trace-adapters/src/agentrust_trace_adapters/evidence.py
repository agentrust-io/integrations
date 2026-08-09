"""What an adapter is allowed to say it has.

An adapter turns evidence some other system produced into a TRACE Trust Record.
Every field it fills is a claim, and the failure mode is always the same: a
required-shaped field with nothing real to put in it, so a placeholder goes in.
The one adapter that existed before this package emitted
``"sha256:placeholder-no-model"``, ``"sha256:placeholder"``, an all-zero
measurement and a tool-transcript hash that was not a hash. Five of its seven
validation failures were that mistake.

So the types here carry bytes, never names of bytes. If a caller has nothing
real, there is no constructor that accepts nothing real, and the record is not
built. That is the point: a record nobody can make is a truthful outcome, and a
record full of placeholders is not.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

__all__ = [
    "DIGEST_RE",
    "MissingEvidence",
    "PolicyEvidence",
    "SourceSystem",
    "digest_bytes",
]

DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")


class MissingEvidence(ValueError):
    """Raised when a record cannot be built without inventing something.

    Deliberately not a warning and not a fallback. An adapter that degrades to a
    placeholder produces a record that validates, reads as evidence, and is not.
    """


def digest_bytes(data: bytes) -> str:
    """``sha256:`` digest of bytes the caller actually holds."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("digest_bytes takes bytes; hashing a description of bytes is not a digest")
    if not data:
        raise MissingEvidence(
            "refusing to digest empty input: the digest of nothing is a valid-looking "
            "hash of an absence"
        )
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


@dataclass(frozen=True)
class SourceSystem:
    """The system whose evidence this record is built from.

    ``kind`` maps to ``origin.kind`` in the record and is what makes the
    assurance downgrade machine-readable rather than rhetorical. ``self`` is
    rejected here: a runtime describing its own execution does not need an
    adapter, and allowing it would let this package be used to launder a
    first-party record through a path that forces ``software-only``.
    """

    producer: str
    kind: str = "third-party-control-plane"
    source_event_id: str | None = None
    ingested_at: int | None = None

    KINDS = ("third-party-control-plane", "log-import")

    def __post_init__(self) -> None:
        if not self.producer or not self.producer.strip():
            raise MissingEvidence(
                "producer is required: a record built from someone else's evidence has to "
                "name whose evidence it was"
            )
        if self.kind not in self.KINDS:
            raise ValueError(
                f"kind {self.kind!r} is not one of {', '.join(self.KINDS)}. "
                "'self' is not accepted here: a runtime producing its own record does not "
                "need an adapter."
            )
        if self.ingested_at is not None and not (
            1_700_000_000 <= self.ingested_at < 4_000_000_000
        ):
            # Milliseconds are the common mistake and they pass a lower bound
            # alone, which is why there is an upper one. A record timestamped in
            # the year 55000 is not caught by anything downstream.
            raise ValueError(
                f"ingested_at {self.ingested_at} is not plausible Unix seconds "
                "(milliseconds are the usual cause)"
            )

    def to_origin(self) -> dict[str, object]:
        block: dict[str, object] = {"kind": self.kind, "producer": self.producer}
        if self.source_event_id is not None:
            block["source_event_id"] = self.source_event_id
        if self.ingested_at is not None:
            block["ingested_at"] = self.ingested_at
        return block


@dataclass(frozen=True)
class PolicyEvidence:
    """The policy that was in force, as bytes.

    ``policy.bundle_hash`` is a digest of the policy bundle. It is not a digest
    of the policy's name, its version string, or the decision it produced, and a
    consumer comparing two records by ``bundle_hash`` is entitled to assume the
    bundles were the same bundle.

    Most third-party control planes do not put the bundle in their telemetry.
    That is not a reason to hash something else, so this class takes only bytes,
    and the deployment supplies them: an operator knows the policy it runs even
    when its vendor's export does not carry it.
    """

    bundle: bytes
    enforcement_mode: str = "enforce"
    version: str | None = None
    policy_uri: str | None = None

    MODES = ("enforce", "advisory", "silent")

    def __post_init__(self) -> None:
        if not isinstance(self.bundle, (bytes, bytearray)) or not self.bundle:
            raise MissingEvidence(
                "PolicyEvidence needs the policy bundle bytes. If the producing system "
                "does not expose them, supply the bundle your deployment enforces; if you "
                "cannot, this record cannot honestly carry a policy.bundle_hash and should "
                "not be built."
            )
        if self.enforcement_mode not in self.MODES:
            raise ValueError(
                f"enforcement_mode {self.enforcement_mode!r} is not one of "
                f"{', '.join(self.MODES)}"
            )

    @property
    def bundle_hash(self) -> str:
        return digest_bytes(self.bundle)

    def to_policy(self) -> dict[str, object]:
        block: dict[str, object] = {
            "bundle_hash": self.bundle_hash,
            "enforcement_mode": self.enforcement_mode,
        }
        if self.version is not None:
            block["version"] = self.version
        if self.policy_uri is not None:
            block["policy_uri"] = self.policy_uri
        return block
