"""Build TRACE Trust Records from evidence another system produced.

An adapter over a third-party control plane is worth having for one reason: it
states, in a form a machine can read, exactly what that evidence is worth. The
record carries ``origin.kind: third-party-control-plane``,
``runtime.platform: software-only`` and ``appraisal.status: none``, so a consumer
can tell it apart from a record a TEE-backed runtime produced without reading a
word of prose.

That only works if the rest of the record is true. This package exists because
the failure mode is well established: a required-shaped field with nothing real
behind it gets a placeholder. Every constructor here takes bytes rather than
descriptions of bytes, and raises ``MissingEvidence`` rather than degrading.
"""

from __future__ import annotations

from .appraisal import AppraisalEvidence, appraisal_from_evidence
from .builder import TRACE_PROFILE, build_record, software_measurement
from .evidence import (
    DIGEST_RE,
    MissingEvidence,
    PolicyEvidence,
    SourceSystem,
    digest_bytes,
)

__all__ = [
    "AppraisalEvidence",
    "DIGEST_RE",
    "MissingEvidence",
    "PolicyEvidence",
    "SourceSystem",
    "TRACE_PROFILE",
    "appraisal_from_evidence",
    "build_record",
    "digest_bytes",
    "software_measurement",
]

__version__ = "0.1.0"
