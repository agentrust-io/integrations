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
from .gap_reconciler import (
    GAP_DISCLOSURE_UNVERIFIED,
    RECEIPT_GAP_DISCLOSED,
    RECEIPT_INVALID,
    RECEIPT_MISSING_REQUIRED,
    DisclosureVerdict,
    MalformedInput,
    Reconciliation,
    reconcile_chain,
    verify_disclosure,
)
from .openshell import (
    OpenShellEvidence,
    build_openshell_record,
    build_policy_bundle,
    build_transcript,
)

__all__ = [
    "AppraisalEvidence",
    "DIGEST_RE",
    "DisclosureVerdict",
    "GAP_DISCLOSURE_UNVERIFIED",
    "MalformedInput",
    "MissingEvidence",
    "OpenShellEvidence",
    "PolicyEvidence",
    "RECEIPT_GAP_DISCLOSED",
    "RECEIPT_INVALID",
    "RECEIPT_MISSING_REQUIRED",
    "Reconciliation",
    "SourceSystem",
    "TRACE_PROFILE",
    "appraisal_from_evidence",
    "build_record",
    "build_openshell_record",
    "build_policy_bundle",
    "build_transcript",
    "digest_bytes",
    "reconcile_chain",
    "software_measurement",
    "verify_disclosure",
]

__version__ = "0.2.0"
