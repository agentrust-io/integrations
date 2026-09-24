"""delegation_verify: check one AuthorityDelegationV1 chain against an expected leaf reference.

An APS action receipt or any other APS artifact can name a ``delegation_ref``,
the id of the ``AuthorityDelegationV1`` record it claims as its authority.
Checking that reference by string equality against a receipt says nothing
about whether the delegation it names is itself a valid, currently active
grant of authority. This module is that other check. Given the actual
root-to-leaf chain a ``delegation_ref`` points at, it reports whether that
chain is valid, and whether its leaf is the record the caller expected.

The chain check itself is ``agent_passport.verify_authority_delegation_chain``,
from the released SDK. This module adds exactly one thing on top. It
compares the chain's leaf ``delegation_id`` against the caller's expected
``delegation_ref`` before anything else runs, because a chain whose leaf is
not the record the caller named is not evidence about that caller's
question, whatever else is true about the chain. That check is reported
under this module's own failure code, ``DELEGATION_REF_MISMATCH``, never
under one of the SDK's own chain-verification codes, so a reader can always
tell which side of this boundary a failure came from.

Everything else is exactly the SDK's own outcome, unchanged. The same
``state`` (``valid``, ``invalid``, ``indeterminate`` or ``unsupported``), the
same ``AuthorityFailure`` objects, and the same ``code``, ``message``,
``index`` and ``facet``. Nothing here maps ``indeterminate`` or
``unsupported`` to ``valid``, and nothing here inspects a failure's meaning
and decides it does not count. A caller reading ``.valid`` sees ``True``
only when ``state == "valid"``, the same property the SDK's own result type
already exposes.

What this module does not do:

- It does not verify an APS action receipt, or read one. A receipt verifier
  is a separate concern with a separate result, composed with this one, not
  merged into it.
- It does not decide whether the delegation's scope authorizes any
  particular action. Scope is one of the seven facets the chain verifier
  already compares parent to child. This module reads that result and adds
  no authority evaluation of its own.
- It does not evaluate more than the one chain it is given. Two chains
  presented as a single concatenated list are not two chains merged into
  wider combined authority. They are one chain to
  ``verify_authority_delegation_chain``, and a record whose
  ``parent_delegation_id`` does not name the immediate previous record's
  id fails that chain's own linkage check the same way any other malformed
  chain does. This module has no code path that evaluates two chains
  together and reports the union of what each alone would allow.
- It does not make an APS delegation a TRACE record, and it emits no TRACE
  record. Nothing here calls ``agentrust_trace``.
"""
from __future__ import annotations

from typing import Any, Callable, Sequence

from agent_passport import AuthorityFailure, AuthorityValidationResult, verify_authority_delegation_chain

#: This module's own failure code for a chain whose leaf does not carry the
#: caller's expected delegation_ref. Never one of the SDK's own chain
#: verification codes, so it cannot be mistaken for one.
DELEGATION_REF_MISMATCH = "DELEGATION_REF_MISMATCH"

#: The four states ``verify_authority_delegation_chain`` reports, carried
#: through unchanged. Re-exported here so a caller of this module does not
#: need a second import from ``agent_passport`` to spell them.
VALID = "valid"
INVALID = "invalid"
INDETERMINATE = "indeterminate"
UNSUPPORTED = "unsupported"
STATES = (VALID, INVALID, INDETERMINATE, UNSUPPORTED)

#: ``resolve_revocation(delegation)`` answers this member's revocation state.
#: Only the exact string ``"active"`` or ``"revoked"`` counts as that
#: outcome. Anything else, including the string ``"unknown"``, ``None``, a
#: stale cached answer, or a raised exception, reaches
#: ``verify_authority_delegation_chain`` as unknown and is reported as
#: ``indeterminate`` with code ``REVOCATION_UNKNOWN``. This module changes
#: none of that. It passes the caller's resolver straight through.
RevocationResolver = Callable[[dict], str]


def verify_delegation_authority(
    chain: Sequence[dict],
    *,
    expected_delegation_ref: str,
    now: str,
    resolve_verification_key: Callable[[str, str, str], Any],
    trust_root: Callable[[dict], bool],
    resolve_revocation: RevocationResolver,
) -> AuthorityValidationResult:
    """Verify one AuthorityDelegationV1 chain and that its leaf matches the expected reference.

    Arguments
    ---------
    chain
        The root-to-leaf ``AuthorityDelegationV1`` records, in order. Exactly
        one chain per call. Presenting two chains concatenated is not a
        supported way to combine their authority, and does not verify valid
        by way of any special case in this module. See "What this module
        does not do" in the module docstring.
    expected_delegation_ref
        The ``sha256:``-prefixed delegation id the caller expects the
        chain's leaf to carry, typically the ``delegation_ref`` an action
        receipt named. Compared to the leaf's own ``delegation_id`` by exact
        string equality, before the chain is otherwise checked.
    now, resolve_verification_key, trust_root, resolve_revocation
        Passed straight through to ``agent_passport.verify_authority_delegation_chain``.
        See that function's docstring for what each one does and how its
        callbacks are called.

    Returns
    -------
    AuthorityValidationResult
        The same type ``verify_authority_delegation_chain`` returns.
        ``state`` is one of ``STATES``, ``failures`` is a tuple of
        ``AuthorityFailure``, and ``.valid`` is ``True`` only when ``state
        == "valid"``. A delegation_ref mismatch is reported as ``state ==
        "invalid"`` with one ``AuthorityFailure`` of code
        ``DELEGATION_REF_MISMATCH``, ``index`` set to the leaf's position.
        Every other result is the SDK's own, returned unchanged. This
        module never turns ``indeterminate`` or ``unsupported`` into
        ``valid``, and never adds, drops or reinterprets one of the SDK's
        own failures.
    """
    mismatch = _delegation_ref_mismatch(chain, expected_delegation_ref)
    if mismatch is not None:
        return mismatch

    return verify_authority_delegation_chain(
        chain,
        now=now,
        resolve_verification_key=resolve_verification_key,
        trust_root=trust_root,
        resolve_revocation=resolve_revocation,
    )


def _delegation_ref_mismatch(
    chain: Sequence[dict], expected_delegation_ref: str
) -> AuthorityValidationResult | None:
    """Return an invalid result if chain's leaf does not carry expected_delegation_ref.

    Returns ``None``, meaning no mismatch found here, whenever the chain is
    not a non-empty list or tuple of dicts. A chain shaped like that is left
    for ``verify_authority_delegation_chain`` to refuse on its own terms
    (``SCHEMA_INVALID`` or ``RESOURCE_LIMIT``), rather than this function
    guessing what the caller meant by an id comparison it cannot perform.
    """
    if type(chain) is not list and type(chain) is not tuple:
        return None
    if not chain:
        return None
    leaf = chain[-1]
    if type(leaf) is not dict:
        return None
    if leaf.get("delegation_id") == expected_delegation_ref:
        return None
    return AuthorityValidationResult(
        state=INVALID,
        failures=(
            AuthorityFailure(
                code=DELEGATION_REF_MISMATCH,
                message="chain leaf delegation_id does not match the expected delegation_ref",
                index=len(chain) - 1,
            ),
        ),
    )
