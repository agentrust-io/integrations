"""Verify the EIP-191 CAIP-380 profile used by this packet, from the published bytes alone.

Independent of Proofable's runtime and its published SDK. It re-derives the canonical JSON subset
(Unicode code-point key order, NFC), recomputes the SHAKE-256 qHash, rebuilds the signer message and
recovers the EIP-191 signer, then requires the recovered signer to equal the envelope's own
`walletAddress`.

Scope, stated precisely:

- This implements the **EIP-191 / did:pkh-eip155** signature profile that this packet uses. It is
  not a universal CAIP-380 verifier: it does not handle Ed25519/Solana, EIP-1271 contract wallets,
  or other signature profiles a CAIP-380 envelope may carry.
- It enforces the CAIP-380 EVM binding: the DID must be `did:pkh:eip155:<chainId>:<address>`, the
  DID chain must equal the envelope `chainId`, the DID address must equal `walletAddress`
  (case-insensitive), and the recovered EIP-191 signer must be that same address.
- It checks **historical receipt integrity** — the bytes hash and the signature binds the signer.
  It does **not** appraise freshness or validity *now*; envelope age, revocation state and expiry
  are a separate appraisal question this verifier does not answer.
- A passing check means the envelope is internally consistent and bound to its signer. It is not a
  claim that any off-chain fact, effect or authority decision behind the statement is true.

CAIP-380 profile: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-380.md
"""

from __future__ import annotations

import json
import unicodedata
from hashlib import shake_256
from typing import Any

SIGNER_HEADER = "Portable Proof Verification Request"


def _string(value: str) -> str:
    """Serialise a string as JavaScript JSON.stringify does (no ASCII escaping)."""
    return json.dumps(unicodedata.normalize("NFC", value), ensure_ascii=False)


def _canonical(value: Any) -> str:
    """Return the canonical JSON of a value: object keys sorted by Unicode code point."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float):
            if not value.is_integer():
                raise ValueError("canonical JSON requires a finite JSON number")
            return str(int(value))
        return str(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        entries = sorted(((unicodedata.normalize("NFC", key), item)
                          for key, item in value.items()),
                         key=lambda pair: [ord(character) for character in pair[0]])
        return "{" + ",".join(f"{_string(key)}:{_canonical(item)}" for key, item in entries) + "}"
    raise ValueError("value is not valid canonical JSON")


def canonical_subset(envelope: dict[str, Any]) -> dict[str, Any]:
    """The CAIP-380 canonical subset: exactly one of chain / chainId is present."""
    has_chain = isinstance(envelope.get("chain"), str) and bool(envelope["chain"].strip())
    has_chain_id = isinstance(envelope.get("chainId"), int) and envelope["chainId"] > 0
    if has_chain == has_chain_id:
        raise ValueError("envelope must contain exactly one of chain or chainId")
    subset = {
        "did": envelope["did"],
        "verifierIds": envelope["verifierIds"],
        "data": envelope["data"],
        "signedTimestamp": envelope["signedTimestamp"],
    }
    if has_chain:
        subset["chain"] = envelope["chain"].strip()
    else:
        subset["chainId"] = envelope["chainId"]
    return subset


def qhash(envelope: dict[str, Any]) -> str:
    """Recompute the CAIP-380 qHash from the canonical subset."""
    digest = shake_256(_canonical(canonical_subset(envelope)).encode("utf-8")).hexdigest(32)
    return "0x" + digest


def message(envelope: dict[str, Any]) -> str:
    """Rebuild the exact signer message the envelope's signature commits to."""
    subset = canonical_subset(envelope)
    chain = subset.get("chain") if subset.get("chain") is not None else subset["chainId"]
    components = [
        SIGNER_HEADER,
        "Wallet: " + str(envelope["walletAddress"]).lower(),
        "Chain: " + str(chain),
        "Verifiers: " + ",".join(str(entry) for entry in envelope["verifierIds"]),
        "Data: " + _canonical(envelope["data"]),
        "Timestamp: " + str(envelope["signedTimestamp"]),
    ]
    return unicodedata.normalize("NFC", "\n".join(components))


def _did_parts(did: Any) -> tuple[int, str] | None:
    """Parse did:pkh:eip155:<chainId>:<address> into (chainId, address); None if malformed."""
    if not isinstance(did, str):
        return None
    parts = did.split(":")
    if len(parts) != 5 or parts[0] != "did" or parts[1] != "pkh" or parts[2] != "eip155":
        return None
    try:
        chain_id = int(parts[3])
    except ValueError:
        return None
    address = parts[4]
    if chain_id <= 0 or not address:
        return None
    return chain_id, address


def verify(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return the qHash and signature verdict for one envelope, with every failure named."""
    errors: list[str] = []
    signer = None
    try:
        if envelope.get("qHash") != qhash(envelope):
            errors.append("qHash does not match the canonical subset")
    except (KeyError, ValueError) as error:
        errors.append("qHash could not be recomputed: " + str(error))
    # CAIP-380 binds the signer DID to the chain and the EVM address: the did:pkh-eip155 CAIP-10
    # form carries the chainId, its address is the signing EOA, and the recovered EIP-191 signer
    # must be that same address. Check the binding from the published fields, not just the
    # address/signature pair.
    did_parts = _did_parts(envelope.get("did"))
    chain_id = envelope.get("chainId")
    wallet = str(envelope.get("walletAddress", ""))
    if did_parts is None:
        errors.append("did is not a did:pkh:eip155 CAIP-10 identifier")
    else:
        did_chain, did_address = did_parts
        if chain_id is not None and did_chain != chain_id:
            errors.append(f"DID chain {did_chain} does not equal envelope chainId {chain_id}")
        if wallet and did_address.lower() != wallet.lower():
            errors.append("DID address does not equal walletAddress")
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
        signer = Account.recover_message(encode_defunct(text=message(envelope)),
                                         signature=envelope["signature"])
    except Exception as error:  # recovery failure is a failing check, never a pass
        errors.append("signature recovery failed: " + str(error))
    if signer is not None:
        if wallet.lower() != signer.lower():
            errors.append("recovered signer does not equal the envelope walletAddress")
        if did_parts is not None and did_parts[1].lower() != signer.lower():
            errors.append("recovered signer does not equal the DID address")
    return {"valid": not errors, "signer": signer, "errors": errors}
