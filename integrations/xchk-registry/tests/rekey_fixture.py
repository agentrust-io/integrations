#!/usr/bin/env python3
"""Re-sign a genuine receipt bundle under keys of your own (2 Nov 2026).

Reproduces drk-ram's exercise in review of agentrust-io/integrations#350: take fixture 01, replace the registry's Ed25519
and ML-DSA-65 keys with freshly generated ones everywhere they appear — the pinned key list, the legacy single-key fields,
the root statement's key list — and re-sign the seal hash, the profile hash and the identity binding with them. Every
check the verifier can run offline then passes, --require-approval included, because every key it checks with is the
one the bundle carries. Only --keys, with the registry's published key document, tells this bundle from a real one.

The root's SLH-DSA-SHA2-128s signature is left as it was: no library here signs FIPS 205, and the Python verifier only
reports it as WAIT. (The browser page, which does verify SLH-DSA, fails this bundle on that signature: a re-keyer who
also rotates the root passes there too, and the key document catches that root in both verifiers.)

Run (needs `pip install cryptography dilithium-py`):
    python3 integrations/xchk-registry/tests/rekey_fixture.py integrations/xchk-registry/examples/approval-outcome/01-approval-confirmed.bundle.json \\
        integrations/xchk-registry/examples/approval-outcome/09-re-keyed-outside-the-registry.bundle.json
The private keys are generated for the run and discarded. The output differs on every run; the fixture is committed once.
"""
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dilithium_py.ml_dsa import ML_DSA_65

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_receipt as v  # noqa: E402


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def main(src: str, dst: str) -> None:
    bundle = json.loads(Path(src).read_text(encoding="utf-8"))
    rs = bundle["registrySignature"]
    old = {k["alg"]: k for k in v.pinned_keys(rs)}
    assert set(old) == {"ed25519", "ml-dsa-65"}, "expects a hybrid-signed bundle"

    ed_priv = Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pq_pub, pq_priv = ML_DSA_65.keygen()
    new = {"ed25519": {"alg": "ed25519", "keyId": v.key_id_for("ed25519", ed_pub), "publicKeyRaw": b64(ed_pub)},
           "ml-dsa-65": {"alg": "ml-dsa-65", "keyId": v.key_id_for("ml-dsa-65", pq_pub), "publicKeyRaw": b64(pq_pub)}}
    sign = {"ed25519": lambda m: b64(ed_priv.sign(m)), "ml-dsa-65": lambda m: b64(ML_DSA_65.sign(pq_priv, m))}

    def resign(obj: dict, msg: bytes) -> None:
        """Rewrite a registry signature object: every entry of `signatures`, and the legacy single Ed25519 fields."""
        obj["signatures"] = [{"alg": a, "keyId": new[a]["keyId"], "signature": sign[a](msg)} for a in ("ed25519", "ml-dsa-65")]
        obj["keyId"] = new["ed25519"]["keyId"]
        obj["signature"] = sign["ed25519"](msg)

    resign(rs, bundle["seal"]["sealHash"].encode("utf-8"))
    rs["keys"] = [new["ed25519"], new["ml-dsa-65"]]
    rs["publicKeyRaw"] = new["ed25519"]["publicKeyRaw"]
    rs["publicKeyPem"] = ed_priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    rs["publicKeyRawPq"] = new["ml-dsa-65"]["publicKeyRaw"]
    rs["keyIdPq"] = new["ml-dsa-65"]["keyId"]
    stated = rs.get("root", {}).get("statement", {}).get("keys")
    if isinstance(stated, list):
        rs["root"]["statement"]["keys"] = [new.get(k.get("alg"), k) if k.get("keyId") == old.get(k.get("alg"), {}).get("keyId") else k for k in stated]
    prof = bundle.get("profile") or {}
    if prof.get("signature") and bundle["seal"].get("profileHash"):
        resign(prof["signature"], bundle["seal"]["profileHash"].encode("utf-8"))
    bd = (bundle.get("approver") or {}).get("binding")
    if bd and bd.get("fields"):
        resign(bd, v.canonical(bd["fields"]).encode("utf-8"))
    bundle["fixtureNote"] = ("TEST FIXTURE, 2 Nov 2026: fixture 01 re-signed under keys that are not the registry's (rekey_fixture.py, beside the tests). "
                             "Every offline check passes without --keys; with the registry's key document the pinned keys fail by name.")
    Path(dst).write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {dst}: keys {new['ed25519']['keyId']} (ed25519), {new['ml-dsa-65']['keyId']} (ml-dsa-65); the registry's were "
          f"{old['ed25519']['keyId']}, {old['ml-dsa-65']['keyId']}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
