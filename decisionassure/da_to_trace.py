#!/usr/bin/env python3
import json, sys, os, time, hashlib
from pathlib import Path
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def load_or_generate_key():
    pem = os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if pem:
        return serialization.load_pem_private_key(pem.encode(), password=None)
    return Ed25519PrivateKey.generate()

def private_key_to_jwk(key):
    pub = key.public_key()
    raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    import base64
    x = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return {"kty": "OKP", "crv": "Ed25519", "x": x}

def map_decisionassure_to_trace(da_trace, jwk):
    trace_id = da_trace.get("trace_id", "unknown")
    final_decision = da_trace.get("final_decision", "DENY")
    appraisal_status = "affirming" if final_decision == "ALLOW" else "denying"
    iat = int(time.time())
    bundle_input = f"{trace_id}:{final_decision}".encode()
    bundle_hash = f"sha256:{hashlib.sha256(bundle_input).hexdigest()}"
    return {
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": iat,
        "subject": f"spiffe://decisionassure.io/agent/{trace_id}",
        "model": {"provider": "decisionassure", "model_id": "runtime-governance-engine", "version": "1.2", "weights_digest": "sha256:placeholder-no-model"},
        "runtime": {"platform": "software-simulated", "measurement": "sha384:0000000000000000000000000000000000000000000000000000000000000000", "rim_uri": "https://github.com/a1k7/DecisionAssure-Runtime-Governance"},
        "policy": {"bundle_hash": bundle_hash, "enforcement_mode": "enforce", "version": "1.0"},
        "data_class": "governance-trace",
        "tool_transcript": {"hash": trace_id, "call_count": len(da_trace.get("steps", []))},
        "build_provenance": {"slsa_level": 0, "builder": "https://github.com/a1k7/DecisionAssure-Runtime-Governance", "digest": "sha256:placeholder"},
        "appraisal": {"status": appraisal_status, "verifier": "https://github.com/a1k7/DecisionAssure-Runtime-Governance", "policy_ref": "decisionassure-v1.2"},
        "transparency": "",
        "cnf": {"jwk": jwk}
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: da_to_trace.py <decisionassure_trace.json>", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1]) as f:
        da_trace = json.load(f)
    key = load_or_generate_key()
    jwk = private_key_to_jwk(key)
    payload = map_decisionassure_to_trace(da_trace, jwk)
    with open("claim.json", "w") as f:
        json.dump(payload, f, indent=2)
    print("✅ Wrote claim.json", file=sys.stderr)
    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"alg":"EdDSA","typ":"JWT"})
    with open("claim.jwt", "w") as f:
        f.write(token)
    print("✅ Wrote claim.jwt", file=sys.stderr)

if __name__ == "__main__":
    main()
