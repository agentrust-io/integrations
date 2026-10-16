"""Bounded LIVE two-host negative matrix. No side-effect retry on unknown results.

Requires a separately provisioned private operator config and remote forced
SSH peer. Never treats unobserved execution as proof of refusal.
"""
import argparse
import json
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ca2a_runtime.delegation import new_keypair
from harness.remote_peer_client import run, ssh_sender


def private(path):
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(path).read_text().strip()))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--config",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    cfg=json.loads(args.config.read_text())
    issuer=private(cfg["issuer_key"])
    holder=private(cfg["holder_key"])
    base_send=ssh_sender(cfg["host"],cfg["ssh_key"])
    results=[]

    def scenario(name, expected, *, send=None, issuer_private=None,
                 permitted=True, trace_public_key="default",
                 credential_not_after_offset=60):
        key = cfg["trace_public_key"] if trace_public_key=="default" else trace_public_key
        result=run(transaction_id="matrix-"+uuid.uuid4().hex,
                   nonce=uuid.uuid4().hex,
                   repo=cfg["repo"],issuer_private=issuer_private or issuer,
                   holder_private=holder,peer_public_key=cfg["peer_public_key"],
                   trace_public_key=key,permitted=permitted,
                   credential_not_after_offset=credential_not_after_offset,
                   send=send or base_send)
        observed=result.outcome
        passed=(observed==expected)
        record={"case":name,"expected":expected,"observed":observed,
                "passed":passed,"transaction_id":result.transaction_id,
                "evidence_class":result.evidence_class,
                "remote_ca2a_verified":result.remote_ca2a_verified,
                "trace_verified":result.trace_verified}
        if result.start_receipt_hash:
            record["start_receipt_hash"]=result.start_receipt_hash
        if result.finish_receipt_hash:
            record["finish_receipt_hash"]=result.finish_receipt_hash
        if result.trace_record_hash:
            record["trace_record_hash"]=result.trace_record_hash
        results.append(record)
        print(json.dumps(record,sort_keys=True),flush=True)
        return result

    valid="authenticated-remote-ca2a-software"
    scenario("positive-twin",valid)
    scenario("local-cmcp-authorization-refusal","refused-cmcp",permitted=False)
    attacker,_=new_keypair()
    scenario("untrusted-issuer","refused-authenticated-peer",issuer_private=attacker)
    scenario("expired-signed-delegation","refused-authenticated-peer",
             credential_not_after_offset=-2)
    scenario("missing-trace-trust-root","missing-trace-trust-anchor",trace_public_key=None)
    other,_=new_keypair()
    scenario("wrong-trace-verifier-root","untrusted-trace-evidence",
             trace_public_key=other.public_key().public_bytes_raw().hex())

    def altered_credential(request):
        if request.get("method")=="execute":
            request["credential"]["scope"]=["conduit.delete"]
        return base_send(request)
    scenario("altered-delegation-scope","refused-authenticated-peer",
             send=altered_credential)

    def tampered_mac(request):
        ans=base_send(request)
        if request.get("method")=="execute" and "envelope" in ans:
            ans["envelope"]["mac"]="00"*32
        return ans
    scenario("response-authentication-mutation","unknown-or-refused-transport",
             send=tampered_mac)

    def lost_response(request):
        ans=base_send(request)
        if request.get("method")=="execute":
            raise RuntimeError("delivery-uncertain-after-execution")
        return ans
    scenario("unobserved-result-remains-unknown","unknown-or-refused-transport",
             send=lost_response)

    last=[None]
    def record_submit(request):
        if request.get("method")=="execute":
            last[0]=json.loads(json.dumps(request))
        return base_send(request)
    scenario("replay-valid-twin",valid,send=record_submit)
    repeated=base_send(last[0])
    replay_ok=repeated.get("status")==403
    rr={"case":"one-time-challenge-replay","expected":"authenticated-peer-denial",
        "observed":"authenticated-peer-denial" if replay_ok else "unexpected",
        "passed":replay_ok,"evidence_class":"live-software-two-host-same-operator"}
    results.append(rr)
    print(json.dumps(rr,sort_keys=True),flush=True)

    passed=all(x["passed"] for x in results)
    report={"schema":"frequency-ca2a-live-adversarial-matrix/1",
            "evidence_class":"live-software-two-host-same-operator",
            "operator_independent":False,"hardware_attested":False,
            "tests":len(results),"passed":sum(x["passed"] for x in results),
            "all_passed":passed, "results":results}
    args.output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    args.output.chmod(0o600)
    print("MATRIX",json.dumps({"passed":report["passed"],"tests":report["tests"],
                               "all_passed":passed}),flush=True)
    if not passed:
        raise SystemExit(1)


if __name__=="__main__":
    main()
