"""The caller's own code. An ordinary OpenAI client, pointed one line differently.

    base_url = "https://api.openai.com/v1"        before
    base_url = "http://127.0.0.1:8500/v1"         after

Nothing else changes: same SDK, same request shape, same response handling.
"""
import json
import sys
import urllib.error
import urllib.request

from openai import OpenAI

GATEWAY = "http://127.0.0.1:8500/v1"

# Four sensitivity classes from cMCP's own vocabulary, against models in two
# regions and two tenancies. The interesting rows are the last three.
CALLS = [
    ("1", "frontier-large", "public",
     "Summarise the published service-level commitments for standard support."),
    ("2", "frontier-large", "pii",
     "Customer 123-45-6789 (card 4444-3333-2222-1111) reports a duplicate charge "
     "on the March invoice. Draft the acknowledgement."),
    ("3", "frontier-large", "confidential",
     "Summarise the unreleased pricing model for the enterprise tier."),
    ("4", "regional-small", "hipaa_phi",
     "Summarise the attached clinical note for the care coordination record."),
    ("5", "regional-isolated", "hipaa_phi",
     "Summarise the attached clinical note for the care coordination record."),
]

BAR = "-" * 78


def main():
    client = OpenAI(
        base_url=GATEWAY,                     # <-- the only change
        default_headers={"api-key": "demo-key"},
        api_key="demo-key",
    )

    print(f"\nbase_url = {GATEWAY}\n")

    for num, model, data_class, prompt in CALLS:
        print(BAR)
        print(f"[{num}] {model:18} data class: {data_class}")
        print(f"    prompt: {prompt[:62]}{'...' if len(prompt) > 62 else ''}")
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                extra_headers={"x-data-class": data_class},
            )
        except Exception as exc:
            detail = {}
            body = getattr(exc, "response", None)
            if body is not None:
                try:
                    detail = body.json().get("error", {}).get("governance", {})
                except Exception:
                    pass
            advice = detail.get("advice") or {}
            print(f"    -> DENIED   {advice.get('reason', '')}")
            for k, v in advice.items():
                if k != "reason":
                    print(f"       {k}: {v}")
            continue

        extra = getattr(resp, "governance", None) or {}
        red = extra.get("redactions") or [] if isinstance(extra, dict) else []
        note = f"   redacted: {', '.join(red)}" if red else ""
        print(f"    -> ALLOWED{note}")
        print(f"       {resp.choices[0].message.content.splitlines()[0][:66]}")

    print(BAR)
    print("\nClosing the session and fetching the signed claim...\n")
    try:
        with urllib.request.urlopen(f"{GATEWAY}/trust-record", timeout=20) as r:
            record = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        print(f"  could not fetch the signed claim: HTTP {exc.code} {detail}")
        print("  Nothing to sign means no call was allowed. Check model-gateway.log for")
        print("  UPSTREAM_CATALOG_DRIFT: catalog.json and model_server.py must describe")
        print("  the same tool, or the gateway fail-closes on every call.")
        return 1
    trace = record.get("trace", {})
    gw = record.get("gateway", {})
    print(f"  policy.bundle_hash   {trace.get('policy', {}).get('bundle_hash', '')}")
    print(f"  enforcement_mode     {trace.get('policy', {}).get('enforcement_mode', '')}")
    tt = trace.get("tool_transcript", {})
    print(f"  calls                {tt.get('call_count')}")
    for e in tt.get("entries", []):
        print(f"     {e.get('tool_name')}  -> {e.get('decision')}")
    print(f"  audit_chain.length   {gw.get('audit_chain', {}).get('length')}")
    print(f"  signature            {str(record.get('signature'))[:44]}...")

    with open("trace-claim.json", "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)
    print("\n  saved to demo-10-model-gateway/trace-claim.json")
    print("  verify it offline:  cmcp verify trace-claim.json\n")


if __name__ == "__main__":
    sys.exit(main())
