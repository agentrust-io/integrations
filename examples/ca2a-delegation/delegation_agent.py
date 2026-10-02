#!/usr/bin/env python3
"""
cA2A delegation demo for the credit-risk workflow.

Builds a three-hop delegation chain (credit platform -> lead credit agent ->
screening sub-agent -> bureau connector), verifies it offline, then shows a
sub-agent trying to widen its scope and being rejected. No network, no TEE.

Usage:
    python delegation_agent.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))

import delegation_scenario as scenario  # noqa: E402
from ca2a_runtime.errors import CA2AError  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent / "chain-output"


def _write(document: dict, name: str) -> Path:
    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / name
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def show_valid_chain() -> None:
    chain = scenario.build_credit_chain()
    print("Building the credit delegation chain:")
    for label, cred in zip(scenario.HOP_LABELS, chain):
        print(f"  [{cred.depth}] {label}")
        print(f"        scope: {sorted(cred.scope)}")
    print()

    scenario.verify(chain)
    leaf = sorted(chain[-1].scope)
    withheld = sorted(scenario.CREDIT_CHAIN_SCOPES[0] - chain[1].scope)
    print(f"verify_chain: verified=True  hops={len(chain)}  leaf_scope={leaf}")
    print(f"  authority withheld at the first delegation (never reaches a sub-agent): {withheld}")
    path = _write(scenario.as_chain_document(chain), "credit-delegation-chain.json")
    print(f"  wrote {path.name}")
    print()


def show_escalation_attempt() -> None:
    chain = scenario.build_escalation_attempt()
    print("Now the bureau connector tries to grant itself write:risk-report ...")
    path = _write(scenario.as_chain_document(chain), "escalation-attempt.json")
    try:
        scenario.verify(chain)
        print("  UNEXPECTED: the chain verified. This should not happen.")
        sys.exit(1)
    except CA2AError as exc:
        code = getattr(exc, "code", "CA2A_ERROR")
        print(f"  verify_chain: verified=False  code={code}")
        print(f"  reason: {exc}")
        print(f"  wrote {path.name}")
    print()


def main() -> None:
    print("=== cA2A: agent-to-agent delegation for the credit-risk workflow ===")
    print()
    show_valid_chain()
    show_escalation_attempt()
    print("The write:risk-report authority stays with the lead agent by construction:")
    print("it is not in any delegated child's scope, so no descendant can regain it.")
    print()
    print("Check either chain's structure from the CLI (it takes no trusted root):")
    print("  ca2a verify-chain --chain chain-output/credit-delegation-chain.json")


if __name__ == "__main__":
    main()
