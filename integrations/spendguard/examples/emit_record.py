#!/usr/bin/env python3
"""Emit a TRACE Trust Record from a SpendGuard decision.

SCAFFOLD: not implemented. Wire this to SpendGuard's signed decision output and
map it onto TRACE record fields (subject, policy.bundle_hash, cnf, signature,
gateway.audit_chain), then write the JWT to --out. Until implemented this exits
non-zero so the conformance step honestly reflects "not done".
"""
import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.parse_args()
    sys.stderr.write(
        "TODO: map a signed SpendGuard spend/gate decision onto a TRACE Trust "
        "Record and write it to --out.\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
