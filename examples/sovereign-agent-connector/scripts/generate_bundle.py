from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Run from anywhere: the local agentrust_auc module lives one folder up.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentrust_auc.core import write_bundle  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("trust_anchors_output")
    args = parser.parse_args()
    result = write_bundle(args.output, args.trust_anchors_output)
    print(f"verified bundle written to {args.output}")
    print(f"out-of-band trust anchors written to {args.trust_anchors_output}")
    print(f"dispatched actions: {', '.join(result.dispatched)}")


if __name__ == "__main__":
    main()
