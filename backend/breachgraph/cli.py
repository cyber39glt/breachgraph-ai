"""Command-line entry point: analyse a dataset, optionally simulate a fix.

    python -m breachgraph.cli ../data/sample_org.json
    python -m breachgraph.cli ../data/sample_org.json --fix fix.json
    python -m breachgraph.cli ../data/sample_org.json --json
"""

from __future__ import annotations

import argparse
import json
import sys

from .engine import analyze
from .model import DatasetError, load_dataset
from .simulate import simulate


def _print_findings(result: dict) -> None:
    s = result["summary"]
    print(f"{result['dataset'].get('name', 'Dataset')}: {s['identities']} identities, "
          f"{s['roles']} roles, {s['resources']} resources ({s['sensitive_resources']} sensitive)")
    print(f"Attack paths: {s['attack_paths']}   Findings by severity: {s['findings_by_severity']}\n")
    for f in result["findings"]:
        score = f"{f['score']:>3}" if "score" in f else "   "
        print(f"[{f['severity'].upper():8}] {score}  {f['id']}  {f['title']}")
        if f["type"] == "attack_path":
            print("               " + "  ->  ".join(f["path"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="breachgraph", description=__doc__.splitlines()[0])
    parser.add_argument("dataset")
    parser.add_argument("--fix", help="JSON file with a list of changes to simulate")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = parser.parse_args(argv)
    try:
        data = load_dataset(args.dataset)
        if args.fix:
            with open(args.fix, encoding="utf-8") as f:
                result = simulate(data, json.load(f))
        else:
            result = analyze(data)
    except (OSError, json.JSONDecodeError, DatasetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    elif args.fix:
        d = result["diff"]
        print(f"Risk (sum of attack-path scores): {d['risk_before']} -> {d['risk_after']}")
        for label, key in (("BROKEN", "broken_paths"), ("REMAINING", "remaining_paths"), ("NEW", "new_paths")):
            for f in d[key]:
                print(f"  {label:9} {f['title']}")
        for a in d["collateral_access_removed"]:
            print(f"  REVIEW    also removes {a['level']} access {a['key']} (not flagged as a path)")
    else:
        _print_findings(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
