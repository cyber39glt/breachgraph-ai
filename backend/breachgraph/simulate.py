"""What-if remediation: apply permission changes to a copy and compare the results.

Changes never touch the original dataset. Each change is a small, explicit
operation, so a proposed fix (including one suggested by the AI) can be checked
by the same deterministic engine before anyone acts on it.
"""

from __future__ import annotations

import copy
from typing import Any

from .engine import analyze
from .model import DatasetError, validate_dataset

OPERATIONS = {
    "remove_group_member": ("group", "user"),
    "detach_policy": ("principal", "policy"),
    "remove_statement": ("policy", "sid"),
    "set_statement_actions": ("policy", "sid", "actions"),
    "set_statement_resources": ("policy", "sid", "resources"),
    "set_role_trust": ("role", "trusted_principals"),
}


def _find(items: list[dict[str, Any]], item_id: str, what: str) -> dict[str, Any]:
    for item in items:
        if item["id"] == item_id:
            return item
    raise DatasetError(f"unknown {what} '{item_id}'")


def _statement(data: dict[str, Any], policy_id: str, sid: str) -> dict[str, Any]:
    policy = _find(data["policies"], policy_id, "policy")
    for st in policy.get("statements", []):
        if st["sid"] == sid:
            return st
    raise DatasetError(f"policy '{policy_id}' has no statement '{sid}'")


def apply_change(data: dict[str, Any], change: dict[str, Any]) -> None:
    op = change.get("op")
    if op not in OPERATIONS:
        raise DatasetError(f"unknown operation '{op}'; expected one of {sorted(OPERATIONS)}")
    missing = [k for k in OPERATIONS[op] if k not in change]
    if missing:
        raise DatasetError(f"{op} needs {', '.join(missing)}")

    if op == "remove_group_member":
        group = _find(data["groups"], change["group"], "group")
        if change["user"] not in group.get("members", []):
            raise DatasetError(f"{change['user']} is not a member of {change['group']}")
        group["members"].remove(change["user"])
    elif op == "detach_policy":
        holders = data["users"] + data["groups"] + data["roles"]
        holder = _find(holders, change["principal"], "principal")
        if change["policy"] not in holder.get("policies", []):
            raise DatasetError(f"{change['policy']} is not attached to {change['principal']}")
        holder["policies"].remove(change["policy"])
    elif op == "remove_statement":
        st = _statement(data, change["policy"], change["sid"])
        policy = _find(data["policies"], change["policy"], "policy")
        policy["statements"].remove(st)
    elif op == "set_statement_actions":
        _statement(data, change["policy"], change["sid"])["actions"] = list(change["actions"])
    elif op == "set_statement_resources":
        _statement(data, change["policy"], change["sid"])["resources"] = list(change["resources"])
    elif op == "set_role_trust":
        _find(data["roles"], change["role"], "role")["trusted_principals"] = list(change["trusted_principals"])


def simulate(data: dict[str, Any], changes: list[dict[str, Any]]) -> dict[str, Any]:
    if not changes:
        raise DatasetError("provide at least one change to simulate")
    after_data = copy.deepcopy(data)
    for change in changes:
        apply_change(after_data, change)
    validate_dataset(after_data)  # a change must not leave dangling references

    before = analyze(data)
    after = analyze(after_data)

    def paths(result):
        return {f["key"]: f for f in result["findings"] if f["type"] == "attack_path"}

    def access(result):
        return {a["key"]: a for a in result["access"]}

    pb, pa = paths(before), paths(after)
    ab, aa = access(before), access(after)
    broken = sorted(pb.keys() - pa.keys())
    # Access the fix removes that was *not* an attack path: possible collateral
    # damage to legitimate work, shown so a reviewer can judge it.
    collateral = sorted((ab.keys() - aa.keys()) - set(broken))
    reduced = sorted(k for k in pb.keys() & pa.keys()
                     if pa[k]["score"] < pb[k]["score"] or pa[k]["path"] != pb[k]["path"])

    return {
        "changes": changes,
        "before": before,
        "after": after,
        "diff": {
            "broken_paths": [pb[k] for k in broken],
            "remaining_paths": [pa[k] for k in sorted(pa.keys() & pb.keys())],
            "new_paths": [pa[k] for k in sorted(pa.keys() - pb.keys())],
            "changed_paths": reduced,
            "access_removed": [ab[k] for k in sorted(ab.keys() - aa.keys())],
            "collateral_access_removed": [ab[k] for k in collateral],
            "access_added": [aa[k] for k in sorted(aa.keys() - ab.keys())],
            "risk_before": sum(f["score"] for f in pb.values()),
            "risk_after": sum(f["score"] for f in pa.values()),
        },
    }
