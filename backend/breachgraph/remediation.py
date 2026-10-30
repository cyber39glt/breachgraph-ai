"""Deterministic remediation candidates.

Every group membership and policy statement that appears on an attack path is a
place where the path could be cut. For each one we run the simulator on its own
and record what it actually does: which paths it breaks, whether any new path
appears, and which other access it would also remove. The ranking is therefore a
measured result, not a guess.
"""

from __future__ import annotations

import json
from typing import Any

from .engine import UNUSED_PERMISSION_DAYS, is_broad_resource
from .simulate import simulate

MAX_CANDIDATES = 25
# Pre-measuring re-runs the whole analysis once per candidate. Above this many attack paths
# that is too slow to do up front, so candidates are listed unmeasured (the simulator still
# measures any you choose to run).
PREVIEW_MAX_PATHS = 200


def _statement(data: dict[str, Any], policy_id: str, sid: str) -> dict[str, Any] | None:
    for policy in data["policies"]:
        if policy["id"] == policy_id:
            return next((st for st in policy.get("statements", []) if st["sid"] == sid), None)
    return None


def _names(data: dict[str, Any]) -> dict[str, str]:
    return {e["id"]: e.get("name", e["id"])
            for section in ("users", "groups", "roles", "policies", "resources") for e in data[section]}


def candidates(data: dict[str, Any], analysis: dict[str, Any]) -> list[dict[str, Any]]:
    names = _names(data)
    found: dict[str, dict[str, Any]] = {}
    for f in analysis["findings"]:
        if f["type"] != "attack_path":
            continue
        for hop in f["hops"]:
            grant = hop["evidence"].get("grant")
            if hop["relation"] == "member_of":
                change = {"op": "remove_group_member", "group": hop["target"], "user": hop["source"]}
                label = f"Remove {names[hop['source']]} from group {names[hop['target']]}"
                notes: list[str] = []
            elif grant:
                change = {"op": "remove_statement", "policy": grant["policy"], "sid": grant["sid"]}
                label = f"Remove statement {grant['sid']} from policy {names[grant['policy']]}"
                st = _statement(data, grant["policy"], grant["sid"]) or {}
                notes = []
                last = st.get("last_used_days")
                if "last_used_days" in st and (last is None or last > UNUSED_PERMISSION_DAYS):
                    notes.append("never used" if last is None else f"unused for {last} days")
                if any(a == "*" or a.endswith(":*") for a in grant["actions"]) or any(
                    is_broad_resource(r) for r in grant["resources"]
                ):
                    notes.append("wildcard")
            else:
                continue
            key = json.dumps(change, sort_keys=True)
            entry = found.setdefault(key, {"change": change, "label": label, "notes": notes, "on_paths": []})
            if f["id"] not in entry["on_paths"]:
                entry["on_paths"].append(f["id"])

    entries = list(found.values())
    if analysis["summary"]["attack_paths"] > PREVIEW_MAX_PATHS:
        # Most-used cut points first, so the likeliest high-impact fixes are at the top.
        entries.sort(key=lambda e: (-len(e["on_paths"]), e["label"]))
        return [{**e, "preview": None} for e in entries[:MAX_CANDIDATES]]

    out = []
    for entry in entries[:MAX_CANDIDATES]:
        diff = simulate(data, [entry["change"]])["diff"]
        entry["preview"] = {
            "broken_paths": [p["id"] for p in diff["broken_paths"]],
            "new_paths": [p["id"] for p in diff["new_paths"]],
            "collateral_access_removed": [a["key"] for a in diff["collateral_access_removed"]],
            "risk_before": diff["risk_before"],
            "risk_after": diff["risk_after"],
        }
        out.append(entry)
    # Most paths broken first; then least collateral; then a stable order.
    out.sort(key=lambda e: (-len(e["preview"]["broken_paths"]), len(e["preview"]["new_paths"]),
                            len(e["preview"]["collateral_access_removed"]), e["label"]))
    return out
