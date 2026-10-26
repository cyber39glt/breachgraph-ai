"""Loading and validating a cloud identity dataset.

The dataset is plain JSON (see data/sample_org.json). Validation here is strict on
purpose: the risk engine must never silently skip a reference it cannot resolve,
because a missing edge would hide an attack path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SENSITIVITY_LEVELS = ("low", "medium", "high", "critical")
ID_PREFIXES = {
    "users": "user:",
    "groups": "group:",
    "roles": "role:",
    "policies": "policy:",
    "resources": "res:",
}
# Trust entry meaning "any principal in this account that is allowed sts:AssumeRole".
ACCOUNT_WIDE_TRUST = "account:*"


class DatasetError(ValueError):
    """The dataset is malformed. The message names the offending entry."""


def load_dataset(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    validate_dataset(data)
    return data


def validate_dataset(data: Any) -> None:
    if not isinstance(data, dict):
        raise DatasetError("dataset must be a JSON object")
    for section in ID_PREFIXES:
        if not isinstance(data.get(section), list):
            raise DatasetError(f"'{section}' must be a list")

    seen: set[str] = set()
    for section, prefix in ID_PREFIXES.items():
        for i, entry in enumerate(data[section]):
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                raise DatasetError(f"{section}[{i}] must be an object with a string 'id'")
            if not entry["id"].startswith(prefix):
                raise DatasetError(f"{section}[{i}] id '{entry['id']}' must start with '{prefix}'")
            if entry["id"] in seen:
                raise DatasetError(f"duplicate id '{entry['id']}'")
            seen.add(entry["id"])

    policy_ids = {p["id"] for p in data["policies"]}
    user_ids = {u["id"] for u in data["users"]}
    group_ids = {g["id"] for g in data["groups"]}
    role_ids = {r["id"] for r in data["roles"]}

    for holder in data["users"] + data["groups"] + data["roles"]:
        for pid in holder.get("policies", []):
            if pid not in policy_ids:
                raise DatasetError(f"{holder['id']} references unknown policy '{pid}'")
    for user in data["users"]:
        if not isinstance(user.get("mfa_enabled"), bool):
            raise DatasetError(f"{user['id']} needs a boolean 'mfa_enabled'")
    for group in data["groups"]:
        for member in group.get("members", []):
            if member not in user_ids:
                raise DatasetError(f"{group['id']} has unknown member '{member}'")
    for role in data["roles"]:
        for principal in role.get("trusted_principals", []):
            if principal in group_ids:
                # Same rule as AWS: a role trust policy cannot name an IAM group.
                raise DatasetError(f"{role['id']} trust cannot name a group ('{principal}')")
            if principal != ACCOUNT_WIDE_TRUST and principal not in user_ids | role_ids:
                raise DatasetError(f"{role['id']} trusts unknown principal '{principal}'")
    for policy in data["policies"]:
        for j, st in enumerate(policy.get("statements", [])):
            where = f"{policy['id']} statement {j}"
            if st.get("effect") not in ("Allow", "Deny"):
                raise DatasetError(f"{where}: effect must be 'Allow' or 'Deny'")
            if not isinstance(st.get("sid"), str) or not st["sid"]:
                raise DatasetError(f"{where}: needs a non-empty 'sid'")
            for key in ("actions", "resources"):
                if not isinstance(st.get(key), list) or not all(isinstance(x, str) for x in st[key]):
                    raise DatasetError(f"{where}: '{key}' must be a list of strings")
        sids = [st["sid"] for st in policy.get("statements", [])]
        if len(sids) != len(set(sids)):
            raise DatasetError(f"{policy['id']} has duplicate statement sids")
    for res in data["resources"]:
        if res.get("sensitivity") not in SENSITIVITY_LEVELS:
            raise DatasetError(f"{res['id']} sensitivity must be one of {SENSITIVITY_LEVELS}")
