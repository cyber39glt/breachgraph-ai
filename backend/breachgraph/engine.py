"""Deterministic risk engine: who can reach which sensitive resource, and how.

How it works, in short:

1. A *session* is what a request runs as: a user (with the policies of the user and
   of every group the user belongs to) or an assumed role (with only the role's own
   policies). This mirrors AWS: an assumed-role session does not keep the user's
   policies, including the user's explicit denies.
2. From each user we walk outwards (breadth-first) through every role the current
   session can assume, so we always find the shortest chain to each role.
3. In each session we work out which resources it can act on, and at what level
   (read / write / admin). An explicit Deny that fully covers an allowed action wins.
4. Reaches to high or critical resources that need a role chain, or that start from a
   risky identity (no MFA, external, inactive), become attack-path findings. The
   score is a transparent sum of named factors, so every number can be explained.

No AI is involved here. The AI layer only explains what this module has verified.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from .model import ACCOUNT_WIDE_TRUST

ACCESS_RANK = {"read": 1, "write": 2, "admin": 3}
READ_VERBS = ("Get", "List", "Describe", "Read", "Select", "Query", "Scan", "Decrypt", "Head", "BatchGet")
# Control-plane services: their actions act on identities, not on data resources.
IDENTITY_SERVICES = ("sts", "iam")
ASSUME_ROLE = "sts:AssumeRole"
MAX_ROLE_HOPS = 5
STALE_LOGIN_DAYS = 90
UNUSED_PERMISSION_DAYS = 90
FINDING_SENSITIVITIES = ("high", "critical")

SCORE_SENSITIVITY = {"low": 10, "medium": 25, "high": 45, "critical": 60}
SCORE_ACCESS = {"read": 8, "write": 15, "admin": 20}
SCORE_FACTORS = {"no_mfa": 10, "external": 8, "stale": 7, "role_chain": 5}
FACTOR_LABELS = {
    "no_mfa": "Identity has no MFA",
    "external": "External / contractor identity",
    "stale": f"Inactive for more than {STALE_LOGIN_DAYS} days",
    "role_chain": "Reached through assumed roles (privilege escalation)",
}


def severity_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def classify_action(action: str) -> str:
    """Access level granted by one action pattern."""
    if action == "*" or action.endswith(":*"):
        return "admin"
    verb = action.split(":", 1)[-1]
    return "read" if verb.startswith(READ_VERBS) else "write"


def _action_matches(pattern: str, action: str) -> bool:
    # IAM action names are case-insensitive.
    return fnmatchcase(action.lower(), pattern.lower())


def _service(action: str) -> str:
    return action.split(":", 1)[0].lower() if ":" in action else "*"


def _stable_id(prefix: str, key: str) -> str:
    return f"{prefix}-{hashlib.sha256(key.encode()).hexdigest()[:8].upper()}"


@dataclass(frozen=True)
class Grant:
    holder: str  # user, group or role that has the policy attached
    policy: str
    sid: str
    effect: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    last_used_days: int | None

    def covers_resource(self, target: str) -> bool:
        return any(fnmatchcase(target, pattern) for pattern in self.resources)

    def evidence(self) -> dict[str, Any]:
        return {"holder": self.holder, "policy": self.policy, "sid": self.sid,
                "effect": self.effect, "actions": list(self.actions), "resources": list(self.resources)}


class Analyzer:
    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.users = {u["id"]: u for u in data["users"]}
        self.groups = {g["id"]: g for g in data["groups"]}
        self.roles = {r["id"]: r for r in data["roles"]}
        self.policies = {p["id"]: p for p in data["policies"]}
        self.resources = {r["id"]: r for r in data["resources"]}
        self.groups_of: dict[str, list[str]] = {uid: [] for uid in self.users}
        for g in data["groups"]:
            for member in g.get("members", []):
                self.groups_of[member].append(g["id"])

    # --- names -------------------------------------------------------------
    def name(self, node_id: str) -> str:
        for table in (self.users, self.groups, self.roles, self.resources, self.policies):
            if node_id in table:
                return table[node_id].get("name", node_id)
        return node_id

    # --- sessions and grants ----------------------------------------------
    def _holder_grants(self, holder: str) -> list[Grant]:
        entity = self.users.get(holder) or self.groups.get(holder) or self.roles.get(holder)
        grants = []
        for pid in entity.get("policies", []):
            for st in self.policies[pid].get("statements", []):
                grants.append(Grant(holder, pid, st["sid"], st["effect"], tuple(st["actions"]),
                                    tuple(st["resources"]), st.get("last_used_days")))
        return grants

    def session_grants(self, session: str) -> list[Grant]:
        holders = [session] + self.groups_of.get(session, [])
        return [g for h in holders for g in self._holder_grants(h)]

    @staticmethod
    def _denied(grants: list[Grant], action_pattern: str, target: str) -> Grant | None:
        """The Deny statement that fully covers this allowed action on this target.

        A Deny that only partly overlaps (e.g. Deny s3:GetObject vs Allow s3:*) is not
        treated as blocking. That over-reports access rather than hiding it.
        """
        for g in grants:
            if g.effect == "Deny" and g.covers_resource(target) and any(
                _action_matches(d, action_pattern) for d in g.actions
            ):
                return g
        return None

    def resource_access(self, session: str, resource: str) -> tuple[str, Grant, str] | None:
        """Highest access level the session has on a data resource, with its evidence."""
        grants = self.session_grants(session)
        best: tuple[str, Grant, str] | None = None
        for g in grants:
            if g.effect != "Allow" or not g.covers_resource(resource):
                continue
            for action in g.actions:
                if _service(action) in IDENTITY_SERVICES:
                    continue
                if self._denied(grants, action, resource):
                    continue
                level = classify_action(action)
                if best is None or ACCESS_RANK[level] > ACCESS_RANK[best[0]]:
                    best = (level, g, action)
        return best

    def assume_evidence(self, session: str, role: str) -> dict[str, Any] | None:
        """Why `session` can assume `role`, or None if it cannot.

        Same-account AWS semantics: a trust policy naming the principal is enough on
        its own; a trust of the whole account delegates the decision to the caller's
        identity policies, which must then allow sts:AssumeRole on the role.
        """
        if session == role:
            return None
        trust = self.roles[role].get("trusted_principals", [])
        grants = self.session_grants(session)
        if session in trust:
            return {"trust": session, "grant": None}
        if ACCOUNT_WIDE_TRUST not in trust:
            return None
        for g in grants:
            if g.effect != "Allow" or not g.covers_resource(role):
                continue
            for action in g.actions:
                if _action_matches(action, ASSUME_ROLE) and not self._denied(grants, ASSUME_ROLE, role):
                    return {"trust": ACCOUNT_WIDE_TRUST, "grant": g}
        return None

    # --- hops --------------------------------------------------------------
    def _via_holder(self, session: str, grant: Grant | None) -> list[dict[str, Any]]:
        """A member_of hop when the permission comes from one of the user's groups."""
        if grant is None or grant.holder == session:
            return []
        return [{"source": session, "target": grant.holder, "relation": "member_of",
                 "detail": f"{self.name(session)} is a member of group {self.name(grant.holder)}.",
                 "evidence": {"group": grant.holder}}]

    def _assume_hops(self, session: str, role: str, ev: dict[str, Any]) -> list[dict[str, Any]]:
        grant = ev["grant"]
        hops = self._via_holder(session, grant)
        actor = grant.holder if grant else session
        if grant:
            detail = (f"Policy {self.name(grant.policy)} (statement {grant.sid}) allows "
                      f"{', '.join(grant.actions)} on {', '.join(grant.resources)}, and role "
                      f"{self.name(role)} trusts the whole account, so {self.name(session)} can assume it.")
        else:
            detail = f"Role {self.name(role)} trusts {self.name(session)} directly."
        hops.append({"source": actor, "target": role, "relation": "can_assume", "detail": detail,
                     "evidence": {"trust": ev["trust"], **({"grant": grant.evidence()} if grant else {})}})
        return hops

    def _access_hops(self, session: str, resource: str, level: str, grant: Grant, action: str):
        hops = self._via_holder(session, grant)
        hops.append({
            "source": grant.holder, "target": resource, "relation": "access", "level": level,
            "detail": (f"Policy {self.name(grant.policy)} (statement {grant.sid}) allows {action} on "
                       f"{', '.join(grant.resources)}, which gives {level} access to {self.name(resource)}."),
            "evidence": {"grant": grant.evidence(), "action": action},
        })
        return hops

    # --- reachability ------------------------------------------------------
    def reach_from(self, user: str) -> list[dict[str, Any]]:
        """Every resource the user can reach, with the best path to each."""
        chains: dict[str, list[dict[str, Any]]] = {user: []}
        roles_on_chain: dict[str, list[str]] = {user: []}
        queue = deque([user])
        while queue:
            session = queue.popleft()
            if len(roles_on_chain[session]) >= MAX_ROLE_HOPS:
                continue
            for role in self.roles:
                if role in chains:
                    continue
                ev = self.assume_evidence(session, role)
                if ev:
                    chains[role] = chains[session] + self._assume_hops(session, role, ev)
                    roles_on_chain[role] = roles_on_chain[session] + [role]
                    queue.append(role)

        best: dict[str, dict[str, Any]] = {}
        for session, chain in chains.items():
            for resource in self.resources:
                found = self.resource_access(session, resource)
                if not found:
                    continue
                level, grant, action = found
                candidate = {
                    "user": user, "resource": resource, "level": level,
                    "roles": roles_on_chain[session],
                    "hops": chain + self._access_hops(session, resource, level, grant, action),
                }
                current = best.get(resource)
                if current is None or (ACCESS_RANK[level], -len(candidate["hops"])) > (
                    ACCESS_RANK[current["level"]], -len(current["hops"])
                ):
                    best[resource] = candidate
        return sorted(best.values(), key=lambda r: r["resource"])

    # --- findings ----------------------------------------------------------
    def user_factors(self, user: str) -> list[str]:
        u = self.users[user]
        factors = []
        if not u["mfa_enabled"]:
            factors.append("no_mfa")
        if u.get("external"):
            factors.append("external")
        if (u.get("last_login_days") or 0) > STALE_LOGIN_DAYS:
            factors.append("stale")
        return factors

    def _path_finding(self, reach: dict[str, Any]) -> dict[str, Any] | None:
        res = self.resources[reach["resource"]]
        factors = self.user_factors(reach["user"])
        if reach["roles"]:
            factors.append("role_chain")
        if res["sensitivity"] not in FINDING_SENSITIVITIES or not factors:
            return None
        breakdown = [
            {"factor": "sensitivity", "label": f"{res['sensitivity'].title()} resource",
             "points": SCORE_SENSITIVITY[res["sensitivity"]]},
            {"factor": "access", "label": f"{reach['level'].title()} access",
             "points": SCORE_ACCESS[reach["level"]]},
        ] + [{"factor": f, "label": FACTOR_LABELS[f], "points": SCORE_FACTORS[f]} for f in factors]
        score = min(100, sum(b["points"] for b in breakdown))
        key = f"{reach['user']}->{reach['resource']}"
        return {
            "id": _stable_id("PATH", key),
            "key": key,
            "type": "attack_path",
            "severity": severity_for(score),
            "score": score,
            "score_breakdown": breakdown,
            "title": (f"{self.name(reach['user'])} can gain {reach['level']} access to "
                      f"{self.name(reach['resource'])}"),
            "entry": reach["user"],
            "target": reach["resource"],
            "level": reach["level"],
            "roles": reach["roles"],
            "path": [reach["user"]] + [h["target"] for h in reach["hops"]],
            "hops": reach["hops"],
            "facts": [h["detail"] for h in reach["hops"]],
        }

    def _holders_of(self, policy: str) -> list[str]:
        tables = (self.users, self.groups, self.roles)
        return [eid for t in tables for eid, e in t.items() if policy in e.get("policies", [])]

    def _statement_findings(self, path_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        used_in: dict[tuple[str, str], list[str]] = {}
        for f in path_findings:
            for hop in f["hops"]:
                grant = hop["evidence"].get("grant")
                if grant:
                    used_in.setdefault((grant["policy"], grant["sid"]), []).append(f["id"])

        out = []
        for policy in self.data["policies"]:
            holders = self._holders_of(policy["id"])
            for st in policy.get("statements", []):
                if st["effect"] != "Allow":
                    continue
                related = sorted(set(used_in.get((policy["id"], st["sid"]), [])))
                ref = f"{policy['name']} / {st['sid']}"
                base = {"policy": policy["id"], "sid": st["sid"], "holders": holders,
                        "statement": st, "related_findings": related}
                wild_actions = [a for a in st["actions"] if a == "*" or a.endswith(":*")]
                wild_resources = [r for r in st["resources"] if "*" in r]
                if wild_actions or wild_resources:
                    parts = []
                    if wild_actions:
                        parts.append(f"actions {', '.join(wild_actions)}")
                    if wild_resources:
                        parts.append(f"resources {', '.join(wild_resources)}")
                    key = f"wildcard:{policy['id']}:{st['sid']}"
                    out.append({**base, "id": _stable_id("WILD", key), "key": key,
                                "type": "wildcard_permission",
                                "severity": "high" if related else "medium",
                                "title": f"Wildcard {' and '.join(parts)} in {ref}",
                                "facts": [f"Statement {st['sid']} in policy {policy['name']} allows "
                                          f"{', '.join(st['actions'])} on {', '.join(st['resources'])}."]})
                last = st.get("last_used_days")
                if last is None or last > UNUSED_PERMISSION_DAYS:
                    when = "has never been used" if last is None else f"was last used {last} days ago"
                    key = f"unused:{policy['id']}:{st['sid']}"
                    out.append({**base, "id": _stable_id("UNUSED", key), "key": key,
                                "type": "unused_permission",
                                "severity": "medium" if related else "low",
                                "title": f"Unused permission {ref} {when}",
                                "facts": [f"Statement {st['sid']} in policy {policy['name']} {when}."]})
        return out

    # --- full analysis -----------------------------------------------------
    def analyze(self) -> dict[str, Any]:
        access = [r for user in self.users for r in self.reach_from(user)]
        paths = [f for f in (self._path_finding(r) for r in access) if f]
        findings = paths + self._statement_findings(paths)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: (order[f["severity"]], -f.get("score", 0), f["id"]))
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in order}
        return {
            "dataset": self.data.get("metadata", {}),
            "summary": {
                "identities": len(self.users),
                "roles": len(self.roles),
                "resources": len(self.resources),
                "sensitive_resources": sum(1 for r in self.resources.values()
                                           if r["sensitivity"] in FINDING_SENSITIVITIES),
                "attack_paths": len(paths),
                "findings_by_severity": counts,
            },
            "findings": findings,
            "access": [{"key": f"{r['user']}->{r['resource']}", "user": r["user"],
                        "resource": r["resource"], "level": r["level"], "roles": r["roles"]}
                       for r in access],
            "graph": self.graph(access),
        }

    def graph(self, access: list[dict[str, Any]]) -> dict[str, Any]:
        nodes = []
        for kind, table in (("user", self.users), ("group", self.groups),
                            ("role", self.roles), ("resource", self.resources)):
            for eid, e in table.items():
                node = {"id": eid, "kind": kind, "label": e.get("name", eid)}
                if kind == "resource":
                    node["sensitivity"] = e["sensitivity"]
                    node["resource_type"] = e.get("type")
                if kind == "user":
                    node["factors"] = self.user_factors(eid)
                nodes.append(node)
        edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        for g in self.groups.values():
            for m in g.get("members", []):
                edges[(m, g["id"], "member_of")] = {"source": m, "target": g["id"], "relation": "member_of"}
        for r in access:
            for h in r["hops"]:
                k = (h["source"], h["target"], h["relation"])
                if k not in edges or ACCESS_RANK.get(h.get("level"), 0) > ACCESS_RANK.get(edges[k].get("level"), 0):
                    edges[k] = {"source": h["source"], "target": h["target"], "relation": h["relation"],
                                **({"level": h["level"]} if "level" in h else {})}
        return {"nodes": nodes, "edges": sorted(edges.values(), key=lambda e: (e["source"], e["target"]))}


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    return Analyzer(data).analyze()
