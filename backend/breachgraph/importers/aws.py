"""Import an AWS IAM export into a BreachGraph dataset. Offline: no AWS connection, no credentials.

Inputs (all produced by the account owner with read-only access):
  - authorization details: `aws iam get-account-authorization-details` (JSON, required)
  - credential report:     `aws iam get-credential-report` or IAM console download (CSV, optional)
  - context:               BreachGraph's own JSON saying which resources are sensitive and which
                           users are external (optional, but AWS records neither)

Every import returns a report of what could not be analysed, and whether each gap can hide
access (under-report) or overstate it (over-report). Nothing is silently dropped.

Usage:
  python -m breachgraph.importers.aws iam.json --credential-report report.csv --context context.json -o dataset.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import unquote

from ..model import ACCOUNT_WIDE_TRUST, SENSITIVITY_LEVELS, DatasetError, validate_dataset

ASSUME_ACTIONS = ("sts:assumerole", "sts:*", "*")
SERVICE_TYPES = {
    "s3": "S3 bucket", "dynamodb": "DynamoDB table", "kms": "KMS key", "rds": "RDS database",
    "secretsmanager": "Secrets Manager secret", "ssm": "SSM parameter", "lambda": "Lambda function",
    "sqs": "SQS queue", "sns": "SNS topic", "ec2": "EC2 resource", "ecr": "ECR repository",
    "logs": "CloudWatch log group",
}
# Always listed in the report: AWS does not include these in the authorization-details export.
NOT_IN_EXPORT = [
    "Resource-based policies (S3 bucket policies, KMS key policies, etc.) are not in this export. "
    "They can grant extra access, so real exposure may be higher (may under-report).",
    "Service control policies (AWS Organizations) are not in this export. They can block access, "
    "so some paths may not work in practice (may over-report).",
]
DEFAULT_SENSITIVITY = "medium"


class ImportReport:
    def __init__(self) -> None:
        self.warnings: list[str] = []
        self._counts: dict[str, int] = {}

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def count(self, key: str, n: int = 1) -> None:
        self._counts[key] = self._counts.get(key, 0) + n

    def summary(self, key: str, template: str) -> None:
        if self._counts.get(key):
            self.warn(template.format(n=self._counts[key]))


def _document(raw: Any) -> dict[str, Any]:
    """Policy documents are JSON objects in CLI output, but URL-encoded strings in the raw API."""
    if isinstance(raw, str):
        raw = json.loads(unquote(raw))
    if not isinstance(raw, dict):
        raise ValueError("policy document is not a JSON object")
    return raw


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _arn_account(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[4] if len(parts) > 5 and parts[4] else None


def _resource_patterns(arn_pattern: str) -> list[str]:
    """Map an IAM Resource ARN pattern to BreachGraph id patterns."""
    if arn_pattern == "*":
        return ["*"]
    m = re.match(r"^arn:aws[\w-]*:iam::[^:]*:role/(?:.*/)?([^/]+)$", arn_pattern)
    if m:
        return [f"role:{m.group(1)}"]
    patterns = [f"res:{arn_pattern}"]
    # S3 object ARNs (bucket/key) also count as access to the bucket itself.
    s3 = re.match(r"^(arn:aws[\w-]*:s3:::[^/]+)/.*$", arn_pattern)
    if s3:
        patterns.append(f"res:{s3.group(1)}")
    return patterns


def _resource_name(arn: str) -> str:
    """The resource's own name: "halcyon-pii" from an S3 ARN, "payments-ledger" from "...:db:payments-ledger"."""
    tail = arn.split(":::", 1)[1] if ":::" in arn else arn.split(":", 5)[-1]
    return re.split(r"[:/]", tail)[-1] or tail


class _Importer:
    def __init__(self, details: dict[str, Any], credential_csv: str | None, context: dict[str, Any] | None,
                 now: datetime | None):
        if not isinstance(details, dict) or not any(
            k in details for k in ("UserDetailList", "GroupDetailList", "RoleDetailList")
        ):
            raise DatasetError("this does not look like `aws iam get-account-authorization-details` output "
                               "(expected UserDetailList, GroupDetailList, RoleDetailList and Policies)")
        self.details = details
        self.context = context or {}
        self.now = now or datetime.now(timezone.utc)
        self.report = ImportReport()
        self.policies: list[dict[str, Any]] = []
        self.policy_ids: dict[str, str] = {}  # managed policy ARN -> BreachGraph id
        self.concrete_arns: set[str] = set()
        self.account = self._find_account()
        self.credentials = self._parse_credentials(credential_csv) if credential_csv else None

    # --- helpers -------------------------------------------------------------
    def _find_account(self) -> str | None:
        for section in ("UserDetailList", "GroupDetailList", "RoleDetailList"):
            for item in self.details.get(section, []):
                acct = _arn_account(item.get("Arn", ""))
                if acct:
                    return acct
        return None

    def _parse_credentials(self, text: str) -> dict[str, dict[str, str]]:
        rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
        if rows and "user" not in rows[0]:
            raise DatasetError("the credential report CSV has no 'user' column")
        return {r["user"]: r for r in rows if r.get("user") != "<root_account>"}

    def _days_since(self, value: str | None) -> int | None:
        if not value or value in ("N/A", "no_information", "not_supported"):
            return None
        try:
            when = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0, (self.now - when).days)

    def _convert_statements(self, doc: dict[str, Any], where: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        used: set[str] = set()
        for i, st in enumerate(_as_list(doc.get("Statement")), 1):
            if not isinstance(st, dict) or st.get("Effect") not in ("Allow", "Deny"):
                self.report.warn(f"{where}: statement {i} is malformed and was skipped.")
                continue
            if "NotAction" in st or "NotResource" in st:
                self.report.count("not_action")
                self.report.warn(f"{where}: statement {i} uses NotAction/NotResource, which is not analysed "
                                 "(may under-report).")
                continue
            if "Condition" in st:
                self.report.count("conditions")
            actions = [a for a in _as_list(st.get("Action")) if isinstance(a, str)]
            resources: list[str] = []
            for r in _as_list(st.get("Resource")):
                if not isinstance(r, str):
                    continue
                resources.extend(_resource_patterns(r))
                if "*" not in r and "?" not in r and ":role/" not in r:
                    self.concrete_arns.add(re.sub(r"^(arn:aws[\w-]*:s3:::[^/]+)/.*$", r"\1", r))
            resources = list(dict.fromkeys(resources))  # keep order, drop duplicates
            if not actions or not resources:
                continue
            sid = str(st.get("Sid") or f"Statement{i}")
            while sid in used:
                sid += "_"
            used.add(sid)
            # No "last_used_days": the export does not record usage, so it is unknown, not "never".
            out.append({"sid": sid, "effect": st["Effect"], "actions": actions, "resources": resources})
        return out

    def _add_policy(self, pid: str, name: str, doc: Any, where: str) -> bool:
        try:
            statements = self._convert_statements(_document(doc), where)
        except (ValueError, json.JSONDecodeError):
            self.report.warn(f"{where}: the policy document could not be read and was skipped (may under-report).")
            return False
        self.policies.append({"id": pid, "name": name, "statements": statements})
        return True

    def _attached(self, entity: dict[str, Any], kind: str, inline_key: str) -> list[str]:
        name = entity.get(f"{kind.title()}Name", "?")
        ids: list[str] = []
        for p in entity.get(inline_key, []) or []:
            pid = f"policy:inline/{kind}/{name}/{p.get('PolicyName')}"
            if self._add_policy(pid, f"{p.get('PolicyName')} (inline on {name})", p.get("PolicyDocument"),
                                f"Inline policy {p.get('PolicyName')} on {kind} {name}"):
                ids.append(pid)
        for p in entity.get("AttachedManagedPolicies", []) or []:
            pid = self.policy_ids.get(p.get("PolicyArn", ""))
            if pid:
                ids.append(pid)
            else:
                self.report.warn(f"Managed policy {p.get('PolicyName')} is attached to {kind} {name} but its "
                                 "document is not in the export; skipped (may under-report).")
        if entity.get("PermissionsBoundary"):
            self.report.count("boundaries")
        return ids

    # --- conversion ------------------------------------------------------------
    def _managed_policies(self) -> None:
        taken: set[str] = set()
        for p in self.details.get("Policies", []) or []:
            arn, name = p.get("Arn", ""), p.get("PolicyName", "?")
            default = next((v for v in p.get("PolicyVersionList", []) or [] if v.get("IsDefaultVersion")), None)
            if default is None:
                self.report.warn(f"Managed policy {name} has no default version in the export; skipped.")
                continue
            pid = f"policy:{name}" if f"policy:{name}" not in taken else f"policy:{arn}"
            taken.add(pid)
            if self._add_policy(pid, name, default.get("Document"), f"Managed policy {name}"):
                self.policy_ids[arn] = pid

    def _trust(self, role: dict[str, Any], users: set[str], roles: set[str]) -> list[str]:
        name = role.get("RoleName", "?")
        try:
            doc = _document(role.get("AssumeRolePolicyDocument") or {})
        except (ValueError, json.JSONDecodeError):
            self.report.warn(f"Role {name}: trust policy could not be read; nobody is treated as trusted.")
            return []
        trusted: list[str] = []
        for st in _as_list(doc.get("Statement")):
            if not isinstance(st, dict):
                continue
            actions = [a.lower() for a in _as_list(st.get("Action")) if isinstance(a, str)]
            if st.get("Effect") != "Allow" or not any(a in ASSUME_ACTIONS for a in actions):
                continue
            if "Condition" in st:
                self.report.count("conditions")
            principal = st.get("Principal")
            aws = _as_list(principal.get("AWS")) if isinstance(principal, dict) else _as_list(principal)
            for p in aws:
                if p == "*":
                    self.report.warn(f"Role {name} trusts any AWS principal (\"*\"). Treated as account-wide; "
                                     "check this role urgently.")
                    trusted.append(ACCOUNT_WIDE_TRUST)
                    continue
                acct = p if re.fullmatch(r"\d{12}", str(p)) else _arn_account(str(p))
                if acct and self.account and acct != self.account:
                    self.report.warn(f"Role {name} trusts another AWS account ({acct}). Cross-account access is "
                                     "not modelled (may under-report).")
                    continue
                if str(p) == acct or str(p).endswith(":root"):
                    trusted.append(ACCOUNT_WIDE_TRUST)
                elif m := re.search(r":user/(?:.*/)?([^/]+)$", str(p)):
                    if m.group(1) in users:
                        trusted.append(f"user:{m.group(1)}")
                elif m := re.search(r":role/(?:.*/)?([^/]+)$", str(p)):
                    if m.group(1) in roles and m.group(1) != name:
                        trusted.append(f"role:{m.group(1)}")
            if isinstance(principal, dict) and principal.get("Federated"):
                self.report.count("federated")
        return sorted(set(trusted))

    def run(self) -> tuple[dict[str, Any], dict[str, Any]]:
        self._managed_policies()
        user_list = self.details.get("UserDetailList", []) or []
        group_list = self.details.get("GroupDetailList", []) or []
        role_list = self.details.get("RoleDetailList", []) or []
        external = [str(g) for g in self.context.get("external_identities", [])]

        users = []
        members: dict[str, list[str]] = {}
        for u in user_list:
            name = u.get("UserName", "?")
            cred = (self.credentials or {}).get(name)
            if cred:
                mfa = cred.get("mfa_active", "").lower() == "true"
                activity = [d for d in (self._days_since(cred.get(k)) for k in
                            ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"))
                            if d is not None]
                last = min(activity) if activity else self._days_since(cred.get("user_creation_time"))
            else:
                mfa, last = False, None
                self.report.count("no_credentials")
            users.append({"id": f"user:{name}", "name": name, "title": "IAM user",
                          "external": any(fnmatchcase(name, g) for g in external),
                          "mfa_enabled": mfa, "last_login_days": last,
                          "policies": self._attached(u, "user", "UserPolicyList")})
            for g in u.get("GroupList", []) or []:
                members.setdefault(g, []).append(f"user:{name}")

        groups = [{"id": f"group:{g.get('GroupName')}", "name": g.get("GroupName"),
                   "members": members.get(g.get("GroupName"), []),
                   "policies": self._attached(g, "group", "GroupPolicyList")} for g in group_list]

        user_names = {u.get("UserName") for u in user_list}
        role_names = {r.get("RoleName") for r in role_list}
        roles = [{"id": f"role:{r.get('RoleName')}", "name": r.get("RoleName"),
                  "description": r.get("Description") or "",
                  "trusted_principals": self._trust(r, user_names, role_names),
                  "policies": self._attached(r, "role", "RolePolicyList")} for r in role_list]

        resources = self._resources()
        report = self.report
        report.summary("no_credentials", "{n} users have no credential-report row, so MFA is treated as off and "
                                         "last sign-in as unknown. Add the credential report for accurate results.")
        report.summary("conditions", "{n} statements have Conditions, analysed as if the condition always passes "
                                     "(may over-report).")
        report.summary("boundaries", "{n} identities have permission boundaries, which are not applied "
                                     "(may over-report).")
        report.summary("federated", "{n} roles trust federated (SAML/OIDC) identities, which are not modelled.")
        report.summary("default_sensitivity", "{n} resources matched no sensitivity rule in the context file and "
                                              "were set to medium. Attack paths are only reported for high and "
                                              "critical resources.")

        data = {
            "metadata": {
                "name": self.context.get("dataset_name") or f"AWS account {self.account or 'unknown'}",
                "description": "Imported offline from an AWS IAM authorization-details export.",
                "synthetic": bool(self.context.get("synthetic", False)),
                "source": "aws-import",
                "account_id": self.account,
            },
            "users": users, "groups": groups, "roles": roles, "policies": self.policies, "resources": resources,
        }
        validate_dataset(data)
        return data, {
            "account_id": self.account,
            "counts": {k: len(data[k]) for k in ("users", "groups", "roles", "policies", "resources")},
            "warnings": report.warnings,
            "not_in_export": NOT_IN_EXPORT,
        }

    def _resources(self) -> list[dict[str, Any]]:
        rules = self.context.get("resources", []) or []
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("sensitivity") not in SENSITIVITY_LEVELS:
                raise DatasetError(f"context resource rule {rule!r} needs an 'arn' and a sensitivity of "
                                   f"{', '.join(SENSITIVITY_LEVELS)}")
            arn = str(rule.get("arn", ""))
            if arn and "*" not in arn and "?" not in arn:
                self.concrete_arns.add(arn)
        out = []
        for arn in sorted(self.concrete_arns):
            rule = next((r for r in rules if fnmatchcase(arn, str(r.get("arn", "")))), None)
            if rule is None:
                self.report.count("default_sensitivity")
            service = arn.split(":")[2] if arn.count(":") >= 2 else ""
            out.append({"id": f"res:{arn}", "name": (rule or {}).get("name") or _resource_name(arn),
                        "type": SERVICE_TYPES.get(service, service or "Resource"), "arn": arn,
                        "sensitivity": (rule or {}).get("sensitivity", DEFAULT_SENSITIVITY),
                        **({"data_classification": rule["data_classification"]}
                           if rule and rule.get("data_classification") else {})})
        return out


def import_aws(details: dict[str, Any], credential_csv: str | None = None, context: dict[str, Any] | None = None,
               now: datetime | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Convert an AWS IAM export into (BreachGraph dataset, import report)."""
    return _Importer(details, credential_csv, context, now).run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="breachgraph.importers.aws", description=__doc__.splitlines()[0])
    parser.add_argument("authorization_details", help="output of `aws iam get-account-authorization-details`")
    parser.add_argument("--credential-report", help="IAM credential report CSV")
    parser.add_argument("--context", help="JSON with resource sensitivity rules and external identities")
    parser.add_argument("-o", "--output", default="-", help="where to write the dataset (default: stdout)")
    args = parser.parse_args(argv)
    try:
        with open(args.authorization_details, encoding="utf-8-sig") as f:
            details = json.load(f)
        cred = open(args.credential_report, encoding="utf-8-sig").read() if args.credential_report else None
        context = json.load(open(args.context, encoding="utf-8-sig")) if args.context else None
        data, report = import_aws(details, cred, context)
    except (OSError, json.JSONDecodeError, DatasetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    text = json.dumps(data, indent=2)
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(f"Imported account {report['account_id']}: {report['counts']}", file=sys.stderr)
    for w in report["warnings"] + report["not_in_export"]:
        print(f"  note: {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
