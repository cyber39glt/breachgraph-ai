"""AWS export importer. Uses synthetic files in AWS's real export formats (data/aws-sample)."""

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from breachgraph import api
from breachgraph.engine import analyze
from breachgraph.importers.aws import import_aws, main
from breachgraph.model import DatasetError

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "aws-sample"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
PII = "res:arn:aws:s3:::halcyon-customer-pii"


@pytest.fixture
def export():
    return (json.loads((SAMPLE / "authorization-details.json").read_text()),
            (SAMPLE / "credential-report.csv").read_text(),
            json.loads((SAMPLE / "context.json").read_text()))


def imported(export, **changes):
    details, cred, context = export
    args = {"details": details, "credential_csv": cred, "context": context, **changes}
    return import_aws(args["details"], args["credential_csv"], args["context"], now=NOW)


def test_aws_export_reproduces_the_signature_attack_path(export):
    data, report = imported(export)
    result = analyze(data)
    assert result["summary"]["attack_paths"] == 6
    assert result["summary"]["findings_by_severity"]["critical"] == 4
    f = next(f for f in result["findings"] if f.get("key") == f"user:jordan.reyes->{PII}")
    assert f["path"] == ["user:jordan.reyes", "group:ci-maintainers", "role:ci-deploy",
                         "role:data-platform-admin", PII]
    assert f["level"] == "admin" and f["severity"] == "critical"
    assert report["account_id"] == "111122223333"
    assert report["counts"] == {"users": 6, "groups": 4, "roles": 3, "policies": 8, "resources": 8}


def test_credential_report_sets_mfa_and_activity(export):
    users = {u["name"]: u for u in imported(export)[0]["users"]}
    assert users["jordan.reyes"]["mfa_enabled"] is False and users["ava.thompson"]["mfa_enabled"] is True
    assert users["jordan.reyes"]["last_login_days"] == 3
    assert users["marco.bianchi"]["last_login_days"] > 90  # stale
    assert users["jordan.reyes"]["external"] is True and users["ava.thompson"]["external"] is False


def test_missing_credential_report_is_reported_not_hidden(export):
    data, report = imported(export, credential_csv=None)
    assert all(u["mfa_enabled"] is False for u in data["users"])
    assert any("credential-report" in w for w in report["warnings"])


def test_usage_is_unknown_so_nothing_is_called_unused(export):
    findings = analyze(imported(export)[0])["findings"]
    assert not any(f["type"] == "unused_permission" for f in findings)


def test_bucket_scoped_object_wildcards_are_not_flagged(export):
    titles = [f["title"] for f in analyze(imported(export)[0])["findings"] if f["type"] == "wildcard_permission"]
    assert not any("halcyon-build-artifacts/*" in t for t in titles)
    assert any("halcyon-*" in t for t in titles)  # a wildcard across buckets is still reported
    assert any("Wildcard resources * in ci-deploy-permissions / AssumeAnyRole" == t for t in titles)


def test_explicit_deny_still_applies_after_import(export):
    access = {a["key"] for a in analyze(imported(export)[0])["access"]}
    assert "user:lena.fischer->res:arn:aws:s3:::halcyon-audit-logs" in access
    assert f"user:lena.fischer->{PII}" not in access


def test_url_encoded_policy_documents_from_the_raw_api(export):
    details = copy.deepcopy(export[0])
    for p in details["Policies"]:
        for v in p["PolicyVersionList"]:
            v["Document"] = quote(json.dumps(v["Document"]))
    assert analyze(imported(export, details=details)[0])["summary"]["attack_paths"] == 6


def test_unsupported_policy_features_are_reported(export):
    details = copy.deepcopy(export[0])
    doc = details["Policies"][0]["PolicyVersionList"][0]["Document"]
    doc["Statement"].append({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    doc["Statement"][0]["Condition"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    details["UserDetailList"][0]["PermissionsBoundary"] = {"PermissionsBoundaryArn": "arn:aws:iam::111122223333:policy/b"}
    warnings = " ".join(imported(export, details=details)[1]["warnings"])
    assert "NotAction/NotResource" in warnings and "may under-report" in warnings
    assert "Conditions" in warnings and "permission boundaries" in warnings


def test_risky_trust_policies_are_flagged(export):
    details = copy.deepcopy(export[0])
    trust = details["RoleDetailList"][0]["AssumeRolePolicyDocument"]["Statement"]
    trust.append({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"})
    details["RoleDetailList"][1]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] = {"AWS": "*"}
    data, report = imported(export, details=details)
    warnings = " ".join(report["warnings"])
    assert "another AWS account (999988887777)" in warnings
    assert 'trusts any AWS principal ("*")' in warnings
    assert data["roles"][1]["trusted_principals"] == ["account:*"]


def test_missing_managed_policy_document_is_reported(export):
    details = copy.deepcopy(export[0])
    details["Policies"] = [p for p in details["Policies"] if p["PolicyName"] != "data-platform-full"]
    data, report = imported(export, details=details)
    assert any("data-platform-full" in w and "may under-report" in w for w in report["warnings"])
    assert analyze(data)["summary"]["attack_paths"] < 6


def test_resources_without_a_sensitivity_rule_default_to_medium(export):
    data, report = imported(export, context=None)
    assert {r["sensitivity"] for r in data["resources"]} == {"medium"}
    assert any("no sensitivity rule" in w for w in report["warnings"])
    assert data["metadata"]["synthetic"] is False and data["metadata"]["name"] == "AWS account 111122223333"


@pytest.mark.parametrize("details,message", [
    ({"hello": "world"}, "does not look like"),
    ([], "does not look like"),
])
def test_wrong_files_are_rejected(details, message):
    with pytest.raises(DatasetError, match=message):
        import_aws(details)


def test_bad_context_is_rejected(export):
    with pytest.raises(DatasetError, match="sensitivity"):
        imported(export, context={"resources": [{"arn": "x", "sensitivity": "extreme"}]})


def test_cli_writes_a_dataset(export, tmp_path, capsys):
    out = tmp_path / "dataset.json"
    code = main([str(SAMPLE / "authorization-details.json"), "--credential-report", str(SAMPLE / "credential-report.csv"),
                 "--context", str(SAMPLE / "context.json"), "-o", str(out)])
    assert code == 0 and json.loads(out.read_text())["metadata"]["source"] == "aws-import"
    assert "Resource-based policies" in capsys.readouterr().err


# --- API ---------------------------------------------------------------------------------

def test_import_endpoint(client, export):
    details, cred, context = export
    r = client.post("/api/import/aws", json={"authorization_details": details, "credential_report_csv": cred,
                                             "context": context})
    assert r.status_code == 200
    body = r.json()
    assert body["report"]["counts"]["users"] == 6 and body["report"]["not_in_export"]
    analysis = client.post("/api/analyze", json={"dataset": body["dataset"]}).json()
    assert analysis["summary"]["attack_paths"] == 6


def test_import_endpoint_rejects_other_files(client):
    r = client.post("/api/import/aws", json={"authorization_details": {"Users": []}})
    assert r.status_code == 400 and "does not look like" in r.json()["message"]


def test_import_allows_larger_bodies_than_other_endpoints(client):
    padding = " " * (api.MAX_BODY_BYTES + 10)
    body = ('{"authorization_details": {"UserDetailList": []}' + padding + "}").encode()
    assert client.post("/api/import/aws", content=body, headers={"content-type": "application/json"}).status_code != 413
    assert client.post("/api/analyze", content=body, headers={"content-type": "application/json"}).status_code == 413


def test_large_results_are_trimmed_with_exact_totals():
    paths = [{"type": "attack_path", "id": f"PATH-{i:08X}", "key": f"user:u{i}->res:r"} for i in range(400)]
    analysis = {"findings": paths + [{"type": "wildcard_permission", "id": "WILD-1"}],
                "access": [{"key": p["key"]} for p in paths], "summary": {}, "graph": {}}
    out = api.trim_analysis(analysis)
    assert out["truncated"] == {"attack_paths_total": 400, "attack_paths_shown": api.MAX_PATHS_RETURNED,
                                "access_total": 400, "access_shown": 400}  # under the access cap
    assert any(f["id"] == "WILD-1" for f in out["findings"])
    assert api.trim_analysis({"findings": paths[:3], "access": [], "summary": {}}) == {
        "findings": paths[:3], "access": [], "summary": {}}


def test_sample_export_endpoint_round_trips(client):
    sample = client.get("/api/demo/aws-sample").json()
    assert set(sample) == {"authorization_details", "credential_report_csv", "context"}
    r = client.post("/api/import/aws", json=sample)
    assert r.status_code == 200 and r.json()["dataset"]["metadata"]["synthetic"] is True
