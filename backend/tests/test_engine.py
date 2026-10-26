import copy
import json
from pathlib import Path

import pytest

from breachgraph.engine import Analyzer, analyze, classify_action, severity_for
from breachgraph.model import DatasetError, load_dataset, validate_dataset
from breachgraph.simulate import simulate

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample_org.json"
SIGNATURE_FIX = [{"op": "remove_statement", "policy": "policy:ci-deploy-permissions", "sid": "AssumeAnyRole"}]


@pytest.fixture
def data():
    return load_dataset(SAMPLE)


def path_keys(result):
    return {f["key"] for f in result["findings"] if f["type"] == "attack_path"}


def minimal(**overrides):
    base = {
        "users": [{"id": "user:a", "name": "A", "mfa_enabled": True, "last_login_days": 1, "policies": []}],
        "groups": [],
        "roles": [],
        "policies": [],
        "resources": [{"id": "res:secret", "name": "secret", "sensitivity": "critical"}],
    }
    base.update(overrides)
    return base


# --- classification and scoring -------------------------------------------------

@pytest.mark.parametrize("action,level", [
    ("*", "admin"), ("s3:*", "admin"), ("s3:GetObject", "read"), ("dynamodb:Scan", "read"),
    ("kms:Decrypt", "read"), ("s3:PutObject", "write"), ("rds:DeleteDBInstance", "write"),
])
def test_classify_action(action, level):
    assert classify_action(action) == level


@pytest.mark.parametrize("score,severity", [(100, "critical"), (85, "critical"), (84, "high"),
                                            (65, "high"), (64, "medium"), (40, "medium"), (39, "low")])
def test_severity_thresholds(score, severity):
    assert severity_for(score) == severity


# --- the signature chain ---------------------------------------------------------

def test_signature_chain_is_found_with_full_evidence(data):
    result = analyze(data)
    f = next(f for f in result["findings"] if f["key"] == "user:jordan.reyes->res:s3-customer-pii")
    assert f["path"] == ["user:jordan.reyes", "group:ci-maintainers", "role:ci-deploy",
                         "role:data-platform-admin", "res:s3-customer-pii"]
    assert f["level"] == "admin"
    assert f["severity"] == "critical"
    assert f["score"] == min(100, sum(b["points"] for b in f["score_breakdown"]))
    assert [h["relation"] for h in f["hops"]] == ["member_of", "can_assume", "can_assume", "access"]
    sids = [h["evidence"]["grant"]["sid"] for h in f["hops"] if "grant" in h["evidence"]]
    assert sids == ["AssumeDeployRole", "AssumeAnyRole", "FullS3"]
    assert len(f["facts"]) == len(f["hops"])


def test_expected_attack_paths(data):
    assert path_keys(analyze(data)) == {
        "user:jordan.reyes->res:s3-customer-pii",
        "user:jordan.reyes->res:kms-pii-key",
        "user:ava.thompson->res:s3-customer-pii",
        "user:ava.thompson->res:kms-pii-key",
        "user:marco.bianchi->res:rds-payments",
        "user:marco.bianchi->res:ddb-support-tickets",
    }


def test_intended_access_is_not_a_finding(data):
    result = analyze(data)
    access = {a["key"] for a in result["access"]}
    # Sam reads finance reports directly, with MFA, and is active: inventory, not a path.
    assert "user:sam.okafor->res:s3-finance-reports" in access
    assert "user:sam.okafor->res:s3-finance-reports" not in path_keys(result)
    # Priya's analytics role reaches only a medium-sensitivity bucket.
    assert "user:priya.nair->res:s3-analytics-warehouse" in access
    assert not any(k.startswith("user:priya.nair") for k in path_keys(result))


def test_explicit_deny_blocks_wildcard_allow(data):
    access = {a["key"] for a in analyze(data)["access"]}
    assert "user:lena.fischer->res:s3-audit-logs" in access
    assert "user:lena.fischer->res:s3-customer-pii" not in access


def test_wildcard_and_unused_findings_link_to_paths(data):
    findings = {f["key"]: f for f in analyze(data)["findings"]}
    wild = findings["wildcard:policy:ci-deploy-permissions:AssumeAnyRole"]
    assert wild["severity"] == "high" and len(wild["related_findings"]) == 4
    unused = findings["unused:policy:support-ticket-export:ReadPaymentsDb"]
    assert "never been used" in unused["title"]
    # A wildcard that feeds no attack path stays medium.
    assert findings["wildcard:policy:security-audit-read:ReadAuditLogs"]["severity"] == "medium"


def test_finding_ids_are_stable(data):
    assert [f["id"] for f in analyze(data)["findings"]] == [f["id"] for f in analyze(data)["findings"]]


def test_graph_contains_every_entity_and_path_edge(data):
    graph = analyze(data)["graph"]
    ids = {n["id"] for n in graph["nodes"]}
    assert len(ids) == 6 + 4 + 3 + 8
    edges = {(e["source"], e["target"], e["relation"]) for e in graph["edges"]}
    assert ("role:ci-deploy", "role:data-platform-admin", "can_assume") in edges
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])


# --- AWS-style semantics on small datasets --------------------------------------

def test_assumed_role_does_not_inherit_user_deny():
    d = minimal(
        users=[{"id": "user:a", "name": "A", "mfa_enabled": True, "last_login_days": 1,
                "policies": ["policy:u"]}],
        roles=[{"id": "role:r", "name": "r", "trusted_principals": ["user:a"], "policies": ["policy:r"]}],
        policies=[
            {"id": "policy:u", "name": "u", "statements": [
                {"sid": "D", "effect": "Deny", "actions": ["*"], "resources": ["res:secret"]}]},
            {"id": "policy:r", "name": "r", "statements": [
                {"sid": "A", "effect": "Allow", "actions": ["s3:GetObject"], "resources": ["res:secret"]}]},
        ],
    )
    reach = Analyzer(d).reach_from("user:a")
    assert [(r["resource"], r["roles"]) for r in reach] == [("res:secret", ["role:r"])]


def test_account_trust_requires_identity_permission():
    d = minimal(
        roles=[{"id": "role:r", "name": "r", "trusted_principals": ["account:*"], "policies": ["policy:r"]}],
        policies=[{"id": "policy:r", "name": "r", "statements": [
            {"sid": "A", "effect": "Allow", "actions": ["*"], "resources": ["*"]}]}],
    )
    assert Analyzer(d).reach_from("user:a") == []


def test_role_cycles_terminate():
    d = minimal(
        users=[{"id": "user:a", "name": "A", "mfa_enabled": True, "last_login_days": 1, "policies": []}],
        roles=[
            {"id": "role:x", "name": "x", "trusted_principals": ["user:a", "role:y"], "policies": []},
            {"id": "role:y", "name": "y", "trusted_principals": ["role:x"], "policies": []},
        ],
    )
    assert Analyzer(d).reach_from("user:a") == []


# --- simulation -----------------------------------------------------------------

def test_signature_fix_breaks_escalation_without_new_paths(data):
    diff = simulate(data, SIGNATURE_FIX)["diff"]
    assert {f["key"] for f in diff["broken_paths"]} == {
        "user:jordan.reyes->res:s3-customer-pii", "user:jordan.reyes->res:kms-pii-key",
        "user:ava.thompson->res:s3-customer-pii", "user:ava.thompson->res:kms-pii-key",
    }
    assert diff["new_paths"] == [] and diff["access_added"] == []
    assert diff["risk_after"] < diff["risk_before"]
    # The CI role keeps the deploy access it actually uses.
    after = {a["key"] for a in simulate(data, SIGNATURE_FIX)["after"]["access"]}
    assert "user:jordan.reyes->res:s3-build-artifacts" in after


def test_simulation_does_not_mutate_input(data):
    before = copy.deepcopy(data)
    simulate(data, SIGNATURE_FIX)
    assert data == before


def test_ineffective_change_breaks_nothing(data):
    change = [{"op": "set_statement_resources", "policy": "policy:analytics-read", "sid": "ReadWarehouse",
               "resources": ["res:s3-analytics-warehouse"]}]
    diff = simulate(data, change)["diff"]
    assert diff["broken_paths"] == [] and diff["risk_after"] == diff["risk_before"]


@pytest.mark.parametrize("change,message", [
    ({"op": "drop_database"}, "unknown operation"),
    ({"op": "remove_statement", "policy": "policy:nope", "sid": "X"}, "unknown policy"),
    ({"op": "remove_statement", "policy": "policy:analytics-read"}, "needs sid"),
    ({"op": "remove_group_member", "group": "group:ci-maintainers", "user": "user:sam.okafor"}, "not a member"),
    ({"op": "set_role_trust", "role": "role:ci-deploy", "trusted_principals": ["group:ci-maintainers"]},
     "cannot name a group"),
])
def test_invalid_changes_are_rejected(data, change, message):
    with pytest.raises(DatasetError, match=message):
        simulate(data, [change])


# --- validation -----------------------------------------------------------------

@pytest.mark.parametrize("mutate,message", [
    (lambda d: d["users"][0].update(id="bad"), "must start with 'user:'"),
    (lambda d: d["groups"][0]["members"].append("user:ghost"), "unknown member"),
    (lambda d: d["resources"][0].update(sensitivity="extreme"), "sensitivity"),
    (lambda d: d["policies"][0]["statements"][0].update(effect="Maybe"), "effect"),
    (lambda d: d["users"].append(dict(d["users"][0])), "duplicate id"),
])
def test_validation_rejects_malformed_data(data, mutate, message):
    mutate(data)
    with pytest.raises(DatasetError, match=message):
        validate_dataset(data)


def test_sample_dataset_is_marked_synthetic():
    assert json.loads(SAMPLE.read_text())["metadata"]["synthetic"] is True
