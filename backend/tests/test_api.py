import copy
import json

from breachgraph import api
from conftest import SIGNATURE_PATH

FIX = {"op": "remove_statement", "policy": "policy:ci-deploy-permissions", "sid": "AssumeAnyRole"}


def test_health_reports_ai_status_without_secrets(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["ai"] == {"provider": "Meta Model API", "configured": False, "model": "muse-spark-1.3"}


def test_demo_analysis_matches_engine(client):
    body = client.post("/api/analyze", json={}).json()
    assert body["dataset"]["synthetic"] is True
    assert body["summary"]["attack_paths"] == 6
    assert body["summary"]["findings_by_severity"] == {"critical": 4, "high": 5, "medium": 4, "low": 0}
    assert body["findings"][0]["id"] == SIGNATURE_PATH
    assert body["graph"]["nodes"] and body["graph"]["edges"]


def test_candidates_rank_the_signature_fix_first(client):
    top = client.post("/api/analyze", json={}).json()["candidates"][0]
    assert top["change"] == FIX
    assert len(top["preview"]["broken_paths"]) == 4
    assert top["preview"]["new_paths"] == []
    assert "wildcard" in top["notes"] and "unused for 140 days" in top["notes"]


def test_uploaded_dataset_is_analyzed(client):
    data = client.get("/api/demo/dataset").json()
    data["users"] = [u for u in data["users"] if u["id"] != "user:marco.bianchi"]
    for g in data["groups"]:
        g["members"] = [m for m in g["members"] if m != "user:marco.bianchi"]
    body = client.post("/api/analyze", json={"dataset": data}).json()
    assert body["summary"]["attack_paths"] == 4


def test_simulate_confirms_broken_and_remaining_paths(client):
    body = client.post("/api/simulate", json={"changes": [FIX]}).json()
    assert len(body["diff"]["broken_paths"]) == 4
    assert {p["entry"] for p in body["diff"]["remaining_paths"]} == {"user:marco.bianchi"}
    assert body["diff"]["new_paths"] == []
    assert body["after"]["summary"]["attack_paths"] == 2
    assert "No real permissions were changed" in body["note"]


def test_simulate_reports_collateral_damage(client):
    change = {"op": "remove_group_member", "group": "group:ci-maintainers", "user": "user:jordan.reyes"}
    diff = client.post("/api/simulate", json={"changes": [change]}).json()["diff"]
    assert "user:jordan.reyes->res:s3-build-artifacts" in {a["key"] for a in diff["collateral_access_removed"]}


def test_simulate_requires_changes(client):
    r = client.post("/api/simulate", json={"changes": []})
    assert r.status_code == 422 and r.json()["error"] == "invalid_request"


def test_bad_change_is_a_clear_400(client):
    r = client.post("/api/simulate", json={"changes": [{"op": "remove_statement", "policy": "policy:x", "sid": "y"}]})
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_dataset", "message": "unknown policy 'policy:x'"}


def test_invalid_dataset_rejected(client):
    r = client.post("/api/analyze", json={"dataset": {"users": "nope"}})
    assert r.status_code == 400 and "'users' must be a list" in r.json()["message"]


def test_oversized_dataset_rejected(client):
    data = client.get("/api/demo/dataset").json()
    data["users"] = [dict(data["users"][0], id=f"user:u{i}") for i in range(api.MAX_ENTITIES["users"] + 1)]
    r = client.post("/api/analyze", json={"dataset": data})
    assert r.status_code == 400 and "too many users" in r.json()["message"]


def test_oversized_body_rejected(client):
    r = client.post("/api/analyze", content=b"{" + b" " * api.MAX_BODY_BYTES + b"}",
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_unknown_fields_rejected(client):
    r = client.post("/api/analyze", json={"dataset": None, "evil": True})
    assert r.status_code == 422


def test_explain_rejects_malformed_and_unknown_ids(client):
    assert client.post("/api/explain", json={"finding_id": "WILD-0D2FBC4D"}).status_code == 422
    assert client.post("/api/explain", json={"finding_id": "../../etc"}).status_code == 422
    r = client.post("/api/explain", json={"finding_id": "PATH-00000000"})
    assert r.status_code == 404 and r.json()["error"] == "not_found"


def test_explain_without_key_is_honest(client):
    r = client.post("/api/explain", json={"finding_id": SIGNATURE_PATH})
    assert r.status_code == 503
    assert r.json() == {"error": "not_configured", "ai_generated": False,
                        "message": "AI explanations are off: MODEL_API_KEY is not set on the server."}


def test_security_headers(client):
    r = client.get("/api/health")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_unknown_api_route_is_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.json()["error"] == "not_found"


def test_request_does_not_mutate_demo(client):
    before = copy.deepcopy(client.get("/api/demo/dataset").json())
    client.post("/api/simulate", json={"changes": [FIX]})
    assert client.get("/api/demo/dataset").json() == before


def test_openapi_lists_endpoints(client):
    paths = json.loads(client.get("/api/openapi.json").text)["paths"]
    assert {"/api/analyze", "/api/simulate", "/api/explain", "/api/health"} <= set(paths)
