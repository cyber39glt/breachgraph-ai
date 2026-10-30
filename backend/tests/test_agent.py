"""Fix Agent tests. The model is scripted with httpx.MockTransport: no key, no network."""

import json

import httpx
import pytest

from breachgraph import api
from breachgraph.agent import MAX_ROUNDS, run_fix_agent
from breachgraph.ai import AISettings
from breachgraph.engine import analyze
from breachgraph.model import load_dataset
from conftest import FAKE_KEY, SIGNATURE_PATH

REMOVE_WILDCARD = {"op": "remove_statement", "policy": "policy:ci-deploy-permissions", "sid": "AssumeAnyRole"}
SCOPE_FULLS3 = {"op": "set_statement_resources", "policy": "policy:data-platform-full", "sid": "FullS3",
                "resources": ["res:s3-analytics-warehouse"]}
NO_EFFECT = {"op": "remove_statement", "policy": "policy:analytics-read", "sid": "ReadWarehouse"}


def reply(analysis="", changes=(), done=False):
    return json.dumps({"analysis": analysis, "changes": list(changes), "done": done})


def scripted(*replies):
    """Answers each model call with the next scripted reply (or an exception / status code)."""
    queue = list(replies)
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, int):
            return httpx.Response(item, json={"error": {"message": f"echo {FAKE_KEY}"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": item}, "finish_reason": "stop"}]})

    transport = httpx.MockTransport(handler)
    transport.seen = seen
    return transport


@pytest.fixture
def demo():
    from pathlib import Path
    data = load_dataset(Path(__file__).resolve().parents[2] / "data" / "sample_org.json")
    analysis = analyze(data)
    finding = next(f for f in analysis["findings"] if f["id"] == SIGNATURE_PATH)
    return data, analysis, finding


def run(demo, transport, **kw):
    data, analysis, finding = demo
    return list(run_fix_agent(data, analysis, finding, AISettings(api_key=FAKE_KEY), transport, **kw))


def rounds(events):
    return [e for e in events if e["type"] == "round"]


def result(events):
    assert events[-1]["type"] == "result"
    return events[-1]


# --- the loop ------------------------------------------------------------------------

def test_self_corrects_after_simulator_rejects_bad_ids(demo):
    bad_ids = {"op": "remove_statement", "policy": "ci-deploy-permissions", "sid": "AssumeAnyRole"}
    t = scripted(reply("Remove the wildcard.", [bad_ids]),
                 reply("Use the prefixed id.", [REMOVE_WILDCARD]),
                 reply("Losing warehouse access is fine: it was only reachable via the escalation.",
                       [REMOVE_WILDCARD], done=True))
    events = run(demo, t)
    r = rounds(events)
    assert r[0]["verification"] == {"valid": False, "error": "unknown policy 'ci-deploy-permissions'"}
    assert r[1]["verification"]["requirements_met"] is True
    assert len(r[1]["verification"]["broken_paths"]) == 4
    assert len(r[1]["verification"]["other_access_removed"]) == 2
    final = result(events)
    assert final["outcome"] == "verified" and final["stopped_reason"] == "agent_done"
    assert final["best_changes"] == [REMOVE_WILDCARD] and final["model_calls"] == 3
    # The simulator's verdict on round 1 was sent back to the model in round 2.
    feedback = t.seen[1]["messages"][-1]["content"]
    assert "unknown policy 'ci-deploy-permissions'" in feedback


def test_stops_early_when_nothing_left_to_improve(demo):
    t = scripted(reply("Scope FullS3 away from the PII bucket.", [SCOPE_FULLS3]))
    events = run(demo, t)
    assert len(t.seen) == 1  # no further calls: credits saved
    v = rounds(events)[0]["verification"]
    assert v["target_path_broken"] and v["new_paths"] == [] and v["other_access_removed"] == []
    assert result(events)["stopped_reason"] == "nothing_left_to_improve"


def test_model_claiming_done_is_not_trusted(demo):
    t = scripted(*[reply("This fixes it.", [NO_EFFECT], done=True)] * MAX_ROUNDS)
    events = run(demo, t)
    assert all(not r["verification"]["target_path_broken"] for r in rounds(events))
    final = result(events)
    assert final["outcome"] == "not_found" and final["best_changes"] == []
    assert final["stopped_reason"] == "max_rounds" and final["model_calls"] == MAX_ROUNDS


def test_done_without_repeating_changes_uses_best_round(demo):
    t = scripted(reply("Remove the wildcard.", [REMOVE_WILDCARD]), reply("That is my final answer.", [], done=True))
    final = result(run(demo, t))
    assert final["outcome"] == "verified" and final["best_round"] == 1 and final["stopped_reason"] == "agent_done"


def test_prefers_less_collateral_across_rounds(demo):
    t = scripted(reply("Remove the wildcard.", [REMOVE_WILDCARD]), reply("Try scoping instead.", [SCOPE_FULLS3]))
    final = result(run(demo, t))
    assert final["best_round"] == 2 and final["best_changes"] == [SCOPE_FULLS3]


def test_invalid_operations_and_malformed_replies_are_rejected(demo):
    t = scripted("not json at all",
                 reply("Delete everything.", [{"op": "rm -rf /"}]),
                 reply("Ok.", [REMOVE_WILDCARD, NO_EFFECT, SCOPE_FULLS3, NO_EFFECT], done=True))
    r = rounds(run(demo, t))
    assert r[0]["rejected"] == ["The reply was not valid JSON."] and r[0]["verification"] is None
    assert "Not a valid simulator operation" in r[1]["rejected"][0] and r[1]["changes"] == []
    assert len(r[2]["changes"]) == 3 and "Only the first 3" in r[2]["rejected"][-1]


def test_upstream_error_mid_run_keeps_verified_rounds(demo):
    t = scripted(reply("Remove the wildcard.", [REMOVE_WILDCARD]), 429)
    events = run(demo, t)
    err = next(e for e in events if e["type"] == "error")
    assert err["error"] == "rate_limited" and FAKE_KEY not in json.dumps(events)
    final = result(events)
    assert final["stopped_reason"] == "rate_limited" and final["outcome"] == "verified"


def test_only_this_paths_evidence_is_sent(demo):
    t = scripted(reply("Scope FullS3.", [SCOPE_FULLS3]))
    run(demo, t)
    prompt = t.seen[0]["messages"][1]["content"]
    assert "jordan.reyes" in prompt and "AssumeAnyRole" in prompt
    assert "sam.okafor" not in prompt and "finance-reports" not in prompt
    assert FAKE_KEY not in json.dumps(t.seen)


# --- the endpoint ------------------------------------------------------------------------

def stream(client, body):
    with client.stream("POST", "/api/agent/fix", json=body) as r:
        lines = [json.loads(line) for line in r.iter_lines() if line]
        return r, lines


def test_endpoint_streams_rounds_then_result(client, with_key, monkeypatch):
    monkeypatch.setattr(api, "ai_transport", scripted(reply("Scope FullS3.", [SCOPE_FULLS3])))
    r, events = stream(client, {"finding_id": SIGNATURE_PATH})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    assert [e["type"] for e in events] == ["round", "result"]
    assert events[-1]["outcome"] == "verified" and events[-1]["ai_generated"] is True


def test_endpoint_requires_key(client):
    r = client.post("/api/agent/fix", json={"finding_id": SIGNATURE_PATH})
    assert r.status_code == 503 and r.json()["error"] == "not_configured"


def test_endpoint_validation(client, with_key):
    assert client.post("/api/agent/fix", json={"finding_id": SIGNATURE_PATH, "max_rounds": 9}).status_code == 422
    assert client.post("/api/agent/fix", json={"finding_id": "WILD-0D2FBC4D"}).status_code == 422
    assert client.post("/api/agent/fix", json={"finding_id": "PATH-00000000"}).status_code == 404


def test_endpoint_rate_limit(client, with_key, monkeypatch):
    for _ in range(api.AGENT_LIMIT_PER_MINUTE):
        monkeypatch.setattr(api, "ai_transport", scripted(reply("Scope.", [SCOPE_FULLS3])))
        assert stream(client, {"finding_id": SIGNATURE_PATH})[0].status_code == 200
    r = client.post("/api/agent/fix", json={"finding_id": SIGNATURE_PATH})
    assert r.status_code == 429 and r.json()["error"] == "local_rate_limited"


def test_wrong_key_is_explained_to_the_model_and_corrected(demo):
    wrong = {"operation": "remove_statement", "policy": "policy:ci-deploy-permissions", "sid": "AssumeAnyRole"}
    t = scripted(reply("Remove the wildcard.", [wrong]), reply("Use the op key.", [REMOVE_WILDCARD], done=True))
    events = run(demo, t)
    first = rounds(events)[0]
    assert first["changes"] == [] and 'missing "op" (found keys: operation, policy, sid)' in first["rejected"][0]
    assert 'missing \\"op\\"' in t.seen[1]["messages"][-1]["content"]  # the reason reached the model
    assert result(events)["outcome"] == "verified"
    assert '"op": "remove_statement"' in t.seen[0]["messages"][0]["content"]  # example in the agent prompt
