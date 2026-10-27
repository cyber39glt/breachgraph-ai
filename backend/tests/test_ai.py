"""Meta Model API integration, tested with mocked HTTP replies only.

No test here needs a real key or makes a network call: every request goes to an
httpx.MockTransport. The live check is a separate script (scripts/live_ai_check.py).
"""

import json
import logging

import httpx
import pytest

from breachgraph import ai, api
from breachgraph.ai import AIError, AISettings, parse_explanation
from conftest import FAKE_KEY, GOOD_EXPLANATION, SIGNATURE_PATH, model_reply


def explain(client, monkeypatch, transport):
    monkeypatch.setattr(api, "ai_transport", transport)
    return client.post("/api/explain", json={"finding_id": SIGNATURE_PATH})


def test_successful_explanation_is_labelled_and_verified(client, with_key, monkeypatch):
    transport = model_reply(GOOD_EXPLANATION)
    r = explain(client, monkeypatch, transport)
    assert r.status_code == 200
    body = r.json()
    assert body["ai_generated"] is True and body["provider"] == "Meta Model API"
    assert body["model"] == "muse-spark-1.3"
    rem = body["explanation"]["remediation"]
    # 1: valid, and the simulator confirms it breaks the path.
    assert rem[0]["verification"]["valid"] and rem[0]["verification"]["breaks_this_path"]
    assert rem[0]["verification"]["new_paths"] == []
    # 2: an operation the simulator does not know is rejected, never run.
    assert rem[1]["change"] is None and rem[1]["change_rejected"] is True
    # 3: advice with no change stays advice.
    assert rem[2]["change"] is None and rem[2]["change_rejected"] is False and rem[2]["verification"] is None


def test_request_format_and_minimal_evidence(client, with_key, monkeypatch):
    transport = model_reply(GOOD_EXPLANATION)
    explain(client, monkeypatch, transport)
    (request,) = transport.seen
    assert str(request.url) == "https://api.meta.ai/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {FAKE_KEY}"
    payload = json.loads(request.content)
    assert payload["model"] == "muse-spark-1.3"
    assert [m["role"] for m in payload["messages"]] == ["system", "user"]
    prompt = payload["messages"][1]["content"]
    assert FAKE_KEY not in prompt
    # Only this finding's evidence: unrelated people and resources are not sent.
    assert "jordan.reyes" in prompt and "customer-pii" in prompt
    assert "sam.okafor" not in prompt and "finance-reports" not in prompt and "marco.bianchi" not in prompt


def test_config_overrides(client, with_key, monkeypatch):
    monkeypatch.setenv("MODEL_API_BASE_URL", "https://example.test/v9/")
    monkeypatch.setenv("MODEL_NAME", "muse-spark-1.1")
    transport = model_reply(GOOD_EXPLANATION)
    assert explain(client, monkeypatch, transport).json()["model"] == "muse-spark-1.1"
    assert str(transport.seen[0].url) == "https://example.test/v9/chat/completions"


def test_explanations_are_cached_to_save_credits(client, with_key, monkeypatch):
    transport = model_reply(GOOD_EXPLANATION)
    assert explain(client, monkeypatch, transport).json()["cached"] is False
    assert explain(client, monkeypatch, transport).json()["cached"] is True
    assert len(transport.seen) == 1


def test_local_rate_limit(client, with_key, monkeypatch):
    monkeypatch.setattr(api, "_explain_cache", api._LRU(0))  # force real calls
    transport = model_reply(GOOD_EXPLANATION)
    codes = [explain(client, monkeypatch, transport).status_code for _ in range(api.EXPLAIN_LIMIT_PER_MINUTE + 1)]
    assert codes[:-1] == [200] * api.EXPLAIN_LIMIT_PER_MINUTE
    assert codes[-1] == 429


@pytest.mark.parametrize("status,code,http", [
    (401, "auth_failed", 502), (403, "auth_failed", 502), (404, "not_found", 502),
    (429, "rate_limited", 429), (500, "upstream_error", 502), (400, "request_rejected", 502),
])
def test_upstream_errors_are_mapped_and_never_echoed(client, with_key, monkeypatch, status, code, http):
    r = explain(client, monkeypatch, model_reply("", status=status, headers={"retry-after": "30"}))
    assert r.status_code == http
    body = r.json()
    assert body["error"] == code and body["ai_generated"] is False
    assert "explanation" not in body
    # The fake upstream echoes the key in its error body; it must never reach the client.
    assert FAKE_KEY not in r.text
    if status == 429:
        assert r.headers["retry-after"] == "30"


@pytest.mark.parametrize("exc,code,http", [
    (httpx.ReadTimeout("slow"), "timeout", 504),
    (httpx.ConnectError("no route"), "network_error", 502),
])
def test_network_failures(client, with_key, monkeypatch, exc, code, http):
    def boom(request):
        raise exc

    r = explain(client, monkeypatch, httpx.MockTransport(boom))
    assert r.status_code == http and r.json()["error"] == code


@pytest.mark.parametrize("content", [
    "Sure! Here is my analysis without JSON.",
    "{not json}",
    json.dumps({"impact": "no summary"}),
    json.dumps(["a", "list"]),
])
def test_malformed_model_output_is_discarded_not_faked(client, with_key, monkeypatch, content):
    r = explain(client, monkeypatch, model_reply(content))
    assert r.status_code == 502 and r.json()["error"] == "malformed_response"
    assert "explanation" not in r.json()


def test_reply_without_choices_is_malformed(client, with_key, monkeypatch):
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"unexpected": True}))
    r = explain(client, monkeypatch, transport)
    assert r.status_code == 502 and r.json()["error"] == "malformed_response"


def test_fenced_json_and_content_parts_are_accepted(client, with_key, monkeypatch):
    parts = [{"type": "text", "text": "```json\n"}, {"type": "text", "text": GOOD_EXPLANATION + "\n```"}]
    transport = httpx.MockTransport(lambda req: httpx.Response(
        200, json={"choices": [{"message": {"content": parts}, "finish_reason": "length"}]}))
    body = explain(client, monkeypatch, transport).json()
    assert body["explanation"]["summary"].startswith("A contractor")
    assert body["truncated"] is True


def test_parse_explanation_caps_lengths_and_types():
    out = parse_explanation(json.dumps({
        "summary": "x" * 5000, "facts_used": ["ok", 7, None, ""] + ["f"] * 20,
        "remediation": [{"title": "t", "change": {"op": "set_role_trust", "role": "role:a",
                                                  "trusted_principals": "not-a-list"}}],
    }))
    assert len(out["summary"]) == ai.LIMITS["summary"]
    assert out["facts_used"][0] == "ok" and len(out["facts_used"]) <= ai.LIMITS["list"]
    assert out["remediation"][0]["change"] is None and out["remediation"][0]["change_rejected"]


def test_settings_never_print_the_key(monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY", FAKE_KEY)
    s = AISettings.from_env()
    assert s.configured and FAKE_KEY not in repr(s) and FAKE_KEY not in str(s)


def test_key_never_logged(client, with_key, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    explain(client, monkeypatch, model_reply(GOOD_EXPLANATION))
    explain(client, monkeypatch, httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))))
    assert FAKE_KEY not in caplog.text


def test_blank_key_counts_as_missing(monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY", "   ")
    with pytest.raises(AIError) as e:
        ai.call_model(AISettings.from_env(), [])
    assert e.value.code == "not_configured"


def test_redact():
    assert ai.redact(f"key={FAKE_KEY}", FAKE_KEY) == "key=[REDACTED]"
    assert ai.redact("nothing", None) == "nothing"
