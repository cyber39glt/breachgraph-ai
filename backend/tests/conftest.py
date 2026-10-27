import json

import httpx
import pytest
from fastapi.testclient import TestClient

from breachgraph import api

FAKE_KEY = "test-key-7f3c9a1e-never-real"
SIGNATURE_PATH = "PATH-9B77622F"  # Jordan Reyes -> customer-pii, a stable id from the engine


def model_reply(content: str, status: int = 200, finish_reason: str = "stop", headers=None):
    """An httpx transport that answers like an OpenAI-compatible chat endpoint."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if status != 200:
            return httpx.Response(status, json={"error": {"message": f"echo {FAKE_KEY}"}}, headers=headers)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content},
                                                      "finish_reason": finish_reason}]})

    transport = httpx.MockTransport(handler)
    transport.seen = seen
    return transport


GOOD_EXPLANATION = json.dumps({
    "summary": "A contractor without MFA can chain two role assumptions to reach admin on the PII bucket.",
    "impact": "Full read and write over synthetic cardholder data.",
    "facts_used": ["ci-deploy-permissions / AssumeAnyRole allows sts:AssumeRole on *"],
    "assumptions": ["The contractor's credentials could be phished because MFA is off."],
    "uncertainties": ["Whether CloudTrail alerts on role chaining is not in the evidence."],
    "remediation": [
        {"title": "Remove the unused wildcard AssumeRole statement",
         "rationale": "Unused for 140 days and it is the escalation step.",
         "change": {"op": "remove_statement", "policy": "policy:ci-deploy-permissions", "sid": "AssumeAnyRole"}},
        {"title": "Delete the whole account", "rationale": "Bad idea.", "change": {"op": "rm -rf /"}},
        {"title": "Turn on MFA for contractors", "rationale": "Not expressible as a change.", "change": None},
    ],
})


@pytest.fixture
def client(monkeypatch):
    for var in ("MODEL_API_KEY", "MODEL_API_BASE_URL", "MODEL_NAME", "MODEL_TIMEOUT_SECONDS"):
        monkeypatch.delenv(var, raising=False)
    api._analysis_cache.clear()
    api._explain_cache.clear()
    api._explain_calls.clear()
    monkeypatch.setattr(api, "ai_transport", None)
    with TestClient(api.app) as c:
        yield c


@pytest.fixture
def with_key(monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY", FAKE_KEY)
