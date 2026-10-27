"""Live connection check for the Meta Model API. Run it yourself; it is not part of pytest.

It makes at most two small requests with your MODEL_API_KEY:
  1. GET  {base}/models                  (only with --list-models)
  2. POST {base}/chat/completions        (one short explanation of the demo's top finding)

It prints only status codes, model ids and the validated explanation. It never
prints the key, request headers or raw error bodies.

    cd breachgraph/backend
    python scripts/live_ai_check.py --list-models
    python scripts/live_ai_check.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from breachgraph.ai import AIError, AISettings, explain_finding  # noqa: E402
from breachgraph.engine import analyze  # noqa: E402
from breachgraph.model import load_dataset  # noqa: E402


def list_models(settings: AISettings) -> int:
    try:
        r = httpx.get(f"{settings.base_url}/models", timeout=settings.timeout,
                      headers={"Authorization": f"Bearer {settings.api_key}"})
    except httpx.HTTPError as e:
        print(f"FAIL  could not reach {settings.base_url} ({type(e).__name__})")
        return 1
    print(f"GET /models -> HTTP {r.status_code}")
    if r.status_code != 200:
        return 1
    try:
        ids = sorted(m.get("id", "?") for m in r.json().get("data", []))
    except (ValueError, AttributeError):
        print("FAIL  the reply was not the expected JSON list")
        return 1
    print("Models:", ", ".join(ids) or "(none listed)")
    print(f"MODEL_NAME={settings.model} is {'listed' if settings.model in ids else 'NOT listed'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list-models", action="store_true", help="only list the models your key can use")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env", override=False)
    settings = AISettings.from_env()
    print(f"Endpoint: {settings.base_url}   Model: {settings.model}   Key set: {settings.configured}")
    if not settings.configured:
        print("FAIL  MODEL_API_KEY is not set. See the README section 'Configure the Meta Model API'.")
        return 1
    if args.list_models:
        return list_models(settings)

    data = load_dataset(ROOT / "data" / "sample_org.json")
    analysis = analyze(data)
    finding = analysis["findings"][0]
    print(f"Explaining {finding['id']}: {finding['title']}")
    try:
        result = explain_finding(data, analysis, finding, settings)
    except AIError as e:
        print(f"FAIL  {e.code}: {e.message}")
        return 1
    print("PASS  the API answered and the reply passed validation.")
    print(json.dumps(result["explanation"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
