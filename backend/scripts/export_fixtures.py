"""Write real API responses for the demo dataset to the frontend test fixtures.

The dashboard tests use these files instead of a running server, so they check the
UI against genuine engine output. Re-run after changing the engine or dataset:

    cd breachgraph/backend && python scripts/export_fixtures.py
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.pop("MODEL_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

from breachgraph.api import app  # noqa: E402

OUT = ROOT / "frontend" / "src" / "test" / "fixtures"
FIX = {"op": "remove_statement", "policy": "policy:ci-deploy-permissions", "sid": "AssumeAnyRole"}

with TestClient(app) as client:
    responses = {
        "dataset.json": client.get("/api/demo/dataset").json(),
        "analyze.json": client.post("/api/analyze", json={}).json(),
        "simulate.json": client.post("/api/simulate", json={"changes": [FIX]}).json(),
    }
OUT.mkdir(parents=True, exist_ok=True)
for name, body in responses.items():
    (OUT / name).write_text(json.dumps(body, indent=1) + "\n", encoding="utf-8")
    print("wrote", OUT / name)
