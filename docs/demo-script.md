# BreachGraph AI: three-minute demo script

Demo the **running product**, not slides. Total ≈ 3:00.

## Before you record

- [ ] `cd backend && python scripts/live_ai_check.py` prints **PASS** (if it does not, record
      the AI part as "AI off" and say so; never show staged or edited AI output).
- [ ] API running (`uvicorn breachgraph.api:app --host 127.0.0.1 --port 8000`), dashboard built.
- [ ] Browser at 1440×900 or larger, zoom 100%, a fresh tab on `http://127.0.0.1:8000/#/overview`.
- [ ] Generate the AI explanation for `PATH-9B77622F` once beforehand, so the recording uses the
      cached answer and does not wait on the network. Say on camera that it was generated live
      by Meta AI (it is, and it is labelled with the model and time).

---

## 0:00 – 0:20 · The problem (Overview page)

> "Cloud breaches rarely come from one bad permission. They come from a **chain**: a group
> membership, a role trust and a wildcard nobody has used in months. BreachGraph AI finds those
> chains, proves them, and lets you test the fix before you touch production."

Point at the metrics: **6 identities, 6 attack paths, 4 critical findings**, and the dataset
chip: *"This is a fictional company, all synthetic data. Nothing connects to a real cloud."*

## 0:20 – 0:50 · The risky chain (Highest-risk path card → Attack graph)

Read the hero card: *"A contractor, Jordan Reyes, no MFA, can get **admin on customer PII** in
four steps."* Click **Attack graph**, choose the path in *Highlight*, and click the edge
**ci-deploy → data-platform-admin**.

> "Every edge is backed by evidence. This one is policy `ci-deploy-permissions`, statement
> `AssumeAnyRole`: `sts:AssumeRole` on **star**, last used **140 days ago**. That one wildcard
> turns a deploy role into a stepping stone to the data platform's admin role."

## 0:50 – 1:30 · Evidence and severity (Investigate)

Click **Investigate** on the path.

> "On the left is the **verified evidence**: four numbered steps, each with the exact policy
> statement. This comes from a deterministic Python engine that applies AWS-style rules:
> sessions, role trust, explicit deny. It's reproducible and covered by tests."

Scroll to **Why this severity**: *"No black-box score. Critical resource +60, admin +20, no MFA
+10, contractor +8, escalation +5. Capped at 100."*

## 1:30 – 2:05 · Meta AI explanation (AI panel)

Click **Generate explanation** (or show the cached one).

> "Now Meta AI explains it. We send **only this finding's evidence**, not the dataset, and ask
> for facts, assumptions and uncertainties **separately**. The panel is clearly labelled
> AI-generated, with the model name."

Point at **Assumptions (not verified)**, then at a suggested fix and its chip:

> "The AI's fixes aren't taken on trust. Each is run through our simulator. This one says
> 'Simulator: breaks this path'. That's the engine talking, not the model."

## 2:05 – 2:45 · Verified remediation (Simulate fix)

Click **Open in simulator** (or select the first candidate and run it).

> "Here's the fix: remove the unused `AssumeAnyRole` statement. The whole analysis re-runs on a
> copy of the data."

Point, in order:
1. **"4 attack paths confirmed broken"**: *"confirmed by recomputation, not predicted."*
2. **Attack paths 6 → 2, risk 516 → 167, critical 4 → 1.**
3. **Before/After graphs**: the lime dashed edge is the cut.
4. **Still open: 2**: *"Marco's legacy support group is a separate problem. We don't pretend
   one fix solves everything."*
5. **Other access removed**: *"It tells you what else changes, so you can check nobody loses
   access they need. CI keeps its deploy access."*

## 2:45 – 3:00 · Close

> "BreachGraph AI: a deterministic engine for proof, Meta AI for explanation, and a simulator so
> every fix is verified before anyone changes a permission. Built for this hackathon on
> synthetic data, with no real cloud access needed. It's open source at
> github.com/cyber39glt/breachgraph-ai."

---

## If something goes wrong live

| Situation | What to do |
|---|---|
| AI call fails or times out | Show the error panel: *"It reports the real failure and never invents an answer."* Continue with the engine-ranked fixes. |
| No API credits / key | The AI panel says "AI explanations are off"; demo everything else. |
| Graph looks cramped | Use the **fit** button (top right of the graph). |
