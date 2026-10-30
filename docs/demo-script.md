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
- [ ] Run the **Fix Agent** on the same path and keep the tab open (see "Recording the agent
      honestly" below). Running it uses up to 4 model calls.

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

## 0:50 – 1:15 · Evidence and severity (Investigate)

Click **Investigate** on the path.

> "On the left is the **verified evidence**: four numbered steps, each with the exact policy
> statement. This comes from a deterministic Python engine that applies AWS-style rules:
> sessions, role trust, explicit deny. It's reproducible and covered by tests."

Point at **Why this severity**: *"No black-box score: every point is a named factor."*

## 1:15 – 1:35 · Meta AI explanation (AI panel)

Show the explanation you generated before recording.

> "Muse Spark explains it from **only this finding's evidence**, and keeps facts, assumptions
> and uncertainties **separate**. It's clearly labelled AI-generated, with the model and time."

## 1:35 – 2:15 · The Fix Agent (the core Meta AI feature)

Show the Fix Agent run you started before recording (see below), scrolling through the rounds.

> "This is the Fix Agent. Muse Spark proposes a least-privilege fix, as structured changes.
> Our simulator applies them to a copy of the data and measures the result, and that
> measurement goes **back to the model**, which refines its proposal."

Point at a round's two halves:

> "Dashed is what the model proposed. Solid is what the simulator measured. If the model gets
> something wrong, like an id that doesn't exist, the simulator rejects it and the agent
> corrects itself in the next round. The model never gets to say 'fixed': only the simulator
> does."

Point at **Verified fix found in round N**, then click **Open in simulator**.

## 2:15 – 2:50 · Verified remediation (Simulate fix)

> "The whole analysis re-runs on the changed copy."

Point, in order (numbers shown are for removing `AssumeAnyRole`; read the ones on screen):
1. **"N attack paths confirmed broken"**: *"confirmed by recomputation, not predicted."*
2. **The before/after metrics** (attack paths, risk, critical findings).
3. **Before/After graphs**: the lime dashed edge is the cut.
4. **Still open**: *"Marco's legacy support group is a separate problem. We don't pretend one
   fix solves everything."*
5. **Other access removed**: *"It tells you what else changes, so nobody loses access they
   need by surprise."*

## 2:50 – 3:00 · Close

> "BreachGraph AI: a deterministic engine for proof, a Muse Spark agent that proposes fixes,
> and a simulator that verifies every one before anyone touches a permission. Built during
> this hackathon, on synthetic data. Open source at github.com/cyber39glt/breachgraph-ai."

### Recording the agent honestly

A full agent run can take 30 seconds to 2 minutes. Start it before you record, and keep the
browser tab open (reloading clears it). On camera, say it was run live by Muse Spark a moment
earlier. If you record the run itself, you may speed it up in editing, but label it on screen
(for example "sped up 4×"). Never edit or stage the model's output.

---

## If something goes wrong live

| Situation | What to do |
|---|---|
| AI call fails or times out | Show the error panel: *"It reports the real failure and never invents an answer."* Continue with the engine-ranked fixes. |
| Fix Agent finds no verified fix | Show it: *"The agent didn't find one, and the app says so instead of pretending."* Use the engine-ranked fix. |
| No API credits / key | The AI panel says "AI explanations are off"; demo everything else. |
| Graph looks cramped | Use the **fit** button (top right of the graph). |
