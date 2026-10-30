import { Bot, FlaskConical, RotateCcw } from "lucide-react";
import { useApp } from "../state";
import type { AgentRound, PathFinding } from "../types";
import { AILabel, Chip, CodeBlock, Notice, Spinner, VerifiedLabel } from "./ui";

const MAX_ROUNDS = 4;

const STOPPED: Record<string, string> = {
  agent_done: "The agent confirmed its best fix.",
  nothing_left_to_improve: "The fix met every requirement and removed no other access, so the agent stopped early.",
  max_rounds: `The agent used all ${MAX_ROUNDS} rounds.`,
};

function Verdict({ round, findingId }: { round: AgentRound; findingId: string }) {
  const v = round.verification;
  if (!v) return <p className="muted small">Nothing could be simulated in this round.</p>;
  if (!v.valid) return <p className="chips"><Chip tone="risk">Simulator rejected it: {v.error}</Chip></p>;
  const others = (v.broken_paths ?? []).filter((p) => p.id !== findingId).length;
  return (
    <>
      <p className="chips">
        <Chip tone={v.target_path_broken ? "safe" : "risk"}>
          {v.target_path_broken ? "Target path broken" : "Target path still open"}
        </Chip>
        {others > 0 && <Chip>+{others} other path{others > 1 ? "s" : ""} broken</Chip>}
        <Chip tone={(v.new_paths?.length ?? 0) > 0 ? "risk" : "neutral"}>{v.new_paths?.length ?? 0} new paths</Chip>
        <Chip>{v.other_access_removed?.length ?? 0} other access removed</Chip>
        <Chip>Risk {v.risk_before} → {v.risk_after}</Chip>
      </p>
      {(v.other_access_removed?.length ?? 0) > 0 && (
        <ul className="agent-collateral small muted">
          {v.other_access_removed!.map((a) => (
            <li key={a.key}>{a.identity} loses {a.level} on {a.resource}{a.via_roles.length ? ` (via ${a.via_roles.join(" → ")})` : ""}</li>
          ))}
        </ul>
      )}
    </>
  );
}

function Round({ round, findingId, best }: { round: AgentRound; findingId: string; best: boolean }) {
  return (
    <li className={`agent-round ${best ? "best" : ""}`}>
      <div className="agent-round-head">
        <span className="step-num" aria-hidden>{String(round.round).padStart(2, "0")}</span>
        <strong>Round {round.round}</strong>
        {best && <Chip tone="safe">Best verified fix</Chip>}
      </div>
      <div className="agent-proposal">
        <AILabel>Muse Spark proposed</AILabel>
        {round.analysis && <p>{round.analysis}</p>}
        {round.changes.length > 0 && <CodeBlock value={round.changes} />}
        {round.rejected.length > 0 && (
          <p className="chips">{round.rejected.map((r) => <Chip key={r} tone="risk">{r}</Chip>)}</p>
        )}
      </div>
      <div className="agent-verdict">
        <VerifiedLabel>Simulator measured</VerifiedLabel>
        <Verdict round={round} findingId={findingId} />
      </div>
    </li>
  );
}

export function FixAgentPanel({ finding }: { finding: PathFinding }) {
  const { analysis, agentRuns, runAgent, queueSimulation } = useApp();
  const run = agentRuns[finding.id];
  const ai = analysis?.ai;
  const result = run?.result;
  return (
    <section className="card ai-panel fix-agent" aria-labelledby="agent-title">
      <div className="card-head">
        <h2 id="agent-title"><Bot size={18} aria-hidden /> Fix Agent</h2>
        <AILabel>Agent · Meta AI</AILabel>
      </div>
      <p>Muse Spark proposes a least-privilege fix, the simulator tests it, and the measured result goes back to
        the model to refine, up to {MAX_ROUNDS} rounds. <strong>Only the simulator decides whether a fix works.</strong></p>

      {!run && (
        <>
          <button type="button" className="btn btn-primary" disabled={!ai?.configured} onClick={() => runAgent(finding.id)}>
            <Bot size={16} aria-hidden /> Run Fix Agent
          </button>
          <p className="fine">{ai?.configured
            ? `Uses up to ${MAX_ROUNDS} calls to ${ai.model}. Nothing is changed in any real system.`
            : "Set MODEL_API_KEY on the server to enable the agent."}</p>
        </>
      )}

      {run && run.rounds.length > 0 && (
        <ol className="agent-rounds" aria-live="polite">
          {run.rounds.map((r) => (
            <Round key={r.round} round={r} findingId={finding.id} best={result?.best_round === r.round} />
          ))}
        </ol>
      )}

      {run?.status === "running" && (
        <Spinner label={`Round ${run.rounds.length + 1}: waiting for Muse Spark…`} />
      )}

      {run?.error && (
        <Notice tone="error" title={run.rounds.length ? "The agent stopped early" : "The agent could not start"}>
          <p>{run.error.message}</p>
          {run.rounds.length > 0 && <p className="muted">Rounds above were verified before the error.</p>}
        </Notice>
      )}

      {result && result.outcome === "verified" && (
        <Notice tone="success" title={`Verified fix found in round ${result.best_round}`} action={
          <button type="button" className="btn btn-primary" onClick={() => queueSimulation(result.best_changes)}>
            <FlaskConical size={15} aria-hidden /> Open in simulator
          </button>
        }>
          The simulator confirmed this fix breaks the path and opens no new ones. {STOPPED[result.stopped_reason] ?? ""}
          {" "}{result.model_calls} model call{result.model_calls === 1 ? "" : "s"}.
        </Notice>
      )}
      {result && result.outcome === "not_found" && (
        <Notice tone="warning" title="No verified fix yet">
          None of the agent's proposals met the requirements. {STOPPED[result.stopped_reason] ?? ""} Try the
          engine-ranked fixes on this page.
        </Notice>
      )}

      {run && run.status !== "running" && (
        <button type="button" className="btn btn-ghost" onClick={() => runAgent(finding.id)} disabled={!ai?.configured}>
          <RotateCcw size={15} aria-hidden /> Run again
        </button>
      )}
    </section>
  );
}
