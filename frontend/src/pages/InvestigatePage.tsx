import { FlaskConical, RotateCcw, Sparkles, Waypoints } from "lucide-react";
import { useMemo } from "react";
import { FixAgentPanel } from "../components/FixAgentPanel";
import { GraphView } from "../components/GraphView";
import { AILabel, Chip, CodeBlock, Empty, Entity, Eyebrow, LevelTag, Notice, PageHeader, SeverityBadge, Spinner, VerifiedLabel } from "../components/ui";
import { edgeId, isPath, pathElements, pathsOf, RELATION_LABEL } from "../lookup";
import { useApp, type ExplainState } from "../state";
import type { Explanation, PathFinding } from "../types";
import { PathChain } from "./OverviewPage";

const AI_ERROR_HELP: Record<string, string> = {
  not_configured: "Set MODEL_API_KEY on the server (see the README), then restart the API. Everything else works without it.",
  auth_failed: "Check that MODEL_API_KEY is correct and active in your Meta developer account.",
  not_found: "Check MODEL_NAME and MODEL_API_BASE_URL against the models your account can use.",
  rate_limited: "Wait a minute, or check your remaining API credits.",
  local_rate_limited: "BreachGraph limits AI calls per minute to protect your credits.",
  timeout: "The model took too long. Try again, or raise MODEL_TIMEOUT_SECONDS.",
  network_error: "The server could not reach the Meta Model API. Check your network or proxy.",
  malformed_response: "The model reply failed validation and was discarded. Trying again usually helps.",
};

function PathPicker() {
  const { analysis } = useApp();
  const paths = analysis ? pathsOf(analysis) : [];
  return (
    <div className="page">
      <PageHeader eyebrow="Investigate" title="Choose an attack path" />
      {paths.length === 0 ? (
        <div className="card"><Empty title="No attack paths to investigate">The engine found no risky route to a sensitive resource.</Empty></div>
      ) : (
        <div className="grid-2">
          {paths.map((p) => (
            <a key={p.id} href={`#/investigate/${p.id}`} className="card card-link">
              <div className="card-head"><SeverityBadge severity={p.severity} score={p.score} /><span className="mono muted">{p.id}</span></div>
              <h2 className="h3">{p.title}</h2>
              <PathChain finding={p} />
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function Steps({ finding }: { finding: PathFinding }) {
  const { index } = useApp();
  if (!index) return null;
  return (
    <ol className="steps">
      {finding.hops.map((hop, i) => {
        const grant = hop.evidence.grant;
        return (
          <li key={edgeId(hop)} className="step">
            <span className="step-num" aria-hidden>{String(i + 1).padStart(2, "0")}</span>
            <div className="step-body">
              <p className="step-rel">
                <Entity id={hop.source} name={index.name(hop.source)} />
                <span className="step-verb">{RELATION_LABEL[hop.relation].toLowerCase()}</span>
                <Entity id={hop.target} name={index.name(hop.target)} />
                {hop.level && <LevelTag level={hop.level} />}
              </p>
              <p>{hop.detail}</p>
              {grant && (
                <CodeBlock label={`${index.name(grant.policy)} / ${grant.sid}`}
                  value={index.statement(grant.policy, grant.sid) ?? grant} />
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function ScoreBreakdown({ finding }: { finding: PathFinding }) {
  const raw = finding.score_breakdown.reduce((n, b) => n + b.points, 0);
  return (
    <div className="card">
      <div className="card-head"><h2>Why this severity</h2><VerifiedLabel /></div>
      <table className="score">
        <tbody>
          {finding.score_breakdown.map((b) => (
            <tr key={b.factor}><td>{b.label}</td><td className="num">+{b.points}</td></tr>
          ))}
        </tbody>
        <tfoot>
          <tr><th scope="row">Score{raw > 100 ? ` (capped from ${raw})` : ""}</th><td className="num"><SeverityBadge severity={finding.severity} score={finding.score} /></td></tr>
        </tfoot>
      </table>
      <p className="fine">A prioritisation heuristic, not a probability. Thresholds: critical 85+, high 65+, medium 40+.</p>
    </div>
  );
}

function EngineFixes({ finding }: { finding: PathFinding }) {
  const { analysis, queueSimulation } = useApp();
  const fixes = (analysis?.candidates ?? []).filter((c) => c.on_paths.includes(finding.id)).slice(0, 4);
  if (fixes.length === 0) return null;
  return (
    <div className="card">
      <div className="card-head"><h2>Ways to cut this path</h2><VerifiedLabel>Measured by simulator</VerifiedLabel></div>
      <ul className="fixes">
        {fixes.map((c) => {
          const breaksThis = c.preview.broken_paths.includes(finding.id);
          return (
            <li key={c.label}>
              <div>
                <strong>{c.label}</strong>
                <p className="chips">
                  <Chip tone={breaksThis ? "safe" : "risk"}>{breaksThis ? "Breaks this path" : "Does not break this path"}</Chip>
                  <Chip>{c.preview.broken_paths.length} path{c.preview.broken_paths.length === 1 ? "" : "s"} broken</Chip>
                  {c.preview.collateral_access_removed.length > 0 && <Chip>{c.preview.collateral_access_removed.length} other access removed</Chip>}
                  {c.notes.map((n) => <Chip key={n} tone="dark">{n}</Chip>)}
                </p>
              </div>
              <button type="button" className="btn btn-secondary" onClick={() => queueSimulation([c.change])}>
                <FlaskConical size={15} aria-hidden /> Simulate
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function List({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <div className="ai-section">
      <h3>{title}</h3>
      {items.length ? <ul>{items.map((t) => <li key={t}>{t}</li>)}</ul> : <p className="muted">{empty}</p>}
    </div>
  );
}

function AIResult({ result, finding }: { result: Explanation; finding: PathFinding }) {
  const { queueSimulation } = useApp();
  const e = result.explanation;
  return (
    <>
      <p className="ai-meta">
        {result.provider} · <span className="mono">{result.model}</span> · {new Date(result.generated_at * 1000).toLocaleTimeString()}
        {result.cached && " · cached"}
      </p>
      {result.truncated && <Notice tone="warning" title="The reply was cut off">The model hit its length limit; some sections may be incomplete.</Notice>}
      <div className="ai-section"><h3>Summary</h3><p>{e.summary}</p></div>
      {e.impact && <div className="ai-section"><h3>Potential impact</h3><p>{e.impact}</p></div>}
      <List title="Facts it relied on" items={e.facts_used} empty="None listed." />
      <List title="Assumptions (not verified)" items={e.assumptions} empty="None stated." />
      <List title="Uncertainties" items={e.uncertainties} empty="None stated." />
      <div className="ai-section">
        <h3>Suggested least-privilege fixes</h3>
        {e.remediation.length === 0 && <p className="muted">No fixes suggested.</p>}
        <ul className="ai-fixes">
          {e.remediation.map((r) => {
            const v = r.verification;
            return (
              <li key={r.title}>
                <strong>{r.title}</strong>
                {r.rationale && <p>{r.rationale}</p>}
                {r.change && <CodeBlock value={r.change} />}
                <p className="chips">
                  {r.change_rejected && (
                    <Chip tone="risk">Not a valid simulator operation{r.rejection_reason ? ` (${r.rejection_reason})` : ""}: ignored</Chip>
                  )}
                  {!r.change && !r.change_rejected && <Chip>Advice only: cannot be simulated</Chip>}
                  {v && !v.valid && <Chip tone="risk">Rejected by simulator: {v.error}</Chip>}
                  {v?.valid && (
                    <>
                      <Chip tone={v.breaks_this_path ? "safe" : "risk"}>
                        Simulator: {v.breaks_this_path ? "breaks this path" : "does NOT break this path"}
                      </Chip>
                      <Chip>{v.broken_paths?.length ?? 0} broken · {v.new_paths?.length ?? 0} new</Chip>
                    </>
                  )}
                </p>
                {v?.valid && r.change && (
                  <button type="button" className="btn btn-secondary" onClick={() => queueSimulation([r.change!])}>
                    <FlaskConical size={15} aria-hidden /> Open in simulator
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      </div>
      <p className="fine">Generated by {result.provider} from the evidence of {finding.id} only. The model cannot change
        anything; its fix suggestions were tested in the simulator before being shown.</p>
    </>
  );
}

function AIPanel({ finding }: { finding: PathFinding }) {
  const { analysis, explanations, explain } = useApp();
  const state: ExplainState | undefined = explanations[finding.id];
  const ai = analysis?.ai;
  return (
    <section className="card ai-panel" aria-labelledby="ai-title">
      <div className="card-head">
        <h2 id="ai-title">AI explanation</h2>
        <AILabel>{state?.status === "done" ? "AI-generated" : "Meta AI"}</AILabel>
      </div>
      {!state && (
        <>
          <p>Ask Meta AI to explain this verified path in plain language, separate facts from assumptions, and propose
            least-privilege fixes. Only this finding's evidence ({finding.hops.length} steps) is sent.</p>
          {ai && !ai.configured && (
            <Notice tone="info" title="AI explanations are off">{AI_ERROR_HELP.not_configured}</Notice>
          )}
          <button type="button" className="btn btn-primary" disabled={!ai?.configured} onClick={() => explain(finding.id)}>
            <Sparkles size={16} aria-hidden /> Generate explanation
          </button>
          {ai?.configured && <p className="fine">Uses your Meta Model API credits ({ai.model}). Nothing is sent automatically.</p>}
        </>
      )}
      {state?.status === "loading" && <Spinner label="Asking Meta AI… this can take up to 30 seconds" />}
      {state?.status === "error" && (
        <Notice tone="error" title="No explanation was generated" action={
          state.error.code !== "not_configured" && (
            <button type="button" className="btn btn-secondary" onClick={() => explain(finding.id)}>
              <RotateCcw size={15} aria-hidden /> Try again
            </button>
          )}>
          <p>{state.error.message}</p>
          {AI_ERROR_HELP[state.error.code] && <p className="muted">{AI_ERROR_HELP[state.error.code]}</p>}
        </Notice>
      )}
      {state?.status === "done" && <AIResult result={state.result} finding={finding} />}
    </section>
  );
}

export function InvestigatePage({ findingId }: { findingId?: string }) {
  const { analysis, index } = useApp();
  const finding = analysis?.findings.find((f) => f.id === findingId);
  const sub = useMemo(() => {
    if (!analysis || !finding || !isPath(finding)) return null;
    const el = pathElements(finding);
    return {
      nodes: analysis.graph.nodes.filter((n) => el.nodes.has(n.id)),
      edges: analysis.graph.edges.filter((e) => el.edges.has(e.id)),
      el,
    };
  }, [analysis, finding]);

  if (!findingId) return <PathPicker />;
  if (!analysis || !index) return null;
  if (!finding || !isPath(finding) || !sub) {
    return (
      <div className="page">
        <Notice tone="warning" title="Finding not found" action={<a className="btn btn-secondary" href="#/investigate">See all attack paths</a>}>
          {findingId} is not an attack path in the current dataset.
        </Notice>
      </div>
    );
  }
  const target = index.resource(finding.target);
  return (
    <div className="page">
      <PageHeader eyebrow={`Attack path · ${finding.id}`} title={finding.title}>
        <a className="btn btn-ghost" href={`#/graph/${finding.id}`}><Waypoints size={15} aria-hidden /> View in graph</a>
      </PageHeader>
      <div className="meta-row">
        <SeverityBadge severity={finding.severity} score={finding.score} />
        <LevelTag level={finding.level} />
        {target && <span className="muted">{target.type} · {target.sensitivity} sensitivity{target.data_classification ? ` · ${target.data_classification}` : ""}</span>}
      </div>

      <section className="card card-forest graph-card">
        <GraphView nodes={sub.nodes} edges={sub.edges} highlightNodes={sub.el.nodes} highlightEdges={sub.el.edges}
          height={240} compact label={`Attack path: ${finding.path.map((id) => index.name(id)).join(" to ")}`} />
      </section>

      <div className="grid-investigate">
        <div className="stack">
          <section className="card">
            <div className="card-head"><h2>Verified evidence</h2><VerifiedLabel /></div>
            <Steps finding={finding} />
          </section>
          <ScoreBreakdown finding={finding} />
          <EngineFixes finding={finding} />
        </div>
        <div className="stack">
          <AIPanel finding={finding} />
          <FixAgentPanel finding={finding} />
          <div className="card card-quiet">
            <Eyebrow>How to read this page</Eyebrow>
            <p className="small">Panels marked <strong>Verified by engine</strong> come from deterministic analysis of the
              dataset and are reproducible. The <strong>AI explanation</strong> is generated text: useful for context, but
              its claims should be checked against the verified evidence.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
