import { ArrowRight, Check, FlaskConical, RotateCcw, ShieldAlert, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api";
import { GraphView } from "../components/GraphView";
import { Chip, CodeBlock, Empty, Entity, Eyebrow, LevelTag, Notice, PageHeader, SeverityBadge, Spinner, VerifiedLabel } from "../components/ui";
import { pathElements, pathsOf } from "../lookup";
import { useApp } from "../state";
import type { Analysis, Candidate, Change, PathFinding, SimulationResult } from "../types";

const keyOf = (c: Change) => JSON.stringify(c, Object.keys(c).sort());

type Option = Candidate & { fromAI?: boolean };

function Delta({ label, before, after, lowerIsBetter = true }: { label: string; before: number; after: number; lowerIsBetter?: boolean }) {
  const better = lowerIsBetter ? after < before : after > before;
  const worse = lowerIsBetter ? after > before : after < before;
  return (
    <div className={`card delta ${better ? "delta-better" : worse ? "delta-worse" : ""}`}>
      <span className="metric-label">{label}</span>
      <span className="delta-values">
        <span className="delta-before">{before}</span>
        <ArrowRight size={18} aria-hidden />
        <span className="delta-after">{after}</span>
      </span>
      <span className="sr-only">{label} goes from {before} to {after}</span>
    </div>
  );
}

function highlightOf(analysis: Analysis) {
  const nodes = new Set<string>();
  const edges = new Set<string>();
  for (const p of pathsOf(analysis)) {
    const el = pathElements(p);
    el.nodes.forEach((n) => nodes.add(n));
    el.edges.forEach((e) => edges.add(e));
  }
  return { nodes, edges };
}

function PathList({ title, paths, tone, empty }: { title: string; paths: PathFinding[]; tone: "safe" | "risk" | "new"; empty: string }) {
  const { index } = useApp();
  return (
    <section className={`card pathlist pathlist-${tone}`}>
      <div className="card-head">
        <h2>{title}</h2>
        <span className="count">{paths.length}</span>
      </div>
      {paths.length === 0 ? <p className="muted">{empty}</p> : (
        <ul>
          {paths.map((p) => (
            <li key={p.key}>
              {tone === "safe" ? <Check size={16} aria-hidden className="ic-safe" /> : <ShieldAlert size={16} aria-hidden className="ic-risk" />}
              <div>
                <span className="pathlist-title">{p.title}</span>
                <span className="muted small">{p.path.map((id) => index?.name(id) ?? id).join(" → ")}</span>
              </div>
              <SeverityBadge severity={p.severity} score={p.score} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Results({ result }: { result: SimulationResult }) {
  const { index } = useApp();
  const d = result.diff;
  const before = result.before.summary;
  const after = result.after.summary;
  const graphs = useMemo(() => {
    const afterIds = new Set(result.after.graph.edges.map((e) => e.id));
    const cut = new Set(result.before.graph.edges.filter((e) => !afterIds.has(e.id)).map((e) => e.id));
    return { before: highlightOf(result.before), after: highlightOf(result.after), cut };
  }, [result]);

  return (
    <div className="stack" aria-live="polite">
      {d.new_paths.length > 0 ? (
        <Notice tone="error" title={`This change opens ${d.new_paths.length} new attack path${d.new_paths.length > 1 ? "s" : ""}`}>
          The recomputed graph contains paths that did not exist before. Do not apply this change as is.
        </Notice>
      ) : d.broken_paths.length > 0 ? (
        <Notice tone="success" title={`${d.broken_paths.length} attack path${d.broken_paths.length > 1 ? "s" : ""} confirmed broken`}>
          Confirmed by re-running the engine on the changed dataset: these paths no longer exist. {d.remaining_paths.length > 0
            ? `${d.remaining_paths.length} other path${d.remaining_paths.length > 1 ? "s" : ""} remain open.` : "No attack paths remain."}
        </Notice>
      ) : (
        <Notice tone="warning" title="No attack path was broken">
          The recomputed graph still contains every path. Try a different change.
        </Notice>
      )}

      <div className="grid-4">
        <Delta label="Attack paths" before={before.attack_paths} after={after.attack_paths} />
        <Delta label="Path risk (sum of scores)" before={d.risk_before} after={d.risk_after} />
        <Delta label="Critical findings" before={before.findings_by_severity.critical} after={after.findings_by_severity.critical} />
        <Delta label="Access entries" before={result.before.access.length} after={result.after.access.length} />
      </div>

      <div className="grid-2">
        <section className="card card-forest graph-card">
          <Eyebrow tone="lime">Before</Eyebrow>
          <GraphView nodes={result.before.graph.nodes} edges={result.before.graph.edges} highlightNodes={graphs.before.nodes}
            highlightEdges={graphs.before.edges} cutEdges={graphs.cut} height={340} compact
            label={`Before the change: ${before.attack_paths} attack paths. ${graphs.cut.size} relationships are removed by the change.`} />
        </section>
        <section className="card card-forest graph-card">
          <Eyebrow tone="lime">After (recomputed)</Eyebrow>
          <GraphView nodes={result.after.graph.nodes} edges={result.after.graph.edges} highlightNodes={graphs.after.nodes}
            highlightEdges={graphs.after.edges} height={340} compact
            label={`After the change: ${after.attack_paths} attack paths remain.`} />
        </section>
      </div>

      <div className="stack">
        <PathList title="Broken" paths={d.broken_paths} tone="safe" empty="No path was broken." />
        <PathList title="Still open" paths={d.remaining_paths} tone="risk" empty="No attack paths remain." />
        <PathList title="New" paths={d.new_paths} tone="new" empty="No new paths appeared." />
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Other access this change removes</h2>
          <span className="count">{d.collateral_access_removed.length}</span>
        </div>
        <p className="small muted">Access that was not part of a flagged attack path. Check that nobody needs it for legitimate work
          before applying the change.</p>
        {d.collateral_access_removed.length === 0 ? <p>None. Only access on attack paths is affected.</p> : (
          <ul className="reach">
            {d.collateral_access_removed.map((a) => (
              <li key={a.key}>
                <Entity id={a.user} name={index?.name(a.user) ?? a.user} />
                <ArrowRight size={14} aria-hidden />
                <Entity id={a.resource} name={index?.name(a.resource) ?? a.resource} />
                <LevelTag level={a.level} />
                {a.roles.length > 0 && <span className="muted small">via {a.roles.map((r) => index?.name(r) ?? r).join(" → ")}</span>}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

export function SimulatePage() {
  const { analysis, uploaded, queued, clearQueue } = useApp();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [aiOptions, setAiOptions] = useState<Option[]>([]);
  const [state, setState] = useState<{ status: "idle" } | { status: "loading" } | { status: "error"; error: ApiError }
    | { status: "done"; result: SimulationResult }>({ status: "idle" });

  const options: Option[] = useMemo(() => {
    const known = new Set((analysis?.candidates ?? []).map((c) => keyOf(c.change)));
    return [...aiOptions.filter((o) => !known.has(keyOf(o.change))), ...(analysis?.candidates ?? [])];
  }, [analysis, aiOptions]);

  const run = async (keys: Set<string>) => {
    const changes = options.filter((o) => keys.has(keyOf(o.change))).map((o) => o.change);
    if (changes.length === 0) return;
    setState({ status: "loading" });
    try {
      setState({ status: "done", result: await api.simulate(uploaded, changes) });
    } catch (e) {
      setState({ status: "error", error: e instanceof ApiError ? e : new ApiError("unknown", String(e), 0) });
    }
  };

  // A change sent here from the investigation page is selected and simulated straight away.
  useEffect(() => {
    if (!queued || !analysis) return;
    const keys = new Set(queued.map(keyOf));
    const known = new Set(analysis.candidates.map((c) => keyOf(c.change)));
    setAiOptions(queued.filter((c) => !known.has(keyOf(c))).map((change) => ({
      change, label: describe(change), notes: [], on_paths: [], fromAI: true, preview: null,
    })));
    setSelected(keys);
    clearQueue();
    setState({ status: "loading" });
    api.simulate(uploaded, queued)
      .then((result) => setState({ status: "done", result }))
      .catch((e) => setState({ status: "error", error: e instanceof ApiError ? e : new ApiError("unknown", String(e), 0) }));
  }, [queued, analysis, uploaded, clearQueue]);

  if (!analysis) return null;
  const toggle = (k: string) => {
    const next = new Set(selected);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    setSelected(next);
  };

  return (
    <div className="page">
      <PageHeader eyebrow="Remediation simulator" title="Test a fix before you make it" />
      <Notice tone="info" title="Simulation only">
        Changes are applied to a copy of the dataset and the whole analysis is re-run. No real cloud permissions are changed.
      </Notice>

      <div className="grid-sim">
        <section className="card candidates">
          <div className="card-head">
            <h2>Candidate changes</h2>
            <VerifiedLabel>{options.some((o) => o.preview && !o.fromAI) ? "Ranked by measured effect" : "Ranked by paths covered"}</VerifiedLabel>
          </div>
          {options.length === 0 ? (
            <Empty title="Nothing to fix">There are no attack paths, so there is nothing to cut.</Empty>
          ) : (
            <ul>
              {options.map((o) => {
                const k = keyOf(o.change);
                const id = `cand-${k.replace(/[^a-z0-9]/gi, "")}`;
                return (
                  <li key={k} className={selected.has(k) ? "on" : undefined}>
                    <input type="checkbox" id={id} checked={selected.has(k)} onChange={() => toggle(k)} />
                    <label htmlFor={id}>
                      <strong>{o.label}</strong>
                      <span className="chips">
                        {o.fromAI ? <Chip tone="dark"><Sparkles size={12} aria-hidden /> Suggested by AI · not pre-measured</Chip>
                        : !o.preview ? (
                          <>
                            <Chip>On {o.on_paths.length} attack path{o.on_paths.length === 1 ? "" : "s"} · run to measure</Chip>
                            {o.notes.map((n) => <Chip key={n} tone="dark">{n}</Chip>)}
                          </>
                        ) : (
                          <>
                            <Chip tone={o.preview.broken_paths.length ? "safe" : "neutral"}>
                              Breaks {o.preview.broken_paths.length} path{o.preview.broken_paths.length === 1 ? "" : "s"}
                            </Chip>
                            {o.preview.new_paths.length > 0 && <Chip tone="risk">{o.preview.new_paths.length} new</Chip>}
                            {o.preview.collateral_access_removed.length > 0 && (
                              <Chip>{o.preview.collateral_access_removed.length} other access removed</Chip>
                            )}
                            {o.notes.map((n) => <Chip key={n} tone="dark">{n}</Chip>)}
                          </>
                        )}
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>
          )}
          <div className="candidates-actions">
            <button type="button" className="btn btn-primary" disabled={selected.size === 0 || state.status === "loading"}
              onClick={() => run(selected)}>
              <FlaskConical size={16} aria-hidden /> Run simulation{selected.size > 1 ? ` (${selected.size} changes)` : ""}
            </button>
            <button type="button" className="btn btn-ghost" disabled={selected.size === 0 && state.status === "idle"}
              onClick={() => { setSelected(new Set()); setState({ status: "idle" }); }}>
              <RotateCcw size={15} aria-hidden /> Reset
            </button>
          </div>
          {selected.size > 0 && (
            <details className="changes-json">
              <summary>Changes being simulated</summary>
              <CodeBlock value={options.filter((o) => selected.has(keyOf(o.change))).map((o) => o.change)} />
            </details>
          )}
        </section>

        <div className="sim-results">
          {state.status === "idle" && (
            <div className="card sim-idle">
              <FlaskConical size={28} aria-hidden />
              <p><strong>Select one or more changes and run the simulation.</strong></p>
              <p className="muted">Each candidate's numbers come from simulating it on its own. Combined changes are measured
                when you run them.</p>
            </div>
          )}
          {state.status === "loading" && <div className="card"><Spinner label="Re-running the engine on the changed dataset…" /></div>}
          {state.status === "error" && (
            <Notice tone="error" title="Simulation failed" action={
              <button type="button" className="btn btn-secondary" onClick={() => run(selected)}><RotateCcw size={15} aria-hidden /> Try again</button>
            }>{state.error.message}</Notice>
          )}
          {state.status === "done" && <Results result={state.result} />}
        </div>
      </div>
    </div>
  );
}

function describe(c: Change): string {
  switch (c.op) {
    case "remove_statement": return `Remove statement ${c.sid} from ${String(c.policy).replace("policy:", "")}`;
    case "remove_group_member": return `Remove ${String(c.user).replace("user:", "")} from ${String(c.group).replace("group:", "")}`;
    case "set_statement_resources": return `Limit ${c.sid} to ${(c.resources as string[]).join(", ") || "no resources"}`;
    case "set_statement_actions": return `Limit ${c.sid} actions to ${(c.actions as string[]).join(", ") || "none"}`;
    case "detach_policy": return `Detach ${String(c.policy).replace("policy:", "")} from ${c.principal}`;
    case "set_role_trust": return `Set ${String(c.role).replace("role:", "")} trust to ${(c.trusted_principals as string[]).join(", ")}`;
    default: return c.op;
  }
}

