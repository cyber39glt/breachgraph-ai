import { ArrowRight, ChevronDown, ChevronRight, FlaskConical, ScanSearch } from "lucide-react";
import { Fragment, useState } from "react";
import { CodeBlock, Empty, Entity, Eyebrow, Notice, PageHeader, SeverityBadge, VerifiedLabel } from "../components/ui";
import { isPath, isStatement } from "../lookup";
import { navigate, useApp } from "../state";
import type { Finding, PathFinding, Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const TYPE_LABEL: Record<Finding["type"], string> = {
  attack_path: "Attack path",
  wildcard_permission: "Wildcard permission",
  unused_permission: "Unused permission",
};

function Metric({ label, value, sub, tone }: { label: string; value: number | string; sub: string; tone?: "risk" }) {
  return (
    <div className={`card metric ${tone === "risk" ? "metric-risk" : ""}`}>
      <span className="metric-label">{label}</span>
      <span className="metric-value">{value}</span>
      <span className="metric-sub">{sub}</span>
    </div>
  );
}

export function PathChain({ finding, dark = false }: { finding: PathFinding; dark?: boolean }) {
  const { index } = useApp();
  return (
    <ol className={`chain ${dark ? "chain-dark" : ""}`} aria-label="Attack path">
      {finding.path.map((id, i) => (
        <Fragment key={id}>
          {i > 0 && <li className="chain-arrow" aria-hidden><ArrowRight size={14} /></li>}
          <li className="chain-node"><Entity id={id} name={index?.name(id) ?? id} /></li>
        </Fragment>
      ))}
    </ol>
  );
}

function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  return (
    <div className="card">
      <div className="card-head">
        <h2>Findings by severity</h2>
        <span className="muted">{total} total</span>
      </div>
      {total > 0 && (
        <div className="sevbar" role="img"
          aria-label={SEVERITIES.map((s) => `${counts[s]} ${s}`).join(", ")}>
          {SEVERITIES.filter((s) => counts[s] > 0).map((s) => (
            <span key={s} className={`sevbar-seg sevbar-${s}`} style={{ flexGrow: counts[s] }} />
          ))}
        </div>
      )}
      <ul className="sevbar-legend">
        {SEVERITIES.map((s) => (
          <li key={s}><span className={`sev-dot sev-dot-${s}`} aria-hidden /> <span className="cap">{s}</span>
            <strong>{counts[s]}</strong></li>
        ))}
      </ul>
      <p className="fine">Severity comes from a transparent score: resource sensitivity, access level, identity
        risk factors and role escalation. Open a finding to see its breakdown.</p>
    </div>
  );
}

function FindingsTable({ findings }: { findings: Finding[] }) {
  const { index } = useApp();
  const [open, setOpen] = useState<string | null>(null);
  if (findings.length === 0) {
    return <Empty title="No findings">The engine found no attack paths or risky statements in this dataset.</Empty>;
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr><th scope="col">Severity</th><th scope="col">Finding</th><th scope="col" className="hide-sm">Type</th>
            <th scope="col" className="hide-sm">ID</th><th scope="col"><span className="sr-only">Open</span></th></tr>
        </thead>
        <tbody>
          {findings.map((f) => {
            const expanded = open === f.id;
            const onOpen = () => (isPath(f) ? navigate("investigate", f.id) : setOpen(expanded ? null : f.id));
            return (
              <Fragment key={f.id}>
                <tr className="row-click" onClick={onOpen}>
                  <td><SeverityBadge severity={f.severity} score={f.score} /></td>
                  <td className="cell-title">{f.title}</td>
                  <td className="hide-sm muted">{TYPE_LABEL[f.type]}</td>
                  <td className="hide-sm mono muted">{f.id}</td>
                  <td className="cell-action">
                    <button type="button" className="icon-btn" onClick={(e) => { e.stopPropagation(); onOpen(); }}
                      aria-expanded={isPath(f) ? undefined : expanded}
                      aria-label={isPath(f) ? `Investigate ${f.title}` : `${expanded ? "Hide" : "Show"} evidence for ${f.title}`}>
                      {isPath(f) ? <ChevronRight size={16} /> : <ChevronDown size={16} className={expanded ? "rot" : ""} />}
                    </button>
                  </td>
                </tr>
                {expanded && isStatement(f) && (
                  <tr className="row-detail">
                    <td colSpan={5}>
                      <div className="detail-grid">
                        <div>
                          <VerifiedLabel />
                          <p>{f.facts[0]}</p>
                          <p className="muted">Attached to: {f.holders.map((h) => index?.name(h) ?? h).join(", ") || "nothing"}</p>
                          {f.related_findings.length > 0 ? (
                            <p>Enables {f.related_findings.length} attack path{f.related_findings.length > 1 ? "s" : ""}:{" "}
                              {f.related_findings.map((id, i) => (
                                <Fragment key={id}>{i > 0 && ", "}<a href={`#/investigate/${id}`} className="mono">{id}</a></Fragment>
                              ))}
                            </p>
                          ) : <p className="muted">Not part of any attack path found in this dataset.</p>}
                        </div>
                        <CodeBlock label={`${index?.name(f.policy) ?? f.policy} / ${f.sid}`} value={f.statement} />
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function OverviewPage() {
  const { analysis, dataset } = useApp();
  if (!analysis || !dataset) return null;
  const s = analysis.summary;
  const top = analysis.findings.find(isPath);
  return (
    <div className="page">
      <PageHeader eyebrow="Identity attack surface" title="Who can reach your most sensitive data" />
      {analysis.truncated && (
        <Notice tone="info" title="Large account: showing the highest-risk results">
          All {analysis.truncated.attack_paths_total.toLocaleString()} attack paths were analysed; the{" "}
          {analysis.truncated.attack_paths_shown} highest-risk are listed here. Totals and simulations use every path.
        </Notice>
      )}

      <section className="grid-4" aria-label="Key metrics">
        <Metric label="Identities analysed" value={s.identities} sub={`${dataset.groups.length} groups · ${s.roles} roles`} />
        <Metric label="Attack paths" value={s.attack_paths} sub="to high or critical resources" tone={s.attack_paths ? "risk" : undefined} />
        <Metric label="Critical findings" value={s.findings_by_severity.critical}
          sub={`${analysis.findings.length} findings in total`} tone={s.findings_by_severity.critical ? "risk" : undefined} />
        <Metric label="Sensitive resources" value={`${s.sensitive_resources}`} sub={`high or critical, of ${s.resources}`} />
      </section>

      <section className="grid-hero">
        {top ? (
          <div className="card card-forest hero">
            <Eyebrow tone="lime">Highest-risk path</Eyebrow>
            <h2>{top.title}</h2>
            <div className="hero-meta">
              <SeverityBadge severity={top.severity} score={top.score} />
              <span>{top.roles.length} role hop{top.roles.length === 1 ? "" : "s"} · {top.hops.length} verified steps</span>
            </div>
            <PathChain finding={top} dark />
            <div className="hero-actions">
              <a className="btn btn-primary" href={`#/investigate/${top.id}`}><ScanSearch size={16} aria-hidden /> Investigate</a>
              <a className="btn btn-outline-dark" href="#/simulate"><FlaskConical size={16} aria-hidden /> Simulate a fix</a>
            </div>
          </div>
        ) : (
          <div className="card"><Empty title="No attack paths">No identity can reach a high or critical resource through a risky route.</Empty></div>
        )}
        <SeverityBar counts={s.findings_by_severity} />
      </section>

      <section className="card">
        <div className="card-head">
          <h2>All findings</h2>
          <VerifiedLabel>Deterministic engine</VerifiedLabel>
        </div>
        <FindingsTable findings={analysis.findings} />
      </section>
    </div>
  );
}
