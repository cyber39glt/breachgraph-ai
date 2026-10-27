import { MousePointerClick } from "lucide-react";
import { useMemo, useState } from "react";
import { GraphLegend, GraphView, type Selection } from "../components/GraphView";
import { Chip, CodeBlock, Entity, Eyebrow, KindIcon, LevelTag, PageHeader, SeverityBadge, VerifiedLabel } from "../components/ui";
import { edgeId, FACTOR_LABEL, KIND_LABEL, pathElements, pathsOf, RELATION_LABEL, type Index } from "../lookup";
import { useApp } from "../state";
import type { AccessEntry, GraphEdge, GraphNode, PathFinding } from "../types";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function PoliciesOf({ ids, index }: { ids: string[]; index: Index }) {
  if (ids.length === 0) return <p className="muted">No policies attached directly.</p>;
  return (
    <>
      {ids.map((pid) => {
        const p = index.policy(pid);
        return p?.statements.map((st) => (
          <CodeBlock key={`${pid}/${st.sid}`} label={`${p.name} / ${st.sid}`} value={st} />
        ));
      })}
    </>
  );
}

function ReachList({ entries, index, side, paths }: {
  entries: AccessEntry[]; index: Index; side: "user" | "resource"; paths: PathFinding[];
}) {
  if (entries.length === 0) return <p className="muted">None.</p>;
  const flagged = new Map(paths.map((p) => [p.key, p]));
  return (
    <ul className="reach">
      {entries.map((a) => {
        const other = side === "user" ? a.resource : a.user;
        const path = flagged.get(a.key);
        return (
          <li key={a.key}>
            <Entity id={other} name={index.name(other)} />
            <LevelTag level={a.level} />
            {a.roles.length > 0 && <span className="muted small">via {a.roles.map((r) => index.name(r)).join(" → ")}</span>}
            {path && <a href={`#/investigate/${path.id}`} className="reach-flag"><SeverityBadge severity={path.severity} /></a>}
          </li>
        );
      })}
    </ul>
  );
}

function NodeInspector({ node, index, access, paths, edges }: {
  node: GraphNode; index: Index; access: AccessEntry[]; paths: PathFinding[]; edges: GraphEdge[];
}) {
  const header = (
    <div className="insp-head">
      <span className={`insp-kind kind-bg-${node.kind}`}><KindIcon kind={node.kind} size={18} /></span>
      <div>
        <Eyebrow>{KIND_LABEL[node.kind]}</Eyebrow>
        <h2>{node.label}</h2>
        <p className="mono muted small">{node.id}</p>
      </div>
    </div>
  );
  if (node.kind === "user") {
    const u = index.user(node.id)!;
    const groups = edges.filter((e) => e.source === node.id && e.relation === "member_of").map((e) => e.target);
    return (
      <>
        {header}
        <dl className="fields">
          {u.title && <Field label="Title">{u.title}</Field>}
          <Field label="MFA">{u.mfa_enabled ? "Enabled" : <Chip tone="risk">Not enabled</Chip>}</Field>
          <Field label="Type">{u.external ? <Chip tone="risk">External / contractor</Chip> : "Employee"}</Field>
          <Field label="Last sign-in">{u.last_login_days === undefined ? "Not recorded" : `${u.last_login_days} days ago`}</Field>
          <Field label="Groups">{groups.map((g) => index.name(g)).join(", ") || "None"}</Field>
        </dl>
        {(node.factors?.length ?? 0) > 0 && (
          <p className="chips">{node.factors!.map((f) => <Chip key={f} tone="risk">{FACTOR_LABEL[f] ?? f}</Chip>)}</p>
        )}
        <h3>Can reach</h3>
        <ReachList entries={access.filter((a) => a.user === node.id)} index={index} side="user" paths={paths} />
        <h3>Directly attached policies</h3>
        <PoliciesOf ids={u.policies} index={index} />
      </>
    );
  }
  if (node.kind === "group") {
    const g = index.group(node.id)!;
    return (
      <>
        {header}
        <dl className="fields"><Field label="Members">{g.members.map((m) => index.name(m)).join(", ") || "None"}</Field></dl>
        <h3>Attached policies</h3>
        <PoliciesOf ids={g.policies} index={index} />
      </>
    );
  }
  if (node.kind === "role") {
    const r = index.role(node.id)!;
    const assumers = edges.filter((e) => e.target === node.id && e.relation === "can_assume").map((e) => e.source);
    return (
      <>
        {header}
        {r.description && <p>{r.description}</p>}
        <dl className="fields">
          <Field label="Trust policy">{r.trusted_principals.map((p) => (p === "account:*" ? "Whole account (account:*)" : index.name(p))).join(", ")}</Field>
          <Field label="Assumable by">{assumers.map((a) => index.name(a)).join(", ") || "Nobody in this dataset"}</Field>
        </dl>
        <h3>Role permissions</h3>
        <PoliciesOf ids={r.policies} index={index} />
      </>
    );
  }
  const res = index.resource(node.id)!;
  return (
    <>
      {header}
      <dl className="fields">
        <Field label="Type">{res.type ?? "Not recorded"}</Field>
        <Field label="Sensitivity"><SeverityBadge severity={res.sensitivity} /></Field>
        {res.data_classification && <Field label="Data">{res.data_classification}</Field>}
      </dl>
      <h3>Who can reach it</h3>
      <ReachList entries={access.filter((a) => a.resource === node.id)} index={index} side="resource" paths={paths} />
    </>
  );
}

function EdgeInspector({ edge, index, paths }: { edge: GraphEdge; index: Index; paths: PathFinding[] }) {
  const using = paths.filter((p) => p.hops.some((h) => edgeId(h) === edge.id));
  return (
    <>
      <div className="insp-head">
        <div>
          <Eyebrow>{RELATION_LABEL[edge.relation]}</Eyebrow>
          <h2 className="edge-title">
            <Entity id={edge.source} name={index.name(edge.source)} />
            <span aria-hidden>→</span>
            <Entity id={edge.target} name={index.name(edge.target)} />
          </h2>
        </div>
      </div>
      <dl className="fields">
        {edge.level && <Field label="Access level"><LevelTag level={edge.level} /></Field>}
        {edge.trust && <Field label="Role trust">{edge.trust === "account:*" ? "Whole account: the caller's own policy decides" : index.name(edge.trust)}</Field>}
      </dl>
      {edge.relation === "member_of" && <p>Group membership: {index.name(edge.source)} receives every permission attached to {index.name(edge.target)}.</p>}
      {edge.grants.length > 0 && <h3>Policy statements behind this edge</h3>}
      {edge.grants.map((g) => (
        <CodeBlock key={`${g.policy}/${g.sid}`} label={`${index.name(g.policy)} / ${g.sid} · grants ${g.action}`}
          value={index.statement(g.policy, g.sid) ?? g} />
      ))}
      <h3>Used by attack paths</h3>
      {using.length ? (
        <ul className="plain">{using.map((p) => (
          <li key={p.id}><a href={`#/investigate/${p.id}`}><SeverityBadge severity={p.severity} score={p.score} /> {p.title}</a></li>
        ))}</ul>
      ) : <p className="muted">None. This edge is not on a flagged path.</p>}
    </>
  );
}

export function ExplorerPage({ focus }: { focus?: string }) {
  const { analysis, index } = useApp();
  const paths = useMemo(() => (analysis ? pathsOf(analysis) : []), [analysis]);
  const [pathId, setPathId] = useState<string>(focus && paths.some((p) => p.id === focus) ? focus : "all");
  const [selected, setSelected] = useState<Selection | null>(null);

  const highlight = useMemo(() => {
    const chosen = pathId === "all" ? paths : paths.filter((p) => p.id === pathId);
    const nodes = new Set<string>();
    const edges = new Set<string>();
    for (const p of chosen) {
      const el = pathElements(p);
      el.nodes.forEach((n) => nodes.add(n));
      el.edges.forEach((e) => edges.add(e));
    }
    return { nodes, edges };
  }, [paths, pathId]);

  if (!analysis || !index) return null;
  const { nodes, edges } = analysis.graph;
  const node = selected?.type === "node" ? nodes.find((n) => n.id === selected.id) : undefined;
  const edge = selected?.type === "edge" ? edges.find((e) => e.id === selected.id) : undefined;

  return (
    <div className="page">
      <PageHeader eyebrow="Attack-path explorer" title="How identities reach sensitive resources">
        <label className="select">
          <span>Highlight</span>
          <select value={pathId} onChange={(e) => setPathId(e.target.value)}>
            <option value="all">All attack paths ({paths.length})</option>
            {paths.map((p) => <option key={p.id} value={p.id}>{p.id} · {p.title}</option>)}
          </select>
        </label>
      </PageHeader>

      <div className="explorer">
        <section className="card card-forest graph-card" aria-label="Identity graph">
          <GraphView nodes={nodes} edges={edges} highlightNodes={highlight.nodes} highlightEdges={highlight.edges}
            dimOthers={pathId !== "all"} selected={selected} onSelect={setSelected} height="min(62vh, 620px)"
            label={`Identity graph with ${nodes.length} entities and ${edges.length} relationships. Use the inspector list to explore it with a keyboard.`} />
          <GraphLegend />
        </section>

        <aside className="card inspector" aria-live="polite">
          <label className="select select-block">
            <span>Inspect</span>
            <select value={selected ? `${selected.type}:${selected.id}` : ""}
              onChange={(e) => {
                const [type, ...rest] = e.target.value.split(":");
                setSelected(e.target.value ? { type: type as "node" | "edge", id: rest.join(":") } : null);
              }}>
              <option value="">Choose an entity or relationship…</option>
              <optgroup label="Entities">
                {nodes.map((n) => <option key={n.id} value={`node:${n.id}`}>{KIND_LABEL[n.kind]}: {n.label}</option>)}
              </optgroup>
              <optgroup label="Relationships">
                {edges.map((e) => <option key={e.id} value={`edge:${e.id}`}>{index.name(e.source)} → {index.name(e.target)}</option>)}
              </optgroup>
            </select>
          </label>
          {node ? <NodeInspector node={node} index={index} access={analysis.access} paths={paths} edges={edges} />
            : edge ? <EdgeInspector edge={edge} index={index} paths={paths} />
            : (
              <div className="insp-empty">
                <MousePointerClick size={22} aria-hidden />
                <p><strong>Select a node or edge</strong> to see the evidence behind it: attributes, trust policies and the
                  exact policy statements.</p>
                <VerifiedLabel>Every edge is computed by the engine</VerifiedLabel>
              </div>
            )}
        </aside>
      </div>
    </div>
  );
}
