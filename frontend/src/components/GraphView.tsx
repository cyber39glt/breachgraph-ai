import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import dagre from "cytoscape-dagre";
import { Maximize2, Minus, Plus } from "lucide-react";
import { useEffect, useRef } from "react";
import type { GraphEdge, GraphNode } from "../types";

cytoscape.use(dagre);

export interface Selection {
  type: "node" | "edge";
  id: string;
}

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlightNodes?: Set<string>;
  highlightEdges?: Set<string>;
  /** Edges that a simulated fix removes (shown as a dashed "cut"). */
  cutEdges?: Set<string>;
  dimOthers?: boolean;
  selected?: Selection | null;
  onSelect?: (s: Selection | null) => void;
  height?: number | string;
  label: string;
  compact?: boolean;
}

/** Colours are read from tokens.css so the graph always matches the design system. */
function token(name: string, fallback: string) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function styles(compact: boolean): cytoscape.StylesheetJson {
  const t = {
    onDark: token("--on-dark", "#f6fbf9"),
    mist: token("--on-dark-muted", "#c5d8d2"),
    subtle: token("--on-dark-subtle", "#9fb8b0"),
    chip: token("--glt-forest-chip", "#235141"),
    forest: token("--glt-forest", "#0b3d2e"),
    raised: token("--glt-forest-raised", "#0f4636"),
    lime: token("--glt-lime", "#b7ff3d"),
    path: token("--graph-path", "#ff7a6b"),
    critical: token("--graph-critical", "#ff7a6b"),
    high: token("--graph-high", "#ffb067"),
    medium: token("--graph-medium", "#f2d16b"),
    low: token("--graph-low", "#c5d8d2"),
  };
  const size = compact ? 26 : 32;
  return [
    {
      selector: "node",
      style: {
        width: size, height: size, label: "data(label)", color: t.onDark,
        "font-family": "Inter, system-ui, sans-serif", "font-size": compact ? 10 : 11, "font-weight": 500,
        "text-valign": "bottom", "text-margin-y": 6, "text-wrap": "wrap", "text-max-width": "110px",
        "border-width": 1.5, "border-color": t.subtle, "background-color": t.raised,
        "transition-property": "opacity, border-color, border-width", "transition-duration": 150,
      },
    },
    { selector: "node[kind = 'user']", style: { shape: "ellipse", "background-color": t.mist, "border-color": t.mist } },
    { selector: "node[?risky]", style: { "border-color": t.path, "border-width": 2.5 } },
    { selector: "node[kind = 'group']", style: { shape: "round-rectangle", "background-color": t.chip } },
    { selector: "node[kind = 'role']", style: { shape: "round-hexagon", "background-color": t.forest,
      "border-color": t.lime, "border-width": 2 } },
    { selector: "node[kind = 'resource']", style: { shape: "barrel", "border-width": 0 } },
    { selector: "node[sensitivity = 'critical']", style: { "background-color": t.critical } },
    { selector: "node[sensitivity = 'high']", style: { "background-color": t.high } },
    { selector: "node[sensitivity = 'medium']", style: { "background-color": t.medium } },
    { selector: "node[sensitivity = 'low']", style: { "background-color": t.low } },
    {
      selector: "edge",
      style: {
        width: 1.5, "line-color": t.subtle, "target-arrow-color": t.subtle, "target-arrow-shape": "triangle",
        "arrow-scale": 0.8, "curve-style": "bezier", opacity: 0.75,
        "font-family": "JetBrains Mono, monospace", "font-size": 9, color: t.mist,
        "text-background-color": t.forest, "text-background-opacity": 1, "text-background-padding": "2px",
        "text-rotation": "autorotate",
      },
    },
    { selector: "edge[relation = 'member_of']", style: { "line-style": "dotted", "target-arrow-shape": "none" } },
    { selector: "edge[relation = 'can_assume']", style: { width: 2 } },
    { selector: ".dim", style: { opacity: 0.25 } },
    { selector: "edge.hl", style: { "line-color": t.path, "target-arrow-color": t.path, width: 3.5, opacity: 1,
      label: "data(caption)", "z-index": 10 } },
    { selector: "node.hl", style: { "border-color": t.path, "border-width": 3 } },
    { selector: "edge.cut", style: { "line-color": t.lime, "target-arrow-color": t.lime, "line-style": "dashed",
      width: 3.5, opacity: 1, label: "cut by fix", color: t.lime, "z-index": 11 } },
    { selector: ":selected, .sel", style: { "overlay-color": t.lime, "overlay-opacity": 0.22, "overlay-padding": 6 } },
  ];
}

/** Fit the graph, but never zoom in past 1.1x: small graphs otherwise get huge labels. */
function fit(cy: Core) {
  cy.fit(undefined, 24);
  if (cy.zoom() > 1.1) {
    cy.zoom(1.1);
    cy.center();
  }
}

function caption(e: GraphEdge) {
  if (e.relation === "member_of") return "member of";
  const action = e.grants[0]?.action ?? (e.relation === "can_assume" ? "sts:AssumeRole" : "");
  return e.relation === "access" && e.level ? `${action} · ${e.level}` : action;
}

export function GraphView({
  nodes, edges, highlightNodes, highlightEdges, cutEdges, dimOthers = false, selected, onSelect,
  height = 520, label, compact = false,
}: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  // Build the graph when its contents change.
  useEffect(() => {
    if (!ref.current) return;
    const elements: ElementDefinition[] = [
      ...nodes.map((n) => ({ data: { ...n, risky: (n.factors?.length ?? 0) > 0 } })),
      ...edges.map((e) => ({ data: { ...e, caption: caption(e) } })),
    ];
    const cy = cytoscape({
      container: ref.current,
      elements,
      style: styles(compact),
      layout: { name: "dagre", rankDir: "LR", nodeSep: compact ? 22 : 34, rankSep: compact ? (nodes.length <= 8 ? 150 : 70) : 110,
        padding: 24, animate: false } as cytoscape.LayoutOptions,
      minZoom: 0.3, maxZoom: 2.5, wheelSensitivity: 0.25, boxSelectionEnabled: false,
      autoungrabify: false,
    });
    cy.on("tap", "node, edge", (evt) => {
      const el = evt.target;
      onSelectRef.current?.({ type: el.isNode() ? "node" : "edge", id: el.id() });
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) onSelectRef.current?.(null);
    });
    fit(cy);
    cyRef.current = cy;
    const resize = new ResizeObserver(() => {
      cy.resize();
      fit(cy);
    });
    resize.observe(ref.current);
    return () => {
      resize.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
  }, [nodes, edges, compact]);

  // Highlighting and selection change without rebuilding the layout.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("hl dim cut sel");
      const anyHl = (highlightNodes?.size ?? 0) + (highlightEdges?.size ?? 0) > 0;
      cy.nodes().forEach((n) => {
        if (highlightNodes?.has(n.id())) n.addClass("hl");
        else if (dimOthers && anyHl) n.addClass("dim");
      });
      cy.edges().forEach((e) => {
        if (cutEdges?.has(e.id())) e.addClass("cut");
        else if (highlightEdges?.has(e.id())) e.addClass("hl");
        else if (dimOthers && anyHl) e.addClass("dim");
      });
      if (selected) cy.getElementById(selected.id).addClass("sel");
    });
  }, [highlightNodes, highlightEdges, cutEdges, dimOthers, selected, nodes, edges]);

  const zoom = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  return (
    <div className="graph" style={{ height }}>
      <div ref={ref} className="graph-canvas" role="img" aria-label={label} />
      <div className="graph-controls" aria-label="Graph controls">
        <button type="button" onClick={() => zoom(1.25)} aria-label="Zoom in"><Plus size={16} /></button>
        <button type="button" onClick={() => zoom(0.8)} aria-label="Zoom out"><Minus size={16} /></button>
        <button type="button" onClick={() => cyRef.current && fit(cyRef.current)} aria-label="Fit graph to view">
          <Maximize2 size={15} />
        </button>
      </div>
    </div>
  );
}

export function GraphLegend() {
  return (
    <ul className="legend" aria-label="Graph legend">
      <li><span className="lg lg-user" />Identity</li>
      <li><span className="lg lg-risky" />Risky identity</li>
      <li><span className="lg lg-group" />Group</li>
      <li><span className="lg lg-role" />Role</li>
      <li><span className="lg lg-res-critical" />Critical resource</li>
      <li><span className="lg lg-res-high" />High</li>
      <li><span className="lg lg-res-medium" />Medium</li>
      <li><span className="lg lg-res-low" />Low</li>
      <li><span className="lg lg-path" />Attack path</li>
    </ul>
  );
}
