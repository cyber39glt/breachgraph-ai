import { Database, FlaskConical, LayoutDashboard, RefreshCw, ScanSearch, Waypoints } from "lucide-react";
import { Notice, Skeleton } from "./components/ui";
import { DatasetPage } from "./pages/DatasetPage";
import { ExplorerPage } from "./pages/ExplorerPage";
import { InvestigatePage } from "./pages/InvestigatePage";
import { OverviewPage } from "./pages/OverviewPage";
import { SimulatePage } from "./pages/SimulatePage";
import { AppProvider, useApp, useRoute, type Page } from "./state";

const NAV: Array<{ page: Page; label: string; icon: typeof Database }> = [
  { page: "overview", label: "Overview", icon: LayoutDashboard },
  { page: "graph", label: "Attack graph", icon: Waypoints },
  { page: "investigate", label: "Investigate", icon: ScanSearch },
  { page: "simulate", label: "Simulate fix", icon: FlaskConical },
  { page: "dataset", label: "Dataset", icon: Database },
];

function BrandMark() {
  return (
    <a className="brand" href="#/overview" aria-label="BreachGraph AI home">
      <span className="brand-square" aria-hidden />
      <span className="brand-text">
        <span className="brand-name">BreachGraph<span className="brand-ai"> AI</span></span>
        <span className="brand-by">by GreenLan<span>Tech</span></span>
      </span>
    </a>
  );
}

function Sidebar({ page }: { page: Page }) {
  return (
    <aside className="sidebar">
      <BrandMark />
      <nav aria-label="Main">
        <ul>
          {NAV.map(({ page: p, label, icon: Icon }) => (
            <li key={p}>
              <a href={`#/${p}`} className={page === p ? "active" : undefined} aria-current={page === p ? "page" : undefined}>
                <Icon size={18} aria-hidden />
                <span>{label}</span>
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <div className="sidebar-foot">
        <p className="eyebrow eyebrow-lime">Read-only</p>
        <p>Synthetic data. Simulations never change real permissions.</p>
      </div>
    </aside>
  );
}

function TopBar() {
  const { analysis, uploaded, loadDemo, loading } = useApp();
  const ai = analysis?.ai;
  return (
    <div className="topbar">
      <div className="topbar-dataset">
        <span className="eyebrow">Dataset</span>
        <strong>{analysis?.dataset.name ?? "Loading…"}</strong>
        {analysis?.dataset.synthetic && <span className="chip chip-dark">Synthetic</span>}
        {uploaded && <span className="chip chip-neutral">Uploaded</span>}
      </div>
      <div className="topbar-actions">
        {ai && (
          <span className={`ai-pill ${ai.configured ? "on" : "off"}`}
            title={ai.configured ? `Key configured for ${ai.model}` : "MODEL_API_KEY is not set on the server"}>
            <span className="ai-dot" aria-hidden />
            Meta AI · {ai.configured ? ai.model : "off"}
          </span>
        )}
        {uploaded && (
          <button type="button" className="btn btn-ghost" onClick={loadDemo} disabled={loading}>
            <RefreshCw size={15} aria-hidden /> Load demo
          </button>
        )}
      </div>
    </div>
  );
}

function Content({ page, param }: { page: Page; param?: string }) {
  const { analysis, error, reload, loading } = useApp();
  if (error && !analysis) {
    return (
      <div className="page">
        <Notice tone="error" title="Could not load the analysis" action={
          <button type="button" className="btn btn-primary" onClick={reload} disabled={loading}>Try again</button>
        }>
          {error.message}
        </Notice>
      </div>
    );
  }
  if (!analysis) {
    return (
      <div className="page" aria-busy="true">
        <div className="sr-only" role="status">Running the risk engine…</div>
        <Skeleton lines={2} />
        <div className="grid-4">{[0, 1, 2, 3].map((i) => <div key={i} className="card"><Skeleton lines={2} /></div>)}</div>
        <div className="card"><Skeleton lines={5} /></div>
      </div>
    );
  }
  switch (page) {
    case "graph": return <ExplorerPage focus={param} />;
    case "investigate": return <InvestigatePage findingId={param} />;
    case "simulate": return <SimulatePage />;
    case "dataset": return <DatasetPage />;
    default: return <OverviewPage />;
  }
}

function Shell() {
  const { page, param } = useRoute();
  return (
    <div className="shell">
      <a className="skip-link" href="#main">Skip to content</a>
      <Sidebar page={page} />
      <div className="main-col">
        <TopBar />
        <main id="main" tabIndex={-1}>
          <Content page={page} param={param} />
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}
