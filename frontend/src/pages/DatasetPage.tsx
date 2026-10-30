import { Download, FileJson, RefreshCw, Upload } from "lucide-react";
import { useRef, useState } from "react";
import { ApiError } from "../api";
import { AwsImportCard } from "../components/AwsImportCard";
import { CodeBlock, Eyebrow, Notice, PageHeader, Spinner } from "../components/ui";
import { useApp } from "../state";
import type { Dataset } from "../types";

const MAX_UPLOAD_BYTES = 900_000;

export function DatasetPage() {
  const { dataset, uploaded, loadDemo, loadUpload, loading, analysis, setImportReport } = useApp();
  const input = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<{ tone: "error" | "success"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setStatus(null);
    if (file.size > MAX_UPLOAD_BYTES) {
      setStatus({ tone: "error", text: "That file is larger than 900 KB. Use a smaller dataset." });
      return;
    }
    setBusy(true);
    try {
      let parsed: unknown;
      try {
        parsed = JSON.parse(await file.text());
      } catch {
        throw new ApiError("invalid_json", "The file is not valid JSON.", 0);
      }
      await loadUpload(parsed as Dataset);
      setImportReport(null);
      setStatus({ tone: "success", text: `Loaded ${file.name}. All pages now show its analysis.` });
    } catch (e) {
      setStatus({ tone: "error", text: e instanceof ApiError ? e.message : String(e) });
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  };

  const download = () => {
    if (!dataset) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(dataset, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = uploaded ? "breachgraph-dataset.json" : "breachgraph-demo-dataset.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!dataset || !analysis) return null;
  const counts: Array<[string, number]> = [
    ["Users", dataset.users.length], ["Groups", dataset.groups.length], ["Roles", dataset.roles.length],
    ["Policies", dataset.policies.length],
    ["Statements", dataset.policies.reduce((n, p) => n + p.statements.length, 0)],
    ["Resources", dataset.resources.length],
  ];

  return (
    <div className="page">
      <PageHeader eyebrow="Dataset" title={analysis.dataset.name ?? "Uploaded dataset"} />

      <div className="grid-2">
        <section className="card card-forest">
          <Eyebrow tone="lime">{uploaded ? "Uploaded dataset" : "Demo mode"}</Eyebrow>
          <p className="on-dark">{analysis.dataset.description ?? "No description provided."}</p>
          <dl className="counts">
            {counts.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}
          </dl>
          <div className="hero-actions">
            <button type="button" className="btn btn-primary" onClick={loadDemo} disabled={loading || busy}>
              <RefreshCw size={15} aria-hidden /> {uploaded ? "Switch to demo dataset" : "Reload demo dataset"}
            </button>
            <button type="button" className="btn btn-outline-dark" onClick={download}>
              <Download size={15} aria-hidden /> Download JSON
            </button>
          </div>
        </section>

        <section className="card">
          <div className="card-head"><h2>Analyse your own synthetic dataset</h2><FileJson size={18} aria-hidden /></div>
          <p>Upload a JSON file in the same format as the demo: users, groups, roles, policies (with statements) and
            resources. It is analysed in memory and not stored.</p>
          <p className="small muted">Use synthetic or anonymised data only. Do not upload real credentials or secrets: the
            format never needs them.</p>
          <input ref={input} type="file" accept="application/json,.json" className="sr-only" id="dataset-file"
            tabIndex={-1} aria-label="Dataset JSON file" onChange={(e) => onFile(e.target.files?.[0])} />
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => input.current?.click()}>
            <Upload size={15} aria-hidden /> Choose JSON file
          </button>
          {busy && <Spinner label="Validating and analysing…" />}
          {status && <Notice tone={status.tone} title={status.tone === "error" ? "Dataset not loaded" : "Dataset loaded"}>{status.text}</Notice>}
          <details className="schema">
            <summary>Format reference</summary>
            <ul className="small">
              <li>Ids are prefixed: <code>user:</code>, <code>group:</code>, <code>role:</code>, <code>policy:</code>, <code>res:</code>.</li>
              <li>Statements: <code>sid</code>, <code>effect</code> (Allow/Deny), <code>actions</code>, <code>resources</code>
                (wildcards allowed), optional <code>last_used_days</code>.</li>
              <li>Role <code>trusted_principals</code> name users, roles, or <code>account:*</code>. Like AWS, a trust policy cannot name a group.</li>
              <li>Resource <code>sensitivity</code>: low, medium, high or critical.</li>
            </ul>
          </details>
        </section>
      </div>

      <AwsImportCard />

      <details className="card raw">
        <summary>View raw dataset JSON</summary>
        <CodeBlock value={dataset} />
      </details>
    </div>
  );
}
