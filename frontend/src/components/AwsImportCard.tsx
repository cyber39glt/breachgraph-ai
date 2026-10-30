import { CloudDownload, FileJson, FileSpreadsheet, FileText, Upload } from "lucide-react";
import { useRef, useState } from "react";
import { api, ApiError } from "../api";
import { useApp } from "../state";
import type { AwsExport, Dataset } from "../types";
import { Eyebrow, Notice, Spinner } from "./ui";

const MAX_IMPORT_BYTES = 19_000_000;

type Slot = "details" | "credentials" | "context";

const SLOTS: Array<{ slot: Slot; label: string; hint: string; accept: string; icon: typeof FileJson; required?: boolean }> = [
  { slot: "details", label: "Authorization details", hint: "iam.json", accept: "application/json,.json", icon: FileJson, required: true },
  { slot: "credentials", label: "Credential report", hint: "credential-report.csv · adds MFA and last sign-in",
    accept: "text/csv,.csv", icon: FileSpreadsheet },
  { slot: "context", label: "Context", hint: "context.json · marks sensitive resources and contractors",
    accept: "application/json,.json", icon: FileText },
];

function FilePick({ label, hint, accept, icon: Icon, file, onPick, required }: {
  label: string; hint: string; accept: string; icon: typeof FileJson; file: File | null;
  onPick: (f: File | null) => void; required?: boolean;
}) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <div className="file-pick">
      <Icon size={18} aria-hidden />
      <div>
        <strong>{label}{required ? "" : " (optional)"}</strong>
        <span className="muted small">{file ? file.name : hint}</span>
      </div>
      <input ref={input} type="file" accept={accept} className="sr-only" tabIndex={-1} aria-label={`${label} file`}
        onChange={(e) => onPick(e.target.files?.[0] ?? null)} />
      <button type="button" className="btn btn-ghost" onClick={() => input.current?.click()}>
        {file ? "Change" : "Choose"}
      </button>
    </div>
  );
}

export function AwsImportCard() {
  const { loadUpload, importReport, setImportReport } = useApp();
  const [files, setFiles] = useState<Record<Slot, File | null>>({ details: null, credentials: null, context: null });
  const [busy, setBusy] = useState<false | "import" | "sample">(false);
  const [error, setError] = useState<string | null>(null);

  const finish = async (exported: AwsExport) => {
    const { dataset, report } = await api.importAws(exported);
    await loadUpload(dataset as Dataset);
    setImportReport(report);
  };

  const run = async (kind: "import" | "sample") => {
    setError(null);
    setBusy(kind);
    try {
      if (kind === "sample") {
        await finish(await api.awsSample());
      } else {
        const total = Object.values(files).reduce((n, f) => n + (f?.size ?? 0), 0);
        if (total > MAX_IMPORT_BYTES) throw new ApiError("too_large", "These files are larger than 19 MB in total.", 0);
        const parse = async (f: File | null, what: string) => {
          if (!f) return null;
          try {
            return JSON.parse(await f.text());
          } catch {
            throw new ApiError("invalid_json", `${what} is not valid JSON.`, 0);
          }
        };
        await finish({
          authorization_details: await parse(files.details, "The authorization details file"),
          credential_report_csv: files.credentials ? await files.credentials.text() : null,
          context: await parse(files.context, "The context file"),
        });
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card aws-import" aria-labelledby="aws-title">
      <div className="card-head">
        <h2 id="aws-title"><CloudDownload size={18} aria-hidden /> Import from AWS (offline)</h2>
      </div>
      <p>Analyse your own AWS account from its standard IAM export. BreachGraph never connects to AWS and never
        sees credentials: you export the files yourself with read-only access, and they are analysed in memory.</p>
      <ol className="small aws-steps">
        <li>In the AWS console, open <strong>CloudShell</strong> and run:
          <code className="cmd">aws iam get-account-authorization-details &gt; iam.json</code></li>
        <li>Optional, for MFA and last sign-in:
          <code className="cmd">aws iam generate-credential-report</code>
          <code className="cmd">aws iam get-credential-report --query Content --output text | base64 -d &gt; credential-report.csv</code></li>
        <li>Download the files (<em>Actions → Download file</em>) and choose them below. The commands only read IAM
          data (the AWS-managed <code>IAMReadOnlyAccess</code> policy covers them); opening CloudShell needs its own
          permission, or run the same commands with the AWS CLI on your computer.</li>
      </ol>

      <div className="file-picks">
        {SLOTS.map((s) => (
          <FilePick key={s.slot} {...s} file={files[s.slot]} onPick={(f) => setFiles((x) => ({ ...x, [s.slot]: f }))} />
        ))}
      </div>

      <div className="hero-actions">
        <button type="button" className="btn btn-primary" disabled={!files.details || !!busy} onClick={() => run("import")}>
          <Upload size={15} aria-hidden /> Import and analyse
        </button>
        <button type="button" className="btn btn-ghost" disabled={!!busy} onClick={() => run("sample")}>
          Try a sample AWS export
        </button>
      </div>
      {busy && <Spinner label={busy === "sample" ? "Importing the synthetic sample export…" : "Converting and analysing your export…"} />}
      {error && <Notice tone="error" title="Import failed">{error}</Notice>}

      {importReport && (
        <div className="import-report" aria-live="polite">
          <Notice tone="success" title={`Imported AWS account ${importReport.account_id ?? "(unknown)"}`}>
            {importReport.counts.users} users · {importReport.counts.groups} groups · {importReport.counts.roles} roles ·{" "}
            {importReport.counts.policies} policies · {importReport.counts.resources} resources. All pages now show this account.
          </Notice>
          {importReport.warnings.length > 0 && (
            <>
              <Eyebrow>Import notes</Eyebrow>
              <ul className="small">{importReport.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
            </>
          )}
          <Eyebrow>What this export cannot show</Eyebrow>
          <ul className="small muted">{importReport.not_in_export.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      )}
    </section>
  );
}
