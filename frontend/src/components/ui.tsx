import { AlertTriangle, Boxes, Database, KeyRound, Loader2, ShieldCheck, Sparkles, User, Users } from "lucide-react";
import type { ReactNode } from "react";
import type { Level, NodeKind, Severity } from "../types";

export function Eyebrow({ children, tone = "default" }: { children: ReactNode; tone?: "default" | "lime" }) {
  return <p className={`eyebrow ${tone === "lime" ? "eyebrow-lime" : ""}`}>{children}</p>;
}

export function PageHeader({ eyebrow, title, children }: { eyebrow: string; title: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <Eyebrow>{eyebrow}</Eyebrow>
        <h1>{title}</h1>
      </div>
      {children && <div className="page-header-actions">{children}</div>}
    </header>
  );
}

export function SeverityBadge({ severity, score }: { severity: Severity; score?: number }) {
  return (
    <span className={`sev sev-${severity}`}>
      <span className="sev-dot" aria-hidden />
      {severity}
      {score !== undefined && <span className="sev-score">{score}</span>}
    </span>
  );
}

export function LevelTag({ level }: { level: Level }) {
  return <span className={`level level-${level}`}>{level}</span>;
}

export function Chip({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "risk" | "safe" | "dark" }) {
  return <span className={`chip chip-${tone}`}>{children}</span>;
}

const KIND_ICON = { user: User, group: Users, role: KeyRound, resource: Database } as const;

export function KindIcon({ kind, size = 15 }: { kind: NodeKind; size?: number }) {
  const Icon = KIND_ICON[kind] ?? Boxes;
  return <Icon size={size} aria-hidden className={`kind-icon kind-${kind}`} />;
}

export function kindOf(id: string): NodeKind {
  if (id.startsWith("user:")) return "user";
  if (id.startsWith("group:")) return "group";
  if (id.startsWith("role:")) return "role";
  return "resource";
}

export function Entity({ id, name }: { id: string; name: string }) {
  return (
    <span className="entity">
      <KindIcon kind={kindOf(id)} />
      <span>{name}</span>
    </span>
  );
}

export function VerifiedLabel({ children = "Verified by engine" }: { children?: ReactNode }) {
  return (
    <span className="provenance provenance-verified">
      <ShieldCheck size={14} aria-hidden /> {children}
    </span>
  );
}

export function AILabel({ children = "AI-generated" }: { children?: ReactNode }) {
  return (
    <span className="provenance provenance-ai">
      <Sparkles size={14} aria-hidden /> {children}
    </span>
  );
}

export function Spinner({ label }: { label: string }) {
  return (
    <span className="spinner" role="status">
      <Loader2 size={16} className="spin" aria-hidden /> {label}
    </span>
  );
}

export function Skeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="skeleton" aria-hidden>
      {Array.from({ length: lines }, (_, i) => <span key={i} style={{ width: `${90 - i * 14}%` }} />)}
    </div>
  );
}

export function Notice({ tone, title, children, action }: {
  tone: "error" | "info" | "success" | "warning"; title: string; children?: ReactNode; action?: ReactNode;
}) {
  return (
    <div className={`notice notice-${tone}`} role={tone === "error" ? "alert" : "status"}>
      {tone === "error" || tone === "warning" ? <AlertTriangle size={18} aria-hidden /> : <ShieldCheck size={18} aria-hidden />}
      <div>
        <strong>{title}</strong>
        {children && <div className="notice-body">{children}</div>}
        {action && <div className="notice-action">{action}</div>}
      </div>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <ShieldCheck size={28} aria-hidden />
      <strong>{title}</strong>
      {children && <p>{children}</p>}
    </div>
  );
}

export function CodeBlock({ value, label }: { value: unknown; label?: string }) {
  return (
    <figure className="code">
      {label && <figcaption>{label}</figcaption>}
      <pre tabIndex={0}>{typeof value === "string" ? value : JSON.stringify(value, null, 2)}</pre>
    </figure>
  );
}
