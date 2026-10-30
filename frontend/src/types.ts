// Shapes returned by the Python API (breachgraph/backend/breachgraph/*.py).

export type Severity = "critical" | "high" | "medium" | "low";
export type Level = "read" | "write" | "admin";
export type NodeKind = "user" | "group" | "role" | "resource";
export type Relation = "member_of" | "can_assume" | "access";

export interface Statement {
  sid: string;
  effect: "Allow" | "Deny";
  actions: string[];
  resources: string[];
  last_used_days?: number | null;
}

export interface Dataset {
  metadata?: { name?: string; description?: string; synthetic?: boolean };
  users: Array<{ id: string; name: string; title?: string; department?: string; external?: boolean;
    mfa_enabled: boolean; last_login_days?: number; policies: string[] }>;
  groups: Array<{ id: string; name: string; members: string[]; policies: string[] }>;
  roles: Array<{ id: string; name: string; description?: string; trusted_principals: string[]; policies: string[] }>;
  policies: Array<{ id: string; name: string; statements: Statement[] }>;
  resources: Array<{ id: string; name: string; type?: string; sensitivity: Severity; data_classification?: string }>;
}

export interface GrantRef {
  holder?: string;
  policy: string;
  sid: string;
  effect?: string;
  actions?: string[];
  resources?: string[];
}

export interface Hop {
  source: string;
  target: string;
  relation: Relation;
  level?: Level;
  detail: string;
  evidence: { grant?: GrantRef; trust?: string; action?: string; group?: string };
}

export interface ScorePart {
  factor: string;
  label: string;
  points: number;
}

export interface PathFinding {
  id: string;
  key: string;
  type: "attack_path";
  severity: Severity;
  score: number;
  score_breakdown: ScorePart[];
  title: string;
  entry: string;
  target: string;
  level: Level;
  roles: string[];
  path: string[];
  hops: Hop[];
  facts: string[];
}

export interface StatementFinding {
  id: string;
  key: string;
  type: "wildcard_permission" | "unused_permission";
  severity: Severity;
  title: string;
  policy: string;
  sid: string;
  holders: string[];
  statement: Statement;
  related_findings: string[];
  facts: string[];
  score?: number;
}

export type Finding = PathFinding | StatementFinding;

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  sensitivity?: Severity;
  resource_type?: string;
  factors?: string[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: Relation;
  level?: Level;
  trust?: string;
  grants: Array<{ policy: string; sid: string; action: string }>;
}

export interface AccessEntry {
  key: string;
  user: string;
  resource: string;
  level: Level;
  roles: string[];
}

export interface Analysis {
  dataset: { name?: string; description?: string; synthetic?: boolean };
  summary: {
    identities: number;
    roles: number;
    resources: number;
    sensitive_resources: number;
    attack_paths: number;
    findings_by_severity: Record<Severity, number>;
  };
  findings: Finding[];
  access: AccessEntry[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
}

export type Change = { op: string; [field: string]: unknown };

export interface Candidate {
  change: Change;
  label: string;
  notes: string[];
  on_paths: string[];
  preview: {
    broken_paths: string[];
    new_paths: string[];
    collateral_access_removed: string[];
    risk_before: number;
    risk_after: number;
  };
}

export interface AIStatus {
  provider: string;
  configured: boolean;
  model: string;
}

export interface AnalyzeResponse extends Analysis {
  candidates: Candidate[];
  ai: AIStatus;
}

export interface SimulationResult {
  changes: Change[];
  before: Analysis;
  after: Analysis;
  note: string;
  diff: {
    broken_paths: PathFinding[];
    remaining_paths: PathFinding[];
    new_paths: PathFinding[];
    changed_paths: string[];
    access_removed: AccessEntry[];
    collateral_access_removed: AccessEntry[];
    access_added: AccessEntry[];
    risk_before: number;
    risk_after: number;
  };
}

export interface RemediationVerification {
  valid: boolean;
  error?: string;
  breaks_this_path?: boolean;
  broken_paths?: string[];
  new_paths?: string[];
  collateral_access_removed?: string[];
  risk_before?: number;
  risk_after?: number;
}

export interface Explanation {
  finding_id: string;
  provider: string;
  model: string;
  truncated: boolean;
  ai_generated: true;
  cached: boolean;
  generated_at: number;
  explanation: {
    summary: string;
    impact: string;
    facts_used: string[];
    assumptions: string[];
    uncertainties: string[];
    remediation: Array<{
      title: string;
      rationale: string;
      change: Change | null;
      change_rejected: boolean;
      rejection_reason?: string | null;
      verification: RemediationVerification | null;
    }>;
  };
  evidence_sent: unknown;
}

export interface AgentVerification {
  valid: boolean;
  error?: string;
  target_path_broken?: boolean;
  requirements_met?: boolean;
  broken_paths?: Array<{ id: string; title: string }>;
  still_open_paths?: Array<{ id: string; title: string }>;
  new_paths?: Array<{ id: string; title: string }>;
  other_access_removed?: Array<{ key: string; identity: string; resource: string; level: Level; via_roles: string[] }>;
  risk_before?: number;
  risk_after?: number;
}

export interface AgentRound {
  round: number;
  analysis: string;
  changes: Change[];
  rejected: string[];
  verification: AgentVerification | null;
  model_done: boolean;
}

export interface AgentResult {
  finding_id: string;
  provider: string;
  model: string;
  outcome: "verified" | "not_found";
  best_round: number | null;
  best_changes: Change[];
  stopped_reason: string;
  model_calls: number;
}

export type AgentEvent =
  | ({ type: "round" } & AgentRound)
  | ({ type: "result" } & AgentResult)
  | { type: "error"; error: string; message: string };
