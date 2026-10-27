import type { Analysis, Dataset, Finding, Hop, PathFinding, Statement, StatementFinding } from "./types";

export interface Index {
  name: (id: string) => string;
  statement: (policy: string, sid: string) => Statement | undefined;
  user: (id: string) => Dataset["users"][number] | undefined;
  group: (id: string) => Dataset["groups"][number] | undefined;
  role: (id: string) => Dataset["roles"][number] | undefined;
  resource: (id: string) => Dataset["resources"][number] | undefined;
  policy: (id: string) => Dataset["policies"][number] | undefined;
  holdersOf: (policy: string) => string[];
}

export function buildIndex(data: Dataset): Index {
  const by = <T extends { id: string }>(items: T[]) => new Map(items.map((i) => [i.id, i]));
  const users = by(data.users);
  const groups = by(data.groups);
  const roles = by(data.roles);
  const resources = by(data.resources);
  const policies = by(data.policies);
  const names = new Map<string, string>();
  for (const table of [users, groups, roles, resources, policies]) {
    for (const [id, item] of table) names.set(id, (item as { name?: string }).name ?? id);
  }
  return {
    name: (id) => names.get(id) ?? id,
    statement: (policy, sid) => policies.get(policy)?.statements.find((s) => s.sid === sid),
    user: (id) => users.get(id),
    group: (id) => groups.get(id),
    role: (id) => roles.get(id),
    resource: (id) => resources.get(id),
    policy: (id) => policies.get(id),
    holdersOf: (policy) =>
      [...data.users, ...data.groups, ...data.roles].filter((h) => h.policies.includes(policy)).map((h) => h.id),
  };
}

export const isPath = (f: Finding): f is PathFinding => f.type === "attack_path";
export const isStatement = (f: Finding): f is StatementFinding => f.type !== "attack_path";

export const edgeId = (h: Pick<Hop, "source" | "relation" | "target">) => `${h.source}|${h.relation}|${h.target}`;

/** Node and edge ids that make up an attack path, for highlighting in the graph. */
export function pathElements(f: PathFinding) {
  return { nodes: new Set(f.path), edges: new Set(f.hops.map(edgeId)) };
}

export function pathsOf(analysis: Analysis): PathFinding[] {
  return analysis.findings.filter(isPath);
}

export const KIND_LABEL = { user: "Identity", group: "Group", role: "Role", resource: "Resource" } as const;

export const RELATION_LABEL = { member_of: "Member of", can_assume: "Can assume", access: "Has access" } as const;

export const FACTOR_LABEL: Record<string, string> = {
  no_mfa: "No MFA",
  external: "External",
  stale: "Inactive 90d+",
};
