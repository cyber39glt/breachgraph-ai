import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, ApiError } from "./api";
import { buildIndex, type Index } from "./lookup";
import type { AgentResult, AgentRound, AnalyzeResponse, AwsImportReport, Change, Dataset, Explanation } from "./types";

export type Page = "overview" | "graph" | "investigate" | "simulate" | "dataset";
export const PAGES: Page[] = ["overview", "graph", "investigate", "simulate", "dataset"];

export interface Route {
  page: Page;
  param?: string;
}

function parseHash(): Route {
  const [page, param] = window.location.hash.replace(/^#\/?/, "").split("/");
  return PAGES.includes(page as Page) ? { page: page as Page, param: param || undefined } : { page: "overview" };
}

export function navigate(page: Page, param?: string) {
  window.location.hash = param ? `/${page}/${param}` : `/${page}`;
}

export function useRoute(): Route {
  const [route, setRoute] = useState(parseHash);
  useEffect(() => {
    const onChange = () => setRoute(parseHash());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export type ExplainState =
  | { status: "loading" }
  | { status: "done"; result: Explanation }
  | { status: "error"; error: ApiError };

export interface AgentState {
  status: "running" | "done" | "error";
  rounds: AgentRound[];
  result?: AgentResult;
  /** A failure reported by the server or the network; rounds already verified are kept. */
  error?: ApiError;
}

interface AppState {
  /** null = the built-in synthetic demo dataset */
  uploaded: Dataset | null;
  dataset: Dataset | null;
  index: Index | null;
  analysis: AnalyzeResponse | null;
  loading: boolean;
  error: ApiError | null;
  reload: () => void;
  loadDemo: () => void;
  loadUpload: (d: Dataset) => Promise<void>;
  explanations: Record<string, ExplainState>;
  explain: (findingId: string) => Promise<void>;
  /** The report from the last AWS import, shown on the Dataset page until another dataset loads. */
  importReport: AwsImportReport | null;
  setImportReport: (r: AwsImportReport | null) => void;
  agentRuns: Record<string, AgentState>;
  runAgent: (findingId: string) => Promise<void>;
  /** Changes queued for the simulator (e.g. from an AI suggestion or a candidate). */
  queued: Change[] | null;
  queueSimulation: (changes: Change[]) => void;
  clearQueue: () => void;
}

const Ctx = createContext<AppState | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [uploaded, setUploaded] = useState<Dataset | null>(null);
  const [dataset, setDataset] = useState<Dataset | null>(null);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [explanations, setExplanations] = useState<Record<string, ExplainState>>({});
  const [queued, setQueued] = useState<Change[] | null>(null);
  const [agentRuns, setAgentRuns] = useState<Record<string, AgentState>>({});
  const [importReport, setImportReport] = useState<AwsImportReport | null>(null);

  const run = useCallback(async (source: Dataset | null) => {
    setLoading(true);
    setError(null);
    try {
      const [data, result] = await Promise.all([
        source ? Promise.resolve(source) : api.demoDataset(),
        api.analyze(source),
      ]);
      setDataset(data);
      setAnalysis(result);
      setUploaded(source);
      setExplanations({});
      setAgentRuns({});
    } catch (e) {
      const err = e instanceof ApiError ? e : new ApiError("unknown", String(e), 0);
      // A rejected upload keeps the current dataset on screen; the caller shows the error.
      if (!source) setError(err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    run(null).catch(() => undefined);
  }, [run]);

  const explain = useCallback(async (findingId: string) => {
    setExplanations((s) => ({ ...s, [findingId]: { status: "loading" } }));
    try {
      const result = await api.explain(uploaded, findingId);
      setExplanations((s) => ({ ...s, [findingId]: { status: "done", result } }));
    } catch (e) {
      const error = e instanceof ApiError ? e : new ApiError("unknown", String(e), 0);
      setExplanations((s) => ({ ...s, [findingId]: { status: "error", error } }));
    }
  }, [uploaded]);

  const runAgent = useCallback(async (findingId: string) => {
    const update = (fn: (a: AgentState) => AgentState) =>
      setAgentRuns((s) => ({ ...s, [findingId]: fn(s[findingId] ?? { status: "running", rounds: [] }) }));
    setAgentRuns((s) => ({ ...s, [findingId]: { status: "running", rounds: [] } }));
    try {
      await api.fixAgent(uploaded, findingId, (event) => {
        if (event.type === "round") {
          const { type: _t, ...round } = event;
          update((a) => ({ ...a, rounds: [...a.rounds, round] }));
        } else if (event.type === "error") {
          update((a) => ({ ...a, error: new ApiError(event.error, event.message, 0) }));
        } else {
          const { type: _t, ...result } = event;
          update((a) => ({ ...a, status: a.error ? "error" : "done", result }));
        }
      });
      update((a) => (a.status === "running" ? { ...a, status: a.error ? "error" : "done" } : a));
    } catch (e) {
      const error = e instanceof ApiError ? e : new ApiError("unknown", String(e), 0);
      update((a) => ({ ...a, status: "error", error }));
    }
  }, [uploaded]);

  const value = useMemo<AppState>(() => ({
    uploaded, dataset, analysis, loading, error,
    index: dataset ? buildIndex(dataset) : null,
    reload: () => void run(uploaded).catch(() => undefined),
    loadDemo: () => {
      setImportReport(null);
      void run(null).catch(() => undefined);
    },
    loadUpload: (d) => run(d),
    explanations, explain,
    importReport, setImportReport,
    agentRuns, runAgent,
    queued,
    queueSimulation: (changes) => {
      setQueued(changes);
      navigate("simulate");
    },
    clearQueue: () => setQueued(null),
  }), [uploaded, dataset, analysis, loading, error, run, explanations, explain, importReport, agentRuns, runAgent, queued]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used inside AppProvider");
  return v;
}
