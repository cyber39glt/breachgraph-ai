import type {
  AgentEvent, AIStatus, AnalyzeResponse, AwsExport, AwsImportReport, Change, Dataset, Explanation, SimulationResult,
} from "./types";

/** An error the API reported, with its stable code (e.g. "not_configured", "rate_limited"). */
export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError("offline", "Cannot reach the BreachGraph API. Is the backend running on port 8000?", 0);
  }
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    /* handled below */
  }
  if (!response.ok) {
    const p = (payload ?? {}) as { error?: string; message?: string };
    throw new ApiError(p.error ?? "http_error", p.message ?? `Request failed (HTTP ${response.status}).`,
      response.status);
  }
  if (payload === null) throw new ApiError("bad_response", "The API returned an unreadable response.", response.status);
  return payload as T;
}

/** Reads a newline-delimited JSON stream, calling onEvent for each event as it arrives. */
async function stream(path: string, body: unknown, onEvent: (e: AgentEvent) => void): Promise<void> {
  let response: Response;
  try {
    response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body) });
  } catch {
    throw new ApiError("offline", "Cannot reach the BreachGraph API. Is the backend running on port 8000?", 0);
  }
  if (!response.ok || !response.body) {
    let p: { error?: string; message?: string } = {};
    try {
      p = await response.json();
    } catch {
      /* use the defaults below */
    }
    throw new ApiError(p.error ?? "http_error", p.message ?? `Request failed (HTTP ${response.status}).`, response.status);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    buffer += decoder.decode(value, { stream: !done });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) if (line.trim()) onEvent(JSON.parse(line) as AgentEvent);
    if (done) break;
  }
  if (buffer.trim()) onEvent(JSON.parse(buffer) as AgentEvent);
}

// `dataset: null` means "use the built-in synthetic demo dataset".
const withDataset = (dataset: Dataset | null) => (dataset ? { dataset } : {});

export const api = {
  health: () => request<{ status: string; version: string; ai: AIStatus }>("/api/health"),
  demoDataset: () => request<Dataset>("/api/demo/dataset"),
  analyze: (dataset: Dataset | null) => request<AnalyzeResponse>("/api/analyze", withDataset(dataset)),
  simulate: (dataset: Dataset | null, changes: Change[]) =>
    request<SimulationResult>("/api/simulate", { ...withDataset(dataset), changes }),
  explain: (dataset: Dataset | null, findingId: string) =>
    request<Explanation>("/api/explain", { ...withDataset(dataset), finding_id: findingId }),
  awsSample: () => request<AwsExport>("/api/demo/aws-sample"),
  importAws: (files: AwsExport) => request<{ dataset: Dataset; report: AwsImportReport }>("/api/import/aws", files),
  fixAgent: (dataset: Dataset | null, findingId: string, onEvent: (e: AgentEvent) => void) =>
    stream("/api/agent/fix", { ...withDataset(dataset), finding_id: findingId }, onEvent),
};
