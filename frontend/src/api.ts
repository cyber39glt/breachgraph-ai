import type { AIStatus, AnalyzeResponse, Change, Dataset, Explanation, SimulationResult } from "./types";

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
};
