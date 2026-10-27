import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import analyzeFixture from "./fixtures/analyze.json";
import datasetFixture from "./fixtures/dataset.json";
import simulateFixture from "./fixtures/simulate.json";

// Cytoscape needs a real canvas; the graph itself is exercised by the e2e script.
vi.mock("../components/GraphView", () => ({
  GraphView: ({ label }: { label: string }) => <div role="img" aria-label={label} />,
  GraphLegend: () => null,
}));

type Handler = (body: unknown) => { status: number; json: unknown };
let routes: Record<string, Handler>;
let calls: Array<{ url: string; body: unknown }>;

const ok = (json: unknown) => () => ({ status: 200, json });
const SIGNATURE = "PATH-9B77622F";

function withAI(configured: boolean) {
  return { ...analyzeFixture, ai: { ...analyzeFixture.ai, configured } };
}

beforeEach(() => {
  calls = [];
  routes = {
    "GET /api/demo/dataset": ok(datasetFixture),
    "POST /api/analyze": ok(analyzeFixture),
    "POST /api/simulate": ok(simulateFixture),
  };
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? "GET"} ${url}`;
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url: key, body });
    const handler = routes[key];
    if (!handler) throw new TypeError("Failed to fetch");
    const { status, json } = handler(body);
    return new Response(JSON.stringify(json), { status, headers: { "Content-Type": "application/json" } });
  }));
  window.location.hash = "";
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function open(hash: string) {
  window.location.hash = hash;
  render(<App />);
  await screen.findByRole("heading", { level: 1 });
}

describe("overview", () => {
  it("shows metrics calculated by the engine", async () => {
    await open("#/overview");
    const metrics = screen.getByRole("region", { name: "Key metrics" });
    expect(within(metrics).getByText("Attack paths").nextSibling).toHaveTextContent("6");
    expect(within(metrics).getByText("Critical findings").nextSibling).toHaveTextContent("4");
    expect(screen.getByText("Highest-risk path")).toBeInTheDocument();
    expect(screen.getAllByText("Jordan Reyes can gain admin access to customer-pii").length).toBeGreaterThan(0);
    expect(screen.getByText("13 findings in total")).toBeInTheDocument();
  });

  it("shows statement evidence when a wildcard finding is expanded", async () => {
    await open("#/overview");
    await userEvent.click(screen.getByRole("button", { name: /Show evidence for Wildcard resources \* in ci-deploy-permissions/ }));
    expect(screen.getByText(/Enables 4 attack paths/)).toBeInTheDocument();
    expect(screen.getByText("ci-deploy-permissions / AssumeAnyRole")).toBeInTheDocument();
  });

  it("shows an error with retry when the API is unreachable", async () => {
    delete routes["POST /api/analyze"];
    window.location.hash = "#/overview";
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the BreachGraph API");
    routes["POST /api/analyze"] = ok(analyzeFixture);
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Who can reach your most sensitive data")).toBeInTheDocument();
  });
});

describe("investigation", () => {
  it("shows every verified step with its policy statement", async () => {
    await open(`#/investigate/${SIGNATURE}`);
    expect(screen.getByText(/Jordan Reyes is a member of group CI Maintainers/)).toBeInTheDocument();
    expect(screen.getByText("ci-deploy-permissions / AssumeAnyRole")).toBeInTheDocument();
    expect(screen.getByText("data-platform-full / FullS3")).toBeInTheDocument();
    expect(screen.getByText("Score (capped from 103)")).toBeInTheDocument();
  });

  it("disables AI and explains why when no key is configured", async () => {
    await open(`#/investigate/${SIGNATURE}`);
    expect(screen.getByRole("button", { name: "Generate explanation" })).toBeDisabled();
    expect(screen.getByText("AI explanations are off")).toBeInTheDocument();
    expect(calls.some((c) => c.url.includes("/api/explain"))).toBe(false);
  });

  it("never calls the model on page load, and labels the AI answer", async () => {
    routes["POST /api/analyze"] = ok(withAI(true));
    routes["POST /api/explain"] = ok({
      finding_id: SIGNATURE, provider: "Meta Model API", model: "muse-spark-1.3", truncated: false,
      ai_generated: true, cached: false, generated_at: 1700000000, evidence_sent: {},
      explanation: {
        summary: "A contractor without MFA can chain two roles.", impact: "Admin over PII.",
        facts_used: ["AssumeAnyRole allows sts:AssumeRole on *"], assumptions: ["Credentials could be phished."],
        uncertainties: [], remediation: [{
          title: "Remove AssumeAnyRole", rationale: "Unused for 140 days.",
          change: { op: "remove_statement", policy: "policy:ci-deploy-permissions", sid: "AssumeAnyRole" },
          change_rejected: false,
          verification: { valid: true, breaks_this_path: true, broken_paths: ["a", "b", "c", "d"], new_paths: [] },
        }],
      },
    });
    await open(`#/investigate/${SIGNATURE}`);
    expect(calls.some((c) => c.url.includes("/api/explain"))).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Generate explanation" }));
    expect(await screen.findByText("A contractor without MFA can chain two roles.")).toBeInTheDocument();
    expect(screen.getByText("AI-generated")).toBeInTheDocument();
    expect(screen.getByText("Assumptions (not verified)")).toBeInTheDocument();
    expect(screen.getByText("Simulator: breaks this path")).toBeInTheDocument();
    expect(calls.find((c) => c.url === "POST /api/explain")?.body).toEqual({ finding_id: SIGNATURE });
  });

  it("shows the real error and no invented text when the AI call fails", async () => {
    routes["POST /api/analyze"] = ok(withAI(true));
    routes["POST /api/explain"] = () => ({ status: 429, json: { error: "rate_limited", message: "The Meta Model API rate limit or credit limit was reached. Try again later.", ai_generated: false } });
    await open(`#/investigate/${SIGNATURE}`);
    await userEvent.click(screen.getByRole("button", { name: "Generate explanation" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("No explanation was generated");
    expect(alert).toHaveTextContent("rate limit");
    expect(screen.queryByText("AI-generated")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("handles an unknown finding id", async () => {
    window.location.hash = "#/investigate/PATH-00000000";
    render(<App />);
    expect(await screen.findByText("Finding not found")).toBeInTheDocument();
  });
});

describe("simulator", () => {
  it("runs the selected fix and reports only engine-confirmed results", async () => {
    await open("#/simulate");
    const first = screen.getAllByRole("checkbox")[0];
    expect(first.closest("li")).toHaveTextContent("Remove statement AssumeAnyRole from policy ci-deploy-permissions");
    await userEvent.click(first);
    await userEvent.click(screen.getByRole("button", { name: /Run simulation/ }));
    expect(await screen.findByText("4 attack paths confirmed broken")).toBeInTheDocument();
    expect(screen.getByText("Attack paths goes from 6 to 2")).toBeInTheDocument();
    expect(screen.getByText("Path risk (sum of scores) goes from 516 to 167")).toBeInTheDocument();
    expect(screen.getByText("No new paths appeared.")).toBeInTheDocument();
    expect(calls.find((c) => c.url === "POST /api/simulate")?.body).toEqual({
      changes: [{ op: "remove_statement", policy: "policy:ci-deploy-permissions", sid: "AssumeAnyRole" }],
    });
  });

  it("warns when a change breaks nothing", async () => {
    routes["POST /api/simulate"] = ok({
      ...simulateFixture,
      after: simulateFixture.before,
      diff: { ...simulateFixture.diff, broken_paths: [], remaining_paths: [], risk_after: simulateFixture.diff.risk_before },
    });
    await open("#/simulate");
    await userEvent.click(screen.getAllByRole("checkbox")[0]);
    await userEvent.click(screen.getByRole("button", { name: /Run simulation/ }));
    expect(await screen.findByText("No attack path was broken")).toBeInTheDocument();
    expect(screen.queryByText(/confirmed broken/)).not.toBeInTheDocument();
  });

  it("requires a selection before running", async () => {
    await open("#/simulate");
    expect(screen.getByRole("button", { name: /Run simulation/ })).toBeDisabled();
  });
});

describe("dataset", () => {
  it("rejects a file that is not JSON without losing the current dataset", async () => {
    await open("#/dataset");
    const file = new File(["not json"], "bad.json", { type: "application/json" });
    await act(async () => {
      await userEvent.upload(screen.getByLabelText("Dataset JSON file"), file);
    });
    expect(await screen.findByText("Dataset not loaded")).toBeInTheDocument();
    expect(screen.getByText("The file is not valid JSON.")).toBeInTheDocument();
    expect(screen.getAllByText("Halcyon Payments (fictional)").length).toBeGreaterThan(0);
  });

  it("shows the server's validation message for an invalid dataset", async () => {
    routes["POST /api/analyze"] = (body) => (body && (body as { dataset?: unknown }).dataset
      ? { status: 400, json: { error: "invalid_dataset", message: "'users' must be a list" } }
      : { status: 200, json: analyzeFixture });
    await open("#/dataset");
    const file = new File([JSON.stringify({ users: 1 })], "x.json", { type: "application/json" });
    await act(async () => {
      await userEvent.upload(screen.getByLabelText("Dataset JSON file"), file);
    });
    await waitFor(() => expect(screen.getByText("'users' must be a list")).toBeInTheDocument());
  });
});
