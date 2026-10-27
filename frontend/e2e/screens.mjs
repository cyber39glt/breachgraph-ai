// Captures screenshots of the running app (default http://127.0.0.1:8000) and reports
// console errors and CSP violations. Usage: node e2e/screens.mjs <outDir> [baseUrl]
import { createRequire } from "node:module";
// Playwright is optional and not a project dependency: install it with `npm i -D playwright && npx playwright install chromium`.
const { chromium } = createRequire(import.meta.url)("playwright");
const out = process.argv[2] ?? "e2e-output";
const base = process.argv[3] ?? "http://127.0.0.1:8000";
const browser = await chromium.launch();
const problems = [];
async function shoot(name, hash, { width = 1440, height = 900, full = false, before, scrollTo } = {}) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
  page.on("console", (m) => m.type() === "error" && problems.push(`${name}: ${m.text()}`));
  page.on("pageerror", (e) => problems.push(`${name}: ${e.message}`));
  await page.goto(`${base}/#${hash}`);
  await page.waitForSelector(".page h1", { timeout: 15000 });
  if (before) await before(page);
  if (scrollTo) {
    await page.evaluate((sel) => {
      const el = document.querySelector(sel);
      if (el) window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY - 72);
    }, scrollTo);
  }
  await page.waitForTimeout(700);
  await page.screenshot({ path: `${out}/${name}.png`, fullPage: full });
  await page.close();
}
const runFix = async (p) => {
  await p.locator(".candidates li").first().locator("input").check();
  await p.getByRole("button", { name: /Run simulation/ }).click();
  await p.waitForSelector(".delta", { timeout: 15000 });
};
await shoot("01-overview", "/overview");
await shoot("02-attack-graph", "/graph/PATH-9B77622F", { before: async (p) => {
  await p.selectOption(".inspector select", "edge:role:ci-deploy|can_assume|role:data-platform-admin");
}});
await shoot("03-investigation", "/investigate/PATH-9B77622F");
await shoot("04-simulator-before-after", "/simulate", { before: runFix, scrollTo: ".sim-results" });
await shoot("05-simulator-results", "/simulate", { before: runFix, scrollTo: ".pathlist-safe" });
await shoot("06-dataset", "/dataset");
await shoot("07-mobile-overview", "/overview", { width: 390, height: 844, full: true });
await shoot("08-mobile-investigation", "/investigate/PATH-9B77622F", { width: 390, height: 844 });
await browser.close();
console.log(problems.length ? "PROBLEMS:\n" + problems.join("\n") : "No console errors or CSP violations.");
process.exitCode = problems.length ? 1 : 0;
