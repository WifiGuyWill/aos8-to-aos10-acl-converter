// End-to-end browser smoke test: drives the real UI in headless Chromium,
// loads Pyodide from the CDN, clicks "Load sample" + "Convert", and asserts the
// rendered output contains the expected AOS 10 policy + report. Dev-only.
//
//   node e2e_browser.mjs   (requires the dev server running on :8788)

import puppeteer from "puppeteer";

const BASE = process.env.BASE || "http://127.0.0.1:8788";

function fail(msg) { console.error("FAIL:", msg); process.exit(1); }

const browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox"] });
try {
  const page = await browser.newPage();
  page.on("console", (m) => { if (m.type() === "error") console.log("  [browser error]", m.text()); });
  page.on("pageerror", (e) => console.log("  [pageerror]", e.message));

  await page.goto(BASE, { waitUntil: "networkidle2", timeout: 60000 });

  // Wait for the engine to finish loading (Convert button enabled).
  await page.waitForFunction(
    () => { const b = document.getElementById("btn-convert"); return b && !b.disabled; },
    { timeout: 90000 }
  );
  console.log("engine loaded in browser (Convert enabled)");

  // Load sample + convert.
  await page.click("#btn-sample");
  await page.waitForFunction(
    () => document.getElementById("config-input").value.includes("ip access-list session"),
    { timeout: 10000 }
  );
  await page.click("#btn-convert");

  // Wait for a rendered policy card.
  await page.waitForSelector(".result-policy h3", { timeout: 30000 });

  const out = await page.evaluate(() => document.getElementById("output").innerText);
  if (!out.includes("corp-acl")) fail("output missing corp-acl policy");
  if (!out.includes("role:corp")) fail("output missing translated role:corp rule");
  if (!out.includes("Conversion report")) fail("report not rendered");
  console.log("side-by-side + report rendered — OK");

  // Switch to Config view.
  await page.evaluate(() => {
    [...document.querySelectorAll("#output-mode button")].find((b) => b.dataset.mode === "config").click();
  });
  await page.waitForSelector("pre.block", { timeout: 5000 });
  const cfg = await page.evaluate(() => document.querySelector("pre.block").innerText);
  if (!cfg.toLowerCase().includes("rule")) fail("config view empty");
  console.log("config view rendered — OK");

  // Status badge should not be an error.
  const badge = await page.evaluate(() => document.getElementById("status-badge").className);
  if (badge.includes("badge-err")) fail("status badge shows error");
  console.log("status badge:", badge.replace("badge ", ""));

  console.log("\nE2E BROWSER TEST PASSED");
} finally {
  await browser.close();
}
