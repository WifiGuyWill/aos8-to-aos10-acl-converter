// Verifies the browser load path WITHOUT a browser: loads real Pyodide (WASM),
// mounts the engine files exactly like static/app.js, and runs web_adapter.run()
// against both sample configs. Exits non-zero on any failure.
//
//   node verify_pyodide.mjs
//
// This is a dev-only check; it is not shipped to Cloudflare.

import { loadPyodide } from "pyodide";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUB = join(__dirname, "public");

const ENGINE_FILES = [
  "aos8_acl_converter/__init__.py",
  "aos8_acl_converter/canonical.py",
  "aos8_acl_converter/core.py",
  "aos8_acl_converter/enum_tables.py",
  "aos8_acl_converter/parser.py",
  "aos8_acl_converter/reader.py",
  "aos8_acl_converter/renderer.py",
  "aos8_acl_converter/report.py",
  "web_adapter.py",
];

function assert(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
}

const py = await loadPyodide();
py.FS.mkdirTree("/py/aos8_acl_converter");
for (const rel of ENGINE_FILES) {
  const src = readFileSync(join(PUB, "py", rel), "utf8");
  py.FS.writeFile(`/py/${rel}`, src);
}
py.runPython(`
import sys
if "/py" not in sys.path:
    sys.path.insert(0, "/py")
import web_adapter
`);
console.log("engine imported under Pyodide OK");

function run(file, bridge) {
  const text = readFileSync(join(PUB, "examples", file), "utf8");
  py.globals.set("_cfg_text", text);
  py.globals.set("_bridge_mode", bridge);
  return JSON.parse(py.runPython("web_adapter.run(_cfg_text, _bridge_mode)"));
}

// --- sample_aos8.cfg ---
const a = run("sample_aos8.cfg", false);
assert(a.ok === true, "sample ok");
assert(a.policies.length === 3, `expected 3 policies, got ${a.policies.length}`);
const names = a.policies.map((p) => p.name).join(",");
assert(names === "corp-acl,guest-acl,corp-v6", `policy names: ${names}`);
assert(a.report.summary.source_rules === 17, `source_rules ${a.report.summary.source_rules}`);
assert(a.report.summary.generated_rules === 22, `generated_rules ${a.report.summary.generated_rules}`);
// any-any bidirectional expansion present
const expanded = a.policies[0].trace.some((t) => t.expanded && t.aos10.length === 2);
assert(expanded, "expected an expanded any-any rule in corp-acl");
console.log(`sample_aos8: ${a.policies.length} policies, ${a.report.summary.generated_rules} AOS10 rules — OK`);

// --- bridge_mode.cfg ---
const b = run("bridge_mode.cfg", true);
assert(b.ok === true, "bridge ok");
const bIssues = b.policies.reduce((n, p) => n + (p.stat.bridge_issues?.length || 0), 0);
assert(bIssues > 0, "expected bridge advisories with --bridge-mode");
console.log(`bridge_mode: ${bIssues} bridge advisories flagged — OK`);

// --- non-config input handled gracefully ---
py.globals.set("_cfg_text", "hostname foo\ninterface vlan 1\n");
py.globals.set("_bridge_mode", false);
const e = JSON.parse(py.runPython("web_adapter.run(_cfg_text, _bridge_mode)"));
assert(e.ok === true, "non-config input still returns ok payload");
console.log("non-config input handled gracefully — OK");

console.log("\nALL PYODIDE CHECKS PASSED");
