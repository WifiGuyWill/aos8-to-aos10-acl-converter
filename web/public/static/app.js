/* AOS 8 -> AOS 10 ACL Converter — browser frontend.
 *
 * Loads Pyodide (WASM Python), mounts the *exact* aos8_acl_converter engine the
 * CLI uses into the in-browser filesystem, and calls web_adapter.run() to
 * translate configs. Nothing is uploaded — all work happens on this device.
 */

"use strict";

// Engine modules copied verbatim from the Python package by web/build.sh.
// web_adapter.py sits alongside the package on the Python path.
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

const els = {};
let pyodide = null;
let engineReady = false;
let lastResult = null;
let currentMode = "text";

function $(id) { return document.getElementById(id); }

document.addEventListener("DOMContentLoaded", () => {
  els.input = $("config-input");
  els.convert = $("btn-convert");
  els.convertLabel = $("convert-label");
  els.output = $("output");
  els.status = $("status-badge");
  els.optBridge = $("opt-bridge");
  els.optReport = $("opt-report");
  els.copy = $("btn-copy");
  els.download = $("btn-download");

  wireControls();
  bootPyodide();
});

function wireControls() {
  // Output-mode segmented control
  document.querySelectorAll("#output-mode button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#output-mode button").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentMode = btn.dataset.mode;
      if (lastResult) render(lastResult);
    });
  });

  $("btn-convert").addEventListener("click", convert);
  $("btn-clear").addEventListener("click", () => {
    els.input.value = "";
    els.input.focus();
  });
  $("btn-sample").addEventListener("click", () => loadSample("/examples/sample_aos8.cfg", false));
  $("btn-bridge-sample").addEventListener("click", () => loadSample("/examples/bridge_mode.cfg", true));

  $("file-input").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { els.input.value = reader.result; };
    reader.readAsText(file);
  });

  // Re-render on report toggle without re-running the engine
  els.optReport.addEventListener("change", () => { if (lastResult) render(lastResult); });

  els.copy.addEventListener("click", copyOutput);
  els.download.addEventListener("click", downloadOutput);

  // Ctrl/Cmd+Enter to convert
  els.input.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); convert(); }
  });
}

async function loadSample(url, bridge) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    els.input.value = await res.text();
    els.optBridge.checked = bridge;
  } catch (err) {
    els.input.value = `# Could not load sample (${err.message}).\n# Paste your own AOS 8 config here.`;
  }
}

async function bootPyodide() {
  setStatus("run", "Loading engine…");
  try {
    pyodide = await loadPyodide();

    // Create the package dir and write every engine module into the FS.
    pyodide.FS.mkdirTree("/py/aos8_acl_converter");
    await Promise.all(
      ENGINE_FILES.map(async (rel) => {
        const res = await fetch(`/py/${rel}`);
        if (!res.ok) throw new Error(`fetch /py/${rel} -> HTTP ${res.status}`);
        const src = await res.text();
        pyodide.FS.writeFile(`/py/${rel}`, src);
      })
    );

    // Put /py on sys.path and import the adapter once.
    pyodide.runPython(`
import sys
if "/py" not in sys.path:
    sys.path.insert(0, "/py")
import web_adapter
`);

    engineReady = true;
    els.convert.disabled = false;
    els.convertLabel.textContent = "Convert";
    setStatus("idle", "Ready");
  } catch (err) {
    console.error(err);
    setStatus("err", "Engine failed");
    els.convertLabel.textContent = "Engine failed to load";
    renderError("Could not load the conversion engine", String(err && err.stack ? err.stack : err));
  }
}

function convert() {
  if (!engineReady) return;
  const text = els.input.value || "";
  if (!text.trim()) {
    setStatus("warn", "Empty");
    renderError("Nothing to convert", "Paste an AOS 8 configuration (or load the sample) first.");
    return;
  }

  setStatus("run", "Converting…");
  els.convert.disabled = true;
  els.convertLabel.innerHTML = '<span class="spinner"></span>Converting…';

  // Defer so the spinner paints before the (synchronous) WASM call.
  setTimeout(() => {
    try {
      const bridge = els.optBridge.checked;
      pyodide.globals.set("_cfg_text", text);
      pyodide.globals.set("_bridge_mode", bridge);
      const jsonStr = pyodide.runPython("web_adapter.run(_cfg_text, _bridge_mode)");
      lastResult = JSON.parse(jsonStr);
      render(lastResult);

      const issues = countIssues(lastResult);
      if (issues.errors) setStatus("warn", `${issues.errors} to review`);
      else if (issues.warnings) setStatus("warn", `${issues.warnings} advisor${issues.warnings === 1 ? "y" : "ies"}`);
      else setStatus("ok", "Clean");

      els.copy.disabled = false;
      els.download.disabled = false;
    } catch (err) {
      console.error(err);
      setStatus("err", "Error");
      renderError("Conversion failed", String(err && err.message ? err.message : err));
    } finally {
      els.convert.disabled = false;
      els.convertLabel.textContent = "Convert";
    }
  }, 20);
}

function countIssues(data) {
  let errors = 0, warnings = 0;
  for (const p of data.policies) {
    if (p.unresolved || (p.unmapped_actions && p.unmapped_actions.length)) errors++;
    if (p.stat.bridge_issues && p.stat.bridge_issues.length) warnings += p.stat.bridge_issues.length;
    if (p.stat.complex_rules && p.stat.complex_rules.length) warnings += p.stat.complex_rules.length;
  }
  warnings += (data.warnings || []).length;
  return { errors, warnings };
}

/* ------------------------------- rendering ------------------------------- */

function render(data) {
  const parts = [];
  if (els.optReport.checked) parts.push(renderReport(data));

  // Named destinations (AOS 8 netdestination blocks) appear before the policies
  // so engineers know to create them in Central first.
  if (data.netdestinations && data.netdestinations.length) {
    parts.push(renderNamedDestinations(data));
  }

  for (const p of data.policies) {
    parts.push(renderPolicy(p, data));
  }
  if (!data.policies.length) {
    parts.push(`<div class="error-box"><h3>No policies found</h3>
      <p class="muted">No <code>ip access-list session</code> blocks were parsed from the input.</p></div>`);
  }
  els.output.innerHTML = parts.join("\n");
}

function renderNamedDestinations(data) {
  if (currentMode === "config") {
    // In config mode, show the rendered named-destination block.
    return data.netdest_config
      ? `<pre class="block">${esc(data.netdest_config)}</pre>`
      : "";
  }
  if (currentMode === "json") {
    const objs = (data.central_json_all.named_destinations || []);
    return objs.length
      ? `<pre class="block">${esc(JSON.stringify({ named_destinations: objs }, null, 2))}</pre>`
      : "";
  }
  // Side-by-side / text mode: a rich card per netdestination.
  const cards = data.netdestinations.map((nd) => {
    // Entry counts summary line.
    const countParts = [];
    if (nd.fqdns.length)    countParts.push(`${nd.fqdns.length} FQDN${nd.fqdns.length !== 1 ? "s" : ""}`);
    if (nd.hosts.length)    countParts.push(`${nd.hosts.length} host${nd.hosts.length !== 1 ? "s" : ""}`);
    if (nd.networks.length) countParts.push(`${nd.networks.length} network${nd.networks.length !== 1 ? "s" : ""}`);
    const summary = countParts.join(" · ") || "empty";

    // Pills: address family, entry count, warnings.
    const afLabel = nd.mixed_af ? "IPv4 + IPv6 (mixed!)" : (nd.is_ipv6 ? "IPv6" : "IPv4");
    const afPillCls = nd.mixed_af ? "err" : "role";
    const pills = [
      `<span class="pill">named-destination</span>`,
      `<span class="pill ${afPillCls}">${afLabel}</span>`,
      `<span class="pill">${esc(summary)}</span>`,
      `<span class="pill warn">create in Central first</span>`,
    ];
    if (nd.mixed_af) {
      pills.push(`<span class="pill err">split required → ${esc(nd.name)}-v4 / ${esc(nd.name)}-v6</span>`);
    }

    // Side-by-side rows: AOS8 keyword → AOS10 keyword.
    const entries = [];
    for (const f of nd.fqdns) {
      entries.push(`<tr><td class="aos8">name ${esc(f)}</td><td class="arrow">→</td><td class="aos10">fqdn ${esc(f)}</td></tr>`);
    }
    for (const h of nd.hosts) {
      const isV6 = h.includes(":");
      const destName = nd.mixed_af ? esc(nd.name) + (isV6 ? "-v6" : "-v4") : esc(nd.name);
      entries.push(`<tr><td class="aos8">host ${esc(h)}</td><td class="arrow">→</td><td class="aos10">host ${esc(h)}<span class="note"> (in ${destName})</span></td></tr>`);
    }
    for (const n of nd.networks) {
      const isV6 = n.includes(":");
      const destName = nd.mixed_af ? esc(nd.name) + (isV6 ? "-v6" : "-v4") : esc(nd.name);
      entries.push(`<tr><td class="aos8">network ${esc(n)}</td><td class="arrow">→</td><td class="aos10">network ${esc(n)}<span class="note"> (in ${destName})</span></td></tr>`);
    }

    const table = entries.length
      ? `<table class="sxs">
           <thead><tr><th>AOS 8 (netdestination)</th><th></th><th>AOS 10 (named-destination)</th></tr></thead>
           <tbody>${entries.join("")}</tbody>
         </table>`
      : `<p class="muted" style="padding:8px 12px">No entries (header only)</p>`;

    const mixedWarning = nd.mixed_af
      ? `<ul class="issues"><li class="err">Central named-destinations are single address-family (IPv4 OR IPv6).
           This block has both — split into <strong>${esc(nd.name)}-v4</strong> and <strong>${esc(nd.name)}-v6</strong>
           and update any policy rules that reference <code>alias:${esc(nd.name)}</code>.</li></ul>`
      : "";

    return `<div class="result-policy">
      <h3>${esc(nd.name)} ${pills.join(" ")}</h3>
      ${table}
      ${mixedWarning}
    </div>`;
  });
  return cards.join("\n");
}

function renderReport(data) {
  const s = data.report.summary;
  const stat = (n, label, cls = "") =>
    `<div class="stat ${cls}"><div class="n">${n}</div><div class="l">${label}</div></div>`;

  const grid = [
    stat(s.policies, "Policies"),
    stat(s.source_rules, "AOS 8 rules"),
    stat(s.generated_rules, "AOS 10 rules"),
    stat(s.any_any_rules, "any-any", s.any_any_rules ? "warn" : ""),
    stat(s.dropped_rules, "Dropped", s.dropped_rules ? "err" : ""),
    stat(s.roles_seen.length, "Roles"),
  ].join("");

  const issues = [];
  if (s.unresolved_policies && s.unresolved_policies.length) {
    issues.push(`<li class="err">Unresolved policies (fail-closed to deny): <strong>${s.unresolved_policies.join(", ")}</strong></li>`);
  }
  // Named-destination summary: counts and mixed-AF warnings.
  const nds = data.netdestinations || [];
  if (nds.length) {
    const mixedNds = nds.filter((n) => n.mixed_af);
    issues.push(`<li class="info">${nds.length} named-destination${nds.length !== 1 ? "s" : ""}: `
      + nds.map((n) => `<strong>${esc(n.name)}</strong> (${n.entry_count} entries)`).join(", ")
      + `</li>`);
    for (const n of mixedNds) {
      issues.push(`<li class="err"><strong>${esc(n.name)}</strong> mixes IPv4 and IPv6 — Central requires a separate named-destination per address family. Split into <strong>${esc(n.name)}-v4</strong> and <strong>${esc(n.name)}-v6</strong>.</li>`);
    }
  }
  if (s.roles_seen && s.roles_seen.length) {
    issues.push(`<li class="info">Roles seen: ${s.roles_seen.map(esc).join(", ")}</li>`);
  }
  if (s.netdestination_aliases && s.netdestination_aliases.length) {
    issues.push(`<li class="info">Netdestination aliases referenced: ${s.netdestination_aliases.map(esc).join(", ")}
      <span class="muted">— define matching Central named destinations.</span></li>`);
  }
  if (s.parse_warnings) {
    issues.push(`<li class="warn">${s.parse_warnings} parser warning(s) — lines that could not be interpreted.</li>`);
  }
  for (const w of data.warnings || []) {
    issues.push(`<li class="warn">${esc(w.acl || "?")}: ${esc(w.message)} <span class="muted">(${esc(w.text)})</span></li>`);
  }

  // Action + rule-type breakdown
  const breakdown = (obj) =>
    Object.entries(obj).map(([k, v]) => `${prettyEnum(k)} <strong>${v}</strong>`).join(" · ");
  if (s.action_breakdown && Object.keys(s.action_breakdown).length) {
    issues.push(`<li class="ok">Actions: ${breakdown(s.action_breakdown)}</li>`);
  }
  if (s.rule_type_breakdown && Object.keys(s.rule_type_breakdown).length) {
    issues.push(`<li class="ok">Rule types: ${breakdown(s.rule_type_breakdown)}</li>`);
  }
  if (!issues.length) issues.push(`<li class="ok">No issues flagged.</li>`);

  return `<div class="report">
    <h3>Conversion report</h3>
    <div class="stat-grid">${grid}</div>
    <ul class="issues">${issues.join("")}</ul>
  </div>`;
}

function renderPolicy(p, data) {
  const pills = [`<span class="pill">${p.association === "role" ? "role-based" : "interface"}</span>`];
  if (p.role_attribution && p.role_attribution.length) {
    pills.push(`<span class="pill role">roles: ${p.role_attribution.map(esc).join(", ")}</span>`);
  }
  if (p.unresolved) pills.push(`<span class="pill err">unresolved → deny</span>`);
  if (p.unmapped_actions && p.unmapped_actions.length) {
    pills.push(`<span class="pill err">unmapped: ${p.unmapped_actions.map(esc).join(", ")}</span>`);
  }
  if (p.stat.bridge_issues && p.stat.bridge_issues.length) {
    pills.push(`<span class="pill warn">${p.stat.bridge_issues.length} bridge advisory</span>`);
  }

  let body;
  if (currentMode === "text") body = renderSideBySide(p);
  else if (currentMode === "config") body = `<pre class="block">${esc(p.config)}</pre>`;
  else body = `<pre class="block">${esc(JSON.stringify(p.central_json, null, 2))}</pre>`;

  // Bridge advisories always shown under the policy when present.
  let advisories = "";
  if (p.stat.bridge_issues && p.stat.bridge_issues.length) {
    advisories = `<ul class="issues">${p.stat.bridge_issues
      .map((b) => `<li class="warn">bridge-mode: ${esc(b)}</li>`).join("")}</ul>`;
  }
  if (p.stat.complex_rules && p.stat.complex_rules.length) {
    advisories += `<ul class="issues">${p.stat.complex_rules
      .map((c) => `<li class="warn">${esc(c)}</li>`).join("")}</ul>`;
  }

  return `<div class="result-policy">
    <h3>${esc(p.name)} ${pills.join(" ")}</h3>
    ${body}
    ${advisories}
  </div>`;
}

function renderSideBySide(p) {
  const rows = p.trace.map((t) => {
    let cls = "";
    let right;
    if (t.dropped) {
      cls = "dropped";
      right = "⟂ dropped (no AOS 10 equivalent)";
    } else {
      right = t.aos10.map(esc).join("\n");
    }
    if (t.expanded) cls += " expanded";
    const arrow = t.dropped ? "⟂" : (t.expanded ? "⇉" : "→");
    return `<tr class="${cls.trim()}">
      <td class="aos8">${esc(t.aos8) || '<span class="note">(implicit)</span>'}</td>
      <td class="arrow">${arrow}</td>
      <td class="aos10">${right}</td>
    </tr>`;
  }).join("");

  return `<table class="sxs">
    <thead><tr><th>AOS 8</th><th></th><th>AOS 10 / Central</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderError(title, detail) {
  els.output.innerHTML = `<div class="error-box">
    <h3>${esc(title)}</h3>
    <pre>${esc(detail)}</pre>
  </div>`;
}

/* ------------------------------- output ops ------------------------------ */

function currentOutputText() {
  if (!lastResult) return "";
  if (currentMode === "json") {
    return JSON.stringify(lastResult.central_json_all, null, 2);
  }
  if (currentMode === "config") {
    const parts = [];
    if (lastResult.netdest_config) parts.push(lastResult.netdest_config);
    parts.push(...lastResult.policies.map((p) => p.config));
    return parts.join("\n\n");
  }
  // text / side-by-side -> a readable plaintext export
  const lines = [];
  // Include netdestination summary in plaintext export.
  for (const nd of (lastResult.netdestinations || [])) {
    lines.push(`# named-destination ${nd.name}  [create in Central before applying policies]`);
    for (const f of nd.fqdns)    lines.push(`  fqdn ${f}`);
    for (const h of nd.hosts)    lines.push(`  host ${h}`);
    for (const n of nd.networks) lines.push(`  network ${n}`);
    lines.push("");
  }
  for (const p of lastResult.policies) {
    lines.push(`# ${p.name}  [${p.association}${p.role_attribution.length ? " roles=" + p.role_attribution.join(",") : ""}]`);
    for (const t of p.trace) {
      if (t.dropped) lines.push(`  ${t.aos8}   ->   (dropped)`);
      else t.aos10.forEach((r, i) => lines.push(`  ${i === 0 ? t.aos8 : "".padEnd(t.aos8.length)}   ->   ${r}`));
    }
    lines.push("");
  }
  return lines.join("\n");
}

function copyOutput() {
  const text = currentOutputText();
  navigator.clipboard.writeText(text).then(() => {
    els.copy.textContent = "Copied!";
    setTimeout(() => (els.copy.textContent = "Copy"), 1400);
  });
}

function downloadOutput() {
  const text = currentOutputText();
  const ext = currentMode === "json" ? "json" : (currentMode === "config" ? "cfg" : "txt");
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `aos10-policies.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

/* -------------------------------- helpers -------------------------------- */

function setStatus(kind, text) {
  const map = { idle: "badge-idle", run: "badge-run", ok: "badge-ok", warn: "badge-warn", err: "badge-err" };
  els.status.className = `badge ${map[kind] || "badge-idle"}`;
  els.status.textContent = text;
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function prettyEnum(s) {
  return String(s)
    .replace(/^ACTION_/, "").replace(/^RULE_/, "")
    .toLowerCase().replace(/_/g, " ");
}
