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
let currentMode = "guide";

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
  if (currentMode === "guide") {
    els.output.innerHTML = renderGuide(data);
    return;
  }

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
  // Side-by-side (text) mode: compact plain-text list — full GUI previews are in Central Guide.
  const rows = data.netdestinations.map((nd) => {
    const af = nd.is_ipv6 ? "IPv6" : "IPv4";
    const mixedTag = nd.mixed_af
      ? ` <span class="pill err">⚠ mixed AF — split in Central</span>` : "";
    const fqdnLines  = nd.fqdns.map(f => `  name ${f}`).join("\n");
    const hostLines  = nd.hosts.map(h => `  host ${h}`).join("\n");
    const netLines   = nd.networks.map(n => `  network ${n}`).join("\n");
    const body = [fqdnLines, hostLines, netLines].filter(Boolean).join("\n") || "  (empty)";
    return `<div class="result-policy">
      <h3>netdestination ${esc(nd.name)}
        <span class="pill role">${af}</span>
        <span class="pill">${nd.entry_count} entr${nd.entry_count !== 1 ? "ies" : "y"}</span>
        <span class="pill warn">create in Central first</span>${mixedTag}
      </h3>
      <pre class="block">${esc(body)}</pre>
      <p class="muted small" style="margin:.25rem 0 0">
        Switch to <strong>Central Guide</strong> for the step-by-step GUI walkthrough.
      </p>
    </div>`;
  });
  return rows.join("\n");
}

/* Render a single "Create an Alias" Central GUI preview panel. */
function renderAliasPreview(name, af, fqdns, hosts, networks) {
  const afDot = (label) =>
    `<span class="af-radio ${label === af ? "af-selected" : ""}">${label}</span>`;

  const entryRows = [];
  for (const f of fqdns) {
    entryRows.push(`<tr><td class="nd-type">Domain Name</td><td class="nd-cond">${esc(f)}</td></tr>`);
  }
  for (const h of hosts) {
    entryRows.push(`<tr><td class="nd-type">Host IP</td><td class="nd-cond">${esc(h)}</td></tr>`);
  }
  for (const n of networks) {
    const [ip, mask] = n.split(" ");
    entryRows.push(`<tr><td class="nd-type">Network</td><td class="nd-cond">${esc(ip)} &nbsp;<span class="muted">${esc(mask || "")}</span></td></tr>`);
  }

  const entriesTable = entryRows.length
    ? `<table class="nd-entries">
        <thead><tr><th>Type</th><th>Condition</th></tr></thead>
        <tbody>${entryRows.join("")}</tbody>
       </table>`
    : `<p class="muted nd-empty">No entries</p>`;

  return `<div class="alias-preview">
    <div class="alias-field">
      <label class="alias-label">Name</label>
      <div class="alias-value name">${esc(name)}</div>
    </div>
    <div class="alias-field-row">
      <div class="alias-field">
        <label class="alias-label">Type</label>
        <div class="alias-value">Network Destination</div>
      </div>
      <div class="alias-field">
        <label class="alias-label">Destination Type</label>
        <div class="alias-af">${afDot("IPv4")} ${afDot("IPv6")}</div>
      </div>
    </div>
    <div class="alias-entries-hdr">
      <span class="alias-label">Entries</span>
      <span class="muted small">${entryRows.length} item${entryRows.length !== 1 ? "s" : ""}</span>
    </div>
    ${entriesTable}
  </div>`;
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
  if (currentMode === "guide") {
    return guideOutputText(lastResult);
  }
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

/* ========================= CENTRAL GUIDE MODE ========================= */

/**
 * Top-level guide renderer. Produces a 3-step Central configuration walkthrough:
 *   Step 1 — Create Named Destinations (Aliases)
 *   Step 2 — Create Roles
 *   Step 3 — Create Security Policies + assign rules
 *
 * Each step mirrors the Aruba Central GUI dialogs so engineers can follow
 * along field-by-field.
 */
function renderGuide(data) {
  const hasNetdests = data.netdestinations && data.netdestinations.length > 0;
  const hasRoles    = (data.roles || []).length > 0;
  const hasPolicies = data.policies.length > 0;

  let totalSteps = (hasNetdests ? 1 : 0) + (hasRoles ? 1 : 0) + (hasPolicies ? 1 : 0);
  if (!totalSteps) {
    return `<div class="error-box"><h3>Nothing to guide</h3>
      <p class="muted">No policies, roles, or named-destinations were found. Convert a config first.</p></div>`;
  }

  const parts = [];
  parts.push(`<div class="guide-intro">
    <h3>📋 Aruba Central Configuration Guide</h3>
    <p class="muted">Follow these steps to create the equivalent configuration in Aruba Central.
    Each panel mirrors the actual Central GUI dialog — enter the highlighted values directly.</p>
    <p class="muted small">Fields shown in <span class="from-aos8-sample">orange</span> come from your AOS&nbsp;8 config.
    Fields showing <span class="placeholder-sample">—</span> were not in the source config and need manual review.</p>
  </div>`);

  let stepNum = 0;

  if (hasNetdests) {
    stepNum++;
    const content = data.netdestinations.map((nd) => renderNdGuideItem(nd)).join("\n");
    parts.push(renderGuideStep(stepNum, totalSteps,
      "Create Named Destinations",
      "Security → Policies → Aliases → + Add",
      "Create these aliases <strong>before</strong> configuring roles and policies — policy rules reference them by name.",
      content));
  }

  if (hasRoles) {
    stepNum++;
    const content = data.roles.map(renderRolePreview).join("\n");
    parts.push(renderGuideStep(stepNum, totalSteps,
      "Create Roles",
      "Security → Roles → + Add Role",
      "Create a role for each user segment. The role name must exactly match the AOS&nbsp;8 <code>user-role</code> name.",
      content));
  }

  if (hasPolicies) {
    stepNum++;
    const content = data.policies.map((p) => renderPolicyGuide(p)).join("\n");
    parts.push(renderGuideStep(stepNum, totalSteps,
      "Create Security Policies &amp; Rules",
      "Security → Policies → + Add Policy",
      "Create each security policy, add its rules, then assign the policy to the matching role.",
      content));
  }

  return parts.join("\n");
}

/** Wraps a guide step in a numbered, collapsible section with nav breadcrumb. */
function renderGuideStep(num, total, title, navPath, description, content) {
  const crumbs = navPath.split(" → ")
    .map(s => `<span class="nav-crumb">${s}</span>`)
    .join(`<span class="nav-arrow"> → </span>`);

  return `<div class="guide-step">
    <div class="guide-step-hdr">
      <span class="guide-step-badge">Step ${num} of ${total}</span>
      <h3 class="guide-step-title">${title}</h3>
    </div>
    <div class="guide-nav-path">${crumbs}</div>
    <p class="guide-step-desc">${description}</p>
    <div class="guide-step-content">
      ${content}
    </div>
  </div>`;
}

/** Renders one netdestination as a guide item (alias preview + heading). */
function renderNdGuideItem(nd) {
  if (nd.mixed_af) {
    const v4Hosts    = nd.hosts.filter(h => !h.includes(":"));
    const v6Hosts    = nd.hosts.filter(h =>  h.includes(":"));
    const v4Networks = nd.networks.filter(n => !n.includes(":"));
    const v6Networks = nd.networks.filter(n =>  n.includes(":"));
    return `<div class="guide-item">
      <div class="guide-item-label">${esc(nd.name)}
        <span class="pill err">⚠ mixed IPv4 + IPv6 — create two aliases</span></div>
      <div class="nd-split">
        ${renderAliasPreview(nd.name + "-v4", "IPv4", nd.fqdns, v4Hosts, v4Networks)}
        ${renderAliasPreview(nd.name + "-v6", "IPv6", [], v6Hosts, v6Networks)}
      </div>
    </div>`;
  }
  const af = nd.is_ipv6 ? "IPv6" : "IPv4";
  return `<div class="guide-item">
    <div class="guide-item-label">${esc(nd.name)}
      <span class="pill role">${af}</span>
      <span class="pill">${nd.entry_count} entr${nd.entry_count !== 1 ? "ies" : "y"}</span></div>
    ${renderAliasPreview(nd.name, af, nd.fqdns, nd.hosts, nd.networks)}
  </div>`;
}

/**
 * Renders a Central "Create Role" GUI preview card.
 * Fields from the AOS 8 user-role block (vlan, captive-portal, bwc) are
 * highlighted in orange. Unknown fields show placeholders.
 */
function renderRolePreview(role) {
  const vlanVal = role.vlan
    ? `<span class="from-aos8">${esc(role.vlan)}</span>`
    : `<span class="placeholder">—</span>`;
  const cpVal = role.captive_portal
    ? `<span class="from-aos8">${esc(role.captive_portal)}</span>`
    : `<span class="placeholder">—</span>`;
  const bwcRow = (role.bwc && role.bwc.length)
    ? `<div class="role-field"><label class="role-label">Bandwidth Contract <span class="aos8-note">(AOS 8)</span></label>
         <div class="role-value"><span class="from-aos8">${role.bwc.map(esc).join(", ")}</span>
           <span class="muted small"> — verify equivalent in Central</span></div></div>` : "";
  const policiesNote = (role.policies && role.policies.length)
    ? `<div class="role-policies-note">
         <span class="muted small">After creation, assign ${role.policies.length === 1 ? "policy" : "policies"}:</span>
         ${role.policies.map(p => `<code class="policy-chip">${esc(p)}</code>`).join(" ")}
       </div>` : "";

  return `<div class="role-preview">
    <div class="role-preview-hdr">
      <span class="role-icon">👤</span>
      <span class="role-preview-name">${esc(role.name)}</span>
    </div>
    <div class="role-fields">
      <div class="role-field">
        <label class="role-label">Name <span class="required">*</span></label>
        <div class="role-value"><span class="from-aos8">${esc(role.name)}</span></div>
      </div>
      <div class="role-field">
        <label class="role-label">Description</label>
        <div class="role-value placeholder">Enter description</div>
      </div>
      <div class="role-field">
        <label class="role-label">VLAN ID</label>
        <div class="role-value">${vlanVal}</div>
      </div>
      <div class="role-field">
        <label class="role-label">Captive Portal Profile</label>
        <div class="role-value">${cpVal}</div>
      </div>
      <div class="role-field">
        <label class="role-label">GPID <span class="required">*</span></label>
        <div class="role-value placeholder">900 <span class="muted">(default)</span></div>
      </div>
      <div class="role-field role-field-wide">
        <label class="role-label">Dynamic Application Prioritization</label>
        <div class="role-value"><span class="cb-off">☐</span> <span class="muted">Disabled by default</span></div>
      </div>
      <div class="role-field role-field-wide">
        <label class="role-label">Device-Specific Parameters</label>
        <div class="role-value"><span class="cb-off">☐</span> Switch &nbsp;&nbsp; <span class="cb-off">☐</span> Gateway</div>
      </div>
      ${bwcRow}
    </div>
    ${policiesNote}
  </div>`;
}

/**
 * Renders a policy block in guide mode: policy-name field, role-assignment
 * note, then one rule card per translated rule.
 */
function renderPolicyGuide(p) {
  const rules = (p.central_json["security-policy"] || {})["policy-rule"] || [];
  const roleNote = (p.role_attribution && p.role_attribution.length)
    ? `<div class="policy-role-note">
         <span class="muted small">After creating the policy, assign it to role${p.role_attribution.length !== 1 ? "s" : ""}:</span>
         ${p.role_attribution.map(r => `<code class="policy-chip">${esc(r)}</code>`).join(" ")}
         <span class="muted small">— via Security → Roles → [role] → Edit → Policies</span>
       </div>` : "";

  const ruleCards = rules.length
    ? rules.map((r, i) => renderRuleCard(r, i + 1, rules.length)).join("\n")
    : `<p class="muted">No rules translated for this policy.</p>`;

  return `<div class="guide-policy">
    <div class="guide-policy-hdr">
      <span class="guide-policy-icon">📄</span>
      <h4 class="guide-policy-name">${esc(p.name)}</h4>
      ${p.unresolved ? `<span class="pill err">⚠ unresolved → review</span>` : ""}
    </div>
    <div class="role-field" style="margin-bottom:.75rem">
      <label class="role-label">Policy Name</label>
      <div class="role-value"><span class="from-aos8">${esc(p.name)}</span></div>
    </div>
    ${roleNote}
    <div class="guide-rules-hdr">Rules <span class="muted small">(${rules.length} total — add each in order)</span></div>
    <div class="guide-rules">${ruleCards}</div>
  </div>`;
}

/**
 * Renders a single translated Central rule as a "Create Rule" dialog preview.
 * Layout mirrors the Central GUI: Source section, Destination section, then
 * Address Family / Service / Action row.
 */
function renderRuleCard(rule, num, total) {
  const cond   = rule.condition || {};
  const src    = cond.source || {};
  const dst    = cond.destination || {};
  const af     = (cond["address-family"] || "IPV4") === "IPV6" ? "IPv6" : "IPv4";
  const action = rule.action || {};

  const srcType   = addrTypeLabel(src.type);
  const srcDetail = addrDetail(src);
  const dstType   = addrTypeLabel(dst.type);
  const dstDetail = addrDetail(dst);
  const svc       = serviceLabel(cond);
  const act       = actionLabel(action.type);
  const actClass  = action.type === "ACTION_ALLOW" ? "act-allow"
                  : action.type === "ACTION_DENY"  ? "act-deny"
                  : "act-other";

  const afDot = (label) =>
    `<span class="af-radio ${label === af ? "af-selected" : ""}">${label}</span>`;

  const srcBlock = srcDetail
    ? `<div class="rule-field">
         <label class="rule-label">Source Type</label>
         <div class="rule-value">${esc(srcType)}</div>
       </div>
       <div class="rule-field">
         <label class="rule-label">${esc(srcType)}</label>
         <div class="rule-value rule-ref">${esc(srcDetail)}</div>
       </div>`
    : `<div class="rule-field">
         <label class="rule-label">Source</label>
         <div class="rule-value">${esc(srcType)}</div>
       </div>`;

  const dstBlock = dstDetail
    ? `<div class="rule-field">
         <label class="rule-label">Destination Type</label>
         <div class="rule-value">${esc(dstType)}</div>
       </div>
       <div class="rule-field">
         <label class="rule-label">${esc(dstType)}</label>
         <div class="rule-value rule-ref">${esc(dstDetail)}</div>
       </div>`
    : `<div class="rule-field">
         <label class="rule-label">Destination</label>
         <div class="rule-value">${esc(dstType)}</div>
       </div>`;

  return `<div class="rule-card">
    <div class="rule-card-hdr">
      <span class="rule-num">Rule ${num}</span>
      <span class="rule-act-badge ${actClass}">${esc(act)}</span>
    </div>
    <div class="rule-sections">
      <div class="rule-section">
        <div class="rule-section-lbl">SOURCE</div>
        ${srcBlock}
      </div>
      <div class="rule-section">
        <div class="rule-section-lbl">DESTINATION</div>
        ${dstBlock}
      </div>
      <div class="rule-section rule-section-misc">
        <div class="rule-field">
          <label class="rule-label">Address Family</label>
          <div class="rule-value">${afDot("IPv4")} ${afDot("IPv6")}</div>
        </div>
        <div class="rule-field">
          <label class="rule-label">Service / Application</label>
          <div class="rule-value rule-ref">${esc(svc)}</div>
        </div>
      </div>
    </div>
  </div>`;
}

/* ---------- address / service / action helpers for guide mode ---------- */

function addrTypeLabel(type) {
  const map = {
    ADDRESS_ANY:     "Any",
    ADDRESS_ROLE:    "Access Role",
    ADDRESS_ALIAS:   "Network Destination",
    ADDRESS_HOST:    "Host IP",
    ADDRESS_NETWORK: "Network",
    ADDRESS_USER:    "Authenticated User",
    ADDRESS_LOCAL:   "Local IP",
  };
  return map[type] || type || "Any";
}

function addrDetail(addr) {
  const t = addr.type;
  if (!t || t === "ADDRESS_ANY" || t === "ADDRESS_USER" || t === "ADDRESS_LOCAL") return null;
  if (t === "ADDRESS_ROLE") {
    return addr.role || (addr["role-list"] || []).join(", ") || null;
  }
  if (t === "ADDRESS_ALIAS") return addr["net-group"] || null;
  if (t === "ADDRESS_HOST") {
    const ha = addr["host-address"] || {};
    return ha["host-ipv4-address"] || ha["host-ipv6-address"] || null;
  }
  if (t === "ADDRESS_NETWORK") {
    const na = addr["network-address"] || {};
    return na["network-ipv4-address"] || na["network-ipv6-address"] || null;
  }
  return null;
}

function serviceLabel(cond) {
  const svcs = cond.services || {};
  if (svcs["net-service"])    return svcs["net-service"];
  if (svcs["application"])    return "App: " + svcs["application"];
  if (svcs["app-category"])   return "App Category: " + svcs["app-category"];
  if (svcs["web-category"])   return "Web Category: " + svcs["web-category"];
  if (svcs["web-reputation"]) return "Web Reputation: " + svcs["web-reputation"];
  const ih = cond["ip-header"] || {};
  const proto = ih.protocol;
  if (proto) {
    const lbl = { IP_TCP: "TCP", IP_UDP: "UDP", IP_ICMP: "ICMP", IPV6_ICMP: "ICMPv6" }[proto] || proto;
    const dp  = (cond["transport-fields"] || {})["destination-port"] || {};
    if (dp.min !== undefined) {
      return dp.operator === "COMPARISON_RANGE" ? `${lbl} ${dp.min}–${dp.max}` : `${lbl} ${dp.min}`;
    }
    return lbl;
  }
  return "Any";
}

function actionLabel(type) {
  return {
    ACTION_ALLOW:           "Allow",
    ACTION_DENY:            "Deny",
    ACTION_SOURCE_NAT:      "Source NAT",
    ACTION_DESTINATION_NAT: "Destination NAT",
    ACTION_DUAL_NAT:        "Dual NAT",
    ACTION_REDIRECT:        "Redirect",
    ACTION_CAPTIVE_PORTAL:  "Captive Portal",
    ACTION_MIRROR:          "Mirror",
    ACTION_ROUTE:           "Route",
  }[type] || type || "Deny";
}

/** Plaintext export for guide mode (copy/download). */
function guideOutputText(data) {
  const lines = ["# Aruba Central Configuration Guide", ""];
  const hasNetdests = data.netdestinations && data.netdestinations.length > 0;
  const hasRoles    = (data.roles || []).length > 0;
  let totalSteps = (hasNetdests ? 1 : 0) + ((data.roles || []).length ? 1 : 0) + (data.policies.length ? 1 : 0);
  let stepNum = 0;

  if (hasNetdests) {
    stepNum++;
    lines.push(`## Step ${stepNum} of ${totalSteps}: Create Named Destinations`);
    lines.push("Navigation: Security → Policies → Aliases → + Add\n");
    for (const nd of data.netdestinations) {
      const af = nd.is_ipv6 ? "IPv6" : "IPv4";
      lines.push(`### ${nd.name}  [${af}${nd.mixed_af ? " — SPLIT REQUIRED" : ""}]`);
      for (const f of nd.fqdns)    lines.push(`  Domain Name: ${f}`);
      for (const h of nd.hosts)    lines.push(`  Host IP: ${h}`);
      for (const n of nd.networks) lines.push(`  Network: ${n}`);
      lines.push("");
    }
  }

  if (hasRoles) {
    stepNum++;
    lines.push(`## Step ${stepNum} of ${totalSteps}: Create Roles`);
    lines.push("Navigation: Security → Roles → + Add Role\n");
    for (const role of data.roles) {
      lines.push(`### ${role.name}`);
      lines.push(`  Name:  ${role.name}`);
      if (role.vlan)            lines.push(`  VLAN ID:                 ${role.vlan}`);
      if (role.captive_portal)  lines.push(`  Captive Portal Profile:  ${role.captive_portal}`);
      if (role.bwc && role.bwc.length) lines.push(`  Bandwidth Contract(s):   ${role.bwc.join(", ")}`);
      lines.push(`  GPID:  900 (default)`);
      if (role.policies && role.policies.length) {
        lines.push(`  Assign policies: ${role.policies.join(", ")}`);
      }
      lines.push("");
    }
  }

  if (data.policies.length) {
    stepNum++;
    lines.push(`## Step ${stepNum} of ${totalSteps}: Create Security Policies`);
    lines.push("Navigation: Security → Policies → + Add Policy\n");
    for (const p of data.policies) {
      lines.push(`### Policy: ${p.name}`);
      if (p.role_attribution && p.role_attribution.length) {
        lines.push(`Assign to role(s): ${p.role_attribution.join(", ")}`);
        lines.push("  (via Security → Roles → [role] → Edit → Policies)");
      }
      const rules = (p.central_json["security-policy"] || {})["policy-rule"] || [];
      for (const r of rules) {
        const cond = r.condition || {};
        const src  = cond.source || {};
        const dst  = cond.destination || {};
        const af   = (cond["address-family"] || "IPV4") === "IPV6" ? "IPv6" : "IPv4";
        const act  = actionLabel((r.action || {}).type);
        const srcStr = addrDetail(src) ? `${addrTypeLabel(src.type)}: ${addrDetail(src)}` : addrTypeLabel(src.type);
        const dstStr = addrDetail(dst) ? `${addrTypeLabel(dst.type)}: ${addrDetail(dst)}` : addrTypeLabel(dst.type);
        lines.push(`  Rule ${r.position}: ${srcStr} → ${dstStr} | Service: ${serviceLabel(cond)} | ${act} | ${af}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
