"use strict";

(() => {
  const SVG_NS = "http://www.w3.org/2000/svg";

  const state = {
    status: null,
    doctor: [],
    report: null,
    history: null,
    playbooks: [],
    matrix: [],
    fixes: null,
    mcpCatalog: [],
    selectedLayers: new Set(),
    matrixFilter: "",
    selectedFindingId: null,
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function svgEl(tag, attrs) {
    const node = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        node.setAttribute(k, String(v));
      }
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  async function apiJSON(url, opts = {}) {
    const headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
    if (opts.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(url, Object.assign({}, opts, { headers }));
    const txt = await resp.text();
    let parsed = null;
    try {
      parsed = txt ? JSON.parse(txt) : {};
    } catch {
      parsed = { error: txt };
    }
    if (!resp.ok) {
      throw new Error((parsed && parsed.error) || `HTTP ${resp.status}`);
    }
    return parsed;
  }

  function appendTelemetry(kind, msg, ts) {
    const host = document.getElementById("telemetry-log");
    const entry = el("div", "telem-entry");
    const stamp = el("div", "muted", `${ts || new Date().toISOString()} [${kind}]`);
    const body = el("div", "", msg);
    entry.appendChild(stamp);
    entry.appendChild(body);
    host.prepend(entry);
    while (host.children.length > 60) {
      host.removeChild(host.lastChild);
    }
  }

  function switchView(viewName) {
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === viewName);
    });
    document.querySelectorAll(".view-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === `view-${viewName}`);
    });
    if (viewName === "fixes" && !state.fixes) {
      loadFixes();
    }
    if (viewName === "siem" && !state.history) {
      loadHistory();
    }
  }

  function renderGauge(score, grade) {
    const host = document.getElementById("overview-gauge-host");
    clear(host);
    const s = Math.max(0, Math.min(100, Number(score || 0)));
    const dash = Math.round((s * 264) / 100);
    const color = s >= 90 ? "#3fb950" : s >= 70 ? "#d29922" : "#f85149";

    const svg = svgEl("svg", { width: "120", height: "120", viewBox: "0 0 120 120" });
    svg.appendChild(svgEl("circle", { cx: "60", cy: "60", r: "42", fill: "none", stroke: "#263244", "stroke-width": "10" }));
    svg.appendChild(svgEl("circle", {
      cx: "60", cy: "60", r: "42", fill: "none", stroke: color, "stroke-width": "10",
      "stroke-dasharray": `${dash} 264`, transform: "rotate(-90 60 60)",
    }));
    const scoreText = svgEl("text", { x: "60", y: "58", "text-anchor": "middle", fill: "#e6edf3", "font-size": "24", "font-weight": "700" });
    scoreText.textContent = String(s);
    const gradeText = svgEl("text", { x: "60", y: "78", "text-anchor": "middle", fill: "#8b9bb0", "font-size": "13" });
    gradeText.textContent = `Grade ${grade || "-"}`;
    svg.appendChild(scoreText);
    svg.appendChild(gradeText);
    host.appendChild(svg);
  }

  function renderSparkline(runs) {
    const host = document.getElementById("sparkline-host");
    clear(host);
    if (!runs || runs.length === 0) {
      host.appendChild(el("p", "muted", "No scan runs recorded yet in runs.ndjson."));
      return;
    }
    const ordered = [...runs].reverse();
    const w = 320;
    const h = 84;
    const svg = svgEl("svg", { viewBox: `0 0 ${w} ${h}`, width: "100%", height: String(h) });
    const pts = ordered.map((r, i) => {
      const x = ordered.length === 1 ? w / 2 : Math.round((i * (w - 20)) / (ordered.length - 1)) + 10;
      const y = h - 10 - Math.round(((r.posture ? r.posture.score : 100) * (h - 22)) / 100);
      return [x, y, r];
    });
    if (pts.length > 1) {
      const d = pts.map(([x, y]) => `${x},${y}`).join(" ");
      svg.appendChild(svgEl("polyline", { fill: "none", stroke: "#4ea1ff", "stroke-width": "2.5", points: d }));
    }
    for (const [x, y, r] of pts) {
      const c = svgEl("circle", { cx: x, cy: y, r: "4", fill: "#3fb950" });
      const title = svgEl("title");
      title.textContent = `#${r.seq} ${r.profile}: ${r.posture ? r.posture.score : 0}/100`;
      c.appendChild(title);
      svg.appendChild(c);
    }
    host.appendChild(svg);
  }

  function renderTelemetryFlow() {
    const host = document.getElementById("telemetry-flow-host");
    clear(host);
    const svg = svgEl("svg", { viewBox: "0 0 680 96", width: "100%", height: "96" });
    const nodes = [
      { x: 10, y: 18, w: 120, h: 60, label: "L1-L5 Sensors", sub: "Net / Host / Web / CI / IoC" },
      { x: 190, y: 18, w: 130, h: 60, label: "L7 Aggregator", sub: "Dedup + Waivers + Score" },
      { x: 380, y: 18, w: 130, h: 60, label: "L6 raksa-siem", sub: "Correlate + Attack Graph" },
      { x: 560, y: 18, w: 110, h: 60, label: "SHA-256 Ledger", sub: "runs.ndjson" },
    ];
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      svg.appendChild(svgEl("rect", { x: n.x, y: n.y, width: n.w, height: n.h, rx: "8", fill: "#121821", stroke: "#388bfd", "stroke-width": "1.5" }));
      const t1 = svgEl("text", { x: n.x + n.w / 2, y: n.y + 26, "text-anchor": "middle", fill: "#e6edf3", "font-size": "12", "font-weight": "700" });
      t1.textContent = n.label;
      const t2 = svgEl("text", { x: n.x + n.w / 2, y: n.y + 44, "text-anchor": "middle", fill: "#8b9bb0", "font-size": "9.5" });
      t2.textContent = n.sub;
      svg.appendChild(t1);
      svg.appendChild(t2);
      if (i < nodes.length - 1) {
        const x1 = n.x + n.w;
        const x2 = nodes[i + 1].x;
        svg.appendChild(svgEl("line", { x1, y1: 48, x2, y2: 48, stroke: "#4ea1ff", "stroke-width": "2" }));
      }
    }
    host.appendChild(svg);
  }

  function renderReport(rep) {
    state.report = rep;
    if (!rep) return;

    const score = rep.posture ? rep.posture.score : 100;
    const grade = rep.posture ? rep.posture.grade : "A+";
    document.getElementById("topbar-score").textContent = `${score}/100`;
    document.getElementById("topbar-grade").textContent = grade;
    document.getElementById("nav-findings-count").textContent = String((rep.summary && rep.summary.total) || 0);
    document.getElementById("overview-meta").textContent =
      `Profile: ${rep.profile} | Target: ${rep.target} | Generated: ${rep.generated_at}`;

    renderGauge(score, grade);

    const s = rep.summary || {};
    document.getElementById("stat-critical").textContent = String(s.critical || 0);
    document.getElementById("stat-high").textContent = String(s.high || 0);
    document.getElementById("stat-medium").textContent = String(s.medium || 0);
    document.getElementById("stat-low").textContent = String(s.low || 0);
    document.getElementById("stat-info").textContent = String(s.info || 0);
    document.getElementById("overview-filters-meta").textContent =
      `Total active: ${s.total || 0} | Deduplicated: ${rep.deduplicated_count || 0} | Waived: ${rep.suppressed_count || 0} | Baselined: ${rep.baselined_count || 0}`;

    renderLayerCards(rep);
    renderLayerTree(rep);
    renderFindingsTable();
  }

  function renderLayerCards(rep) {
    const grid = document.getElementById("layer-cards-grid");
    clear(grid);
    const docMap = new Map((state.doctor || []).map((d) => [d.id, d]));
    const execs = (rep && rep.layers) || [];
    for (const ex of execs) {
      const doc = docMap.get(ex.layer);
      const card = el("div", "layer-card");
      const head = el("div", "layer-card-head");
      const title = el("strong", "", `L${doc ? doc.number : "?"} ${ex.layer}`);
      const badge = el("span", "badge", ex.status);
      head.appendChild(title);
      head.appendChild(badge);
      card.appendChild(head);

      const scoreText = `${ex.posture ? ex.posture.score : 100}/100 (${ex.posture ? ex.posture.grade : "A+"})`;
      card.appendChild(el("div", "layer-card-score", scoreText));
      card.appendChild(el("div", "muted", `Findings: ${ex.findings_count || 0} | Rules: ${doc ? doc.rule_count : "-"}`));
      if (ex.message) {
        card.appendChild(el("div", "layer-card-hint", ex.message));
      } else if (doc && !doc.installed) {
        card.appendChild(el("div", "layer-card-hint", doc.hint || `raksa install --layers ${ex.layer}`));
      }
      grid.appendChild(card);
    }
  }

  function renderLayerTree(rep) {
    const host = document.getElementById("layer-tree");
    clear(host);
    const docMap = new Map((state.doctor || []).map((d) => [d.id, d]));
    const execMap = new Map(((rep && rep.layers) || []).map((l) => [l.layer, l]));
    const ids = (state.doctor && state.doctor.length > 0)
      ? state.doctor.map((d) => d.id)
      : ["netguard", "hostguard", "webshield", "pipeguard", "iocscan", "siem"];

    for (const id of ids) {
      const doc = docMap.get(id);
      const ex = execMap.get(id);
      const row = el("div", "layer-row");
      const top = el("div", "layer-row-top");

      const lbl = el("label", "layer-check-label");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = state.selectedLayers.has(id);
      cb.addEventListener("change", () => {
        if (cb.checked) state.selectedLayers.add(id);
        else state.selectedLayers.delete(id);
      });
      const dot = el("span", `dot ${doc && doc.installed ? "dot-ready" : "dot-missing"}`);
      lbl.appendChild(cb);
      lbl.appendChild(dot);
      lbl.appendChild(el("span", "", `L${doc ? doc.number : "-"} ${id}`));

      const runBtn = el("button", "btn-link", "Scan");
      runBtn.type = "button";
      runBtn.addEventListener("click", () => runScan({ layers: [id], profile: `layer:${id}` }));

      top.appendChild(lbl);
      top.appendChild(runBtn);
      row.appendChild(top);

      const meta = el("div", "layer-row-meta");
      meta.appendChild(el("span", "", doc && doc.installed ? "ready" : "missing"));
      meta.appendChild(el("span", "", `findings: ${ex ? ex.findings_count : 0}`));
      row.appendChild(meta);
      host.appendChild(row);
    }
  }

  function renderPlaybooks(pbs) {
    state.playbooks = pbs || [];
    const host = document.getElementById("playbook-list");
    clear(host);
    for (const pb of state.playbooks) {
      const row = el("div", "playbook-row");
      const top = el("div", "layer-row-top");
      top.appendChild(el("strong", "", pb.name));
      const runBtn = el("button", "btn-link", "Run");
      runBtn.type = "button";
      runBtn.addEventListener("click", () => runPlaybook(pb.name));
      top.appendChild(runBtn);
      row.appendChild(top);
      row.appendChild(el("div", "muted", (pb.layers || []).join(", ")));
      host.appendChild(row);
    }
  }

  function renderFindingsTable() {
    const tbody = document.getElementById("findings-tbody");
    clear(tbody);
    const findings = (state.report && state.report.findings) || [];
    const q = document.getElementById("findings-search").value.trim().toLowerCase();
    const layerF = document.getElementById("findings-layer-filter").value;
    const sevF = document.getElementById("findings-severity-filter").value;

    const filtered = findings.filter((f) => {
      if (layerF && f.layer !== layerF) return false;
      if (sevF && String(f.severity).toLowerCase() !== sevF) return false;
      if (!q) return true;
      return (
        (f.rule_id || "").toLowerCase().includes(q) ||
        (f.title || "").toLowerCase().includes(q) ||
        (f.target || "").toLowerCase().includes(q) ||
        (f.mitre_d3fend || "").toLowerCase().includes(q)
      );
    });

    if (filtered.length === 0) {
      const tr = el("tr");
      const td = el("td", "muted", "No findings match current filters.");
      td.colSpan = 6;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const f of filtered) {
      const tr = el("tr");
      tr.addEventListener("click", () => showFindingDrawer(f));

      const tdSev = el("td");
      tdSev.appendChild(el("span", `sev-pill sev-${String(f.severity).toLowerCase()}`, f.severity));
      tr.appendChild(tdSev);

      const tdRule = el("td");
      tdRule.appendChild(el("code", "", f.rule_id));
      tr.appendChild(tdRule);

      tr.appendChild(el("td", "", f.layer));
      tr.appendChild(el("td", "", f.title));

      const tdTarget = el("td");
      tdTarget.appendChild(el("code", "", f.target));
      tr.appendChild(tdTarget);

      const tdAct = el("td");
      const waiveBtn = el("button", "btn btn-ghost", "Waive");
      waiveBtn.type = "button";
      waiveBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        openWaiverModal(f);
      });
      tdAct.appendChild(waiveBtn);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }
  }

  function showFindingDrawer(f) {
    state.selectedFindingId = f.id;
    document.getElementById("drawer-placeholder").classList.add("hidden");
    document.getElementById("drawer-content").classList.remove("hidden");

    const meta = document.getElementById("drawer-meta");
    clear(meta);
    meta.appendChild(el("div", "", `Rule: ${f.rule_id} (${f.severity})`));
    meta.appendChild(el("div", "", `Layer: ${f.layer}`));
    meta.appendChild(el("div", "", `Target: ${f.target}`));
    if (f.mitre_d3fend) meta.appendChild(el("div", "", `MITRE D3FEND: ${f.mitre_d3fend}`));
    if (f.compliance && f.compliance.length) meta.appendChild(el("div", "", `Controls: ${f.compliance.join(", ")}`));

    document.getElementById("drawer-remediation").textContent = f.remediation || f.description || "-";
    document.getElementById("drawer-evidence").textContent = JSON.stringify(f.evidence || { description: f.description }, null, 2);
  }

  function openWaiverModal(f) {
    document.getElementById("waiver-rule-id").value = f.rule_id || "";
    document.getElementById("waiver-target").value = f.target || "";
    document.getElementById("waiver-reason").value = "";
    const nextYear = new Date(Date.now() + 90 * 86400 * 1000).toISOString().slice(0, 10);
    document.getElementById("waiver-expires").value = nextYear;
    document.getElementById("waiver-error").textContent = "";
    document.getElementById("waiver-modal").showModal();
  }

  function renderMatrix(rows) {
    state.matrix = rows || [];
    const tbody = document.getElementById("matrix-tbody");
    clear(tbody);

    const visible = state.matrix.filter((r) => !state.matrixFilter || r.status === state.matrixFilter);
    const counts = { covered: 0, partial: 0, planned: 0 };
    for (const r of state.matrix) {
      if (counts[r.status] !== undefined) counts[r.status]++;
    }
    document.getElementById("matrix-summary").textContent =
      `Covered: ${counts.covered} | Partial: ${counts.partial} | Planned (v0.4.0): ${counts.planned}`;

    for (const r of visible) {
      const tr = el("tr");
      const tdSt = el("td");
      const pill = el("span", `sev-pill ${r.status === "covered" ? "sev-low" : r.status === "partial" ? "sev-medium" : "sev-info"}`, r.status);
      tdSt.appendChild(pill);
      tr.appendChild(tdSt);

      tr.appendChild(el("td", "", r.category));
      tr.appendChild(el("td", "", `${r.mitre_attack} / ${r.mitre_d3fend}`));
      tr.appendChild(el("td", "", `${(r.layers || []).join(", ")} (${r.rule_ranges})`));
      tr.appendChild(el("td", "", r.defensive_aim));

      const tdAct = el("td");
      const btn = el("button", "btn btn-ghost", "Scan");
      btn.type = "button";
      btn.addEventListener("click", () => {
        const runnable = (r.layers || []).filter((l) => l !== "orchestrator");
        if (runnable.length > 0) runScan({ layers: runnable, profile: "matrix" });
      });
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }
  }

  function renderFixes(res) {
    state.fixes = res;
    const banner = document.getElementById("fix-skipped-banner");
    const host = document.getElementById("fix-items-host");
    clear(host);

    if (res && res.skipped && res.skipped.length > 0) {
      banner.classList.remove("hidden");
      banner.textContent = `Skipped tools: ${res.skipped.join(" | ")}`;
    } else {
      banner.classList.add("hidden");
    }

    const items = (res && res.items) || [];
    if (items.length === 0) {
      const card = el("div", "card");
      card.appendChild(el("p", "muted", `No read-only unified remediation patches returned for target '${(res && res.target) || "."}'.`));
      host.appendChild(card);
      return;
    }

    for (const item of items) {
      const card = el("div", "card");
      card.appendChild(el("h3", "", `[${item.layer}] ${item.tool} (${item.target})`));
      const pre = el("pre", "diff-block");
      for (const line of String(item.diff || "").split("\n")) {
        let cls = "diff-line-ctx";
        if (line.startsWith("+")) cls = "diff-line-add";
        else if (line.startsWith("-")) cls = "diff-line-del";
        else if (line.startsWith("@@")) cls = "diff-line-hunk";
        pre.appendChild(el("span", cls, line));
      }
      card.appendChild(pre);
      host.appendChild(card);
    }
  }

  function renderHistory(data) {
    state.history = data;
    const badge = document.getElementById("ledger-status-badge");
    badge.textContent = data.chain_verified ? `${data.chain_entries} verified` : "CHAIN TAMPERED";
    badge.className = `badge ${data.chain_verified ? "badge-edition" : "sev-critical"}`;

    document.getElementById("ledger-verify-detail").textContent =
      `Ledger: ${data.history_path} | Entries: ${data.chain_entries} | Status: ${data.chain_reason}`;
    renderSparkline(data.runs || []);

    const tbody = document.getElementById("history-tbody");
    clear(tbody);
    for (const r of (data.runs || [])) {
      const tr = el("tr");
      tr.appendChild(el("td", "", `#${r.seq}`));
      tr.appendChild(el("td", "", r.timestamp));
      tr.appendChild(el("td", "", r.profile));
      tr.appendChild(el("td", "", r.target));
      tr.appendChild(el("td", "", r.posture ? `${r.posture.score}/100 (${r.posture.grade})` : "-"));
      const tdHash = el("td");
      tdHash.appendChild(el("code", "", (r.entry_hash || "").slice(0, 16) + "..."));
      tr.appendChild(tdHash);
      tbody.appendChild(tr);
    }
  }

  function renderMCPCatalog(tools) {
    state.mcpCatalog = tools || [];
    const host = document.getElementById("mcp-list");
    clear(host);
    const q = document.getElementById("mcp-search").value.trim().toLowerCase();
    const filtered = state.mcpCatalog.filter((t) => {
      if (!q) return true;
      return t.name.toLowerCase().includes(q) || t.layer.toLowerCase().includes(q) || (t.description || "").toLowerCase().includes(q);
    });
    for (const t of filtered) {
      const card = el("div", "mcp-card");
      card.appendChild(el("code", "", t.name));
      card.appendChild(el("span", "badge", ` ${t.layer}`));
      card.appendChild(el("p", "", t.description));
      host.appendChild(card);
    }
  }

  async function runScan(overrides = {}) {
    const target = overrides.target || document.getElementById("target-input").value.trim() || ".";
    const profile = overrides.profile || document.getElementById("profile-select").value || "full";
    const layers = overrides.layers || [];
    appendTelemetry("scan", `Starting Hybrid audit (profile=${profile}, target=${target})`);
    try {
      const rep = await apiJSON("/api/v1/scan", {
        method: "POST",
        body: JSON.stringify({ target, profile, layers }),
      });
      renderReport(rep);
      await loadHistory();
      appendTelemetry("scan", `Completed audit: score ${rep.posture.score}/100 (${rep.posture.grade}), findings=${rep.summary.total}`);
    } catch (err) {
      appendTelemetry("error", `Scan failed: ${err.message}`);
    }
  }

  async function runPlaybook(name) {
    const target = document.getElementById("target-input").value.trim() || ".";
    appendTelemetry("playbook", `Executing playbook '${name}' on '${target}'`);
    try {
      const rep = await apiJSON("/api/v1/playbooks/run", {
        method: "POST",
        body: JSON.stringify({ name, target }),
      });
      renderReport(rep);
      await loadHistory();
      appendTelemetry("playbook", `Playbook '${name}' finished (${rep.posture.score}/100)`);
    } catch (err) {
      appendTelemetry("error", `Playbook '${name}' error: ${err.message}`);
    }
  }

  async function loadDoctor() {
    const res = await apiJSON("/api/v1/doctor");
    state.doctor = res.tools || [];
    if (state.report) {
      renderLayerCards(state.report);
      renderLayerTree(state.report);
    }
  }

  async function loadHistory() {
    const res = await apiJSON("/api/v1/history");
    renderHistory(res);
  }

  async function loadFixes() {
    const target = document.getElementById("target-input").value.trim() || ".";
    const res = await apiJSON(`/api/v1/fix-preview?path=${encodeURIComponent(target)}`);
    renderFixes(res);
  }

  function exportReport(format) {
    window.location.href = `/api/v1/export?format=${encodeURIComponent(format)}`;
  }

  function openPalette() {
    const modal = document.getElementById("palette-modal");
    const input = document.getElementById("palette-input");
    input.value = "";
    renderPaletteResults("");
    modal.showModal();
    input.focus();
  }

  function renderPaletteResults(query) {
    const q = query.trim().toLowerCase();
    const actions = [
      { label: "View: Overview", hint: "view", fn: () => switchView("overview") },
      { label: "View: Findings Explorer", hint: "view", fn: () => switchView("findings") },
      { label: "View: Attack-vs-Defense Matrix", hint: "view", fn: () => switchView("matrix") },
      { label: "View: Fix Workbench", hint: "view", fn: () => switchView("fixes") },
      { label: "View: SIEM & Audit Ledger", hint: "view", fn: () => switchView("siem") },
      { label: "Scan: Run Selected Profile", hint: "scan", fn: () => runScan() },
      { label: "Scan: Checked Hybrid Layers", hint: "hybrid", fn: () => runScan({ layers: [...state.selectedLayers] }) },
      { label: "Export: SARIF 2.1.0", hint: "export", fn: () => exportReport("sarif") },
      { label: "Export: Standalone HTML Report", hint: "export", fn: () => exportReport("html") },
      { label: "Ledger: Verify SHA-256 Chain", hint: "verify", fn: () => loadHistory() },
    ];
    for (const pb of state.playbooks) {
      actions.push({ label: `Playbook: ${pb.name}`, hint: "playbook", fn: () => runPlaybook(pb.name) });
    }
    const host = document.getElementById("palette-results");
    clear(host);
    for (const act of actions.filter((a) => !q || a.label.toLowerCase().includes(q))) {
      const btn = el("button", "palette-item");
      btn.type = "button";
      btn.appendChild(el("span", "", act.label));
      btn.appendChild(el("span", "badge", act.hint));
      btn.addEventListener("click", () => {
        document.getElementById("palette-modal").close();
        act.fn();
      });
      host.appendChild(btn);
    }
  }

  function connectSSE() {
    const badge = document.getElementById("sse-conn-badge");
    const es = new EventSource("/api/v1/events");
    es.onopen = () => {
      badge.textContent = "live SSE";
      badge.className = "badge badge-edition";
    };
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        appendTelemetry(data.type || "event", data.message || ev.data, data.timestamp);
      } catch {
        appendTelemetry("event", ev.data);
      }
    };
    es.onerror = () => {
      badge.textContent = "reconnecting";
      badge.className = "badge";
    };
  }

  function wireEvents() {
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view));
    });
    document.querySelectorAll(".rtab").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".rtab").forEach((t) => t.classList.toggle("active", t === btn));
        document.querySelectorAll(".right-pane").forEach((p) => p.classList.toggle("active", p.id === `rtab-${btn.dataset.rtab}`));
      });
    });
    document.getElementById("btn-toggle-right").addEventListener("click", () => {
      document.querySelector(".workspace").classList.toggle("right-collapsed");
    });
    document.getElementById("btn-run-audit").addEventListener("click", () => runScan());
    document.getElementById("btn-run-selected").addEventListener("click", () => {
      const layers = [...state.selectedLayers];
      if (layers.length === 0) {
        appendTelemetry("hint", "Check at least one layer checkbox in the Hybrid sidebar.");
        return;
      }
      runScan({ layers, profile: "hybrid-selected" });
    });
    document.getElementById("btn-refresh-doctor").addEventListener("click", loadDoctor);
    document.getElementById("btn-refresh-fixes").addEventListener("click", loadFixes);
    document.getElementById("btn-verify-chain").addEventListener("click", loadHistory);
    document.getElementById("btn-clear-events").addEventListener("click", () => {
      clear(document.getElementById("telemetry-log"));
    });

    document.querySelectorAll(".export-btn").forEach((btn) => {
      btn.addEventListener("click", () => exportReport(btn.dataset.format));
    });

    document.getElementById("findings-search").addEventListener("input", renderFindingsTable);
    document.getElementById("findings-layer-filter").addEventListener("change", renderFindingsTable);
    document.getElementById("findings-severity-filter").addEventListener("change", renderFindingsTable);
    document.getElementById("mcp-search").addEventListener("input", () => renderMCPCatalog(state.mcpCatalog));

    document.querySelectorAll("#matrix-filter-pills .pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.matrixFilter = btn.dataset.status || "";
        document.querySelectorAll("#matrix-filter-pills .pill").forEach((p) => p.classList.toggle("active", p === btn));
        renderMatrix(state.matrix);
      });
    });

    document.getElementById("btn-copy-diff").addEventListener("click", async () => {
      const items = (state.fixes && state.fixes.items) || [];
      const text = items.map((i) => `# ${i.layer}\n${i.diff}`).join("\n\n");
      if (navigator.clipboard && text) await navigator.clipboard.writeText(text);
      appendTelemetry("fix", "Copied unified patch diff to clipboard.");
    });

    document.getElementById("btn-download-patch").addEventListener("click", () => {
      const items = (state.fixes && state.fixes.items) || [];
      const text = items.map((i) => `# ${i.layer}\n${i.diff}`).join("\n\n");
      const blob = new Blob([text || "# No patches generated\n"], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "raksa-hardening.patch";
      a.click();
      URL.revokeObjectURL(url);
    });

    document.getElementById("btn-copy-mcp-cfg").addEventListener("click", async () => {
      const snippet = JSON.stringify({ mcpServers: { raksa: { command: "raksa", args: ["mcp"] } } }, null, 2);
      if (navigator.clipboard) await navigator.clipboard.writeText(snippet);
      appendTelemetry("mcp", "Copied 61-tool raksa MCP config to clipboard.");
    });

    document.getElementById("btn-siem-health").addEventListener("click", async () => {
      try {
        const res = await apiJSON("/api/v1/siem/health", { method: "POST", body: "{}" });
        document.getElementById("siem-bridge-status").textContent = `SIEM Healthy: ${res.endpoint}`;
      } catch (err) {
        document.getElementById("siem-bridge-status").textContent = `SIEM Unreachable: ${err.message}`;
      }
    });

    document.getElementById("btn-siem-ingest").addEventListener("click", async () => {
      try {
        const res = await apiJSON("/api/v1/siem/ingest", { method: "POST", body: "{}" });
        document.getElementById("siem-bridge-status").textContent = `SIEM Ingest OK: ${JSON.stringify(res.response || res)}`;
      } catch (err) {
        document.getElementById("siem-bridge-status").textContent = `SIEM Ingest Failed: ${err.message}`;
      }
    });

    document.getElementById("btn-close-waiver").addEventListener("click", () => {
      document.getElementById("waiver-modal").close();
    });
    document.getElementById("waiver-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const errBox = document.getElementById("waiver-error");
      errBox.textContent = "";
      try {
        const rep = await apiJSON("/api/v1/waivers", {
          method: "POST",
          body: JSON.stringify({
            rule_id: document.getElementById("waiver-rule-id").value,
            target_contains: document.getElementById("waiver-target").value,
            reason: document.getElementById("waiver-reason").value,
            expires_on: document.getElementById("waiver-expires").value,
          }),
        });
        document.getElementById("waiver-modal").close();
        renderReport(rep);
        appendTelemetry("waiver", "Saved fail-closed waiver to .raksa.yml and refreshed posture.");
      } catch (err) {
        errBox.textContent = err.message;
      }
    });

    document.getElementById("btn-cmd-palette").addEventListener("click", openPalette);
    document.getElementById("btn-close-palette").addEventListener("click", () => {
      document.getElementById("palette-modal").close();
    });
    document.getElementById("palette-input").addEventListener("input", (ev) => renderPaletteResults(ev.target.value));
    document.addEventListener("keydown", (ev) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
        ev.preventDefault();
        openPalette();
      }
    });
  }

  async function init() {
    wireEvents();
    renderTelemetryFlow();
    connectSSE();
    try {
      const [status, doc, rep, pbs, mat, hist, mcp] = await Promise.all([
        apiJSON("/api/v1/status"),
        apiJSON("/api/v1/doctor"),
        apiJSON("/api/v1/report"),
        apiJSON("/api/v1/playbooks"),
        apiJSON("/api/v1/attack-matrix"),
        apiJSON("/api/v1/history"),
        apiJSON("/api/v1/mcp-catalog"),
      ]);
      state.status = status;
      document.getElementById("ui-version").textContent = `v${status.version || "0.2.0"}`;
      document.getElementById("ui-edition").textContent = String((status.edition && status.edition.edition) || "OSS").toUpperCase();
      document.getElementById("target-input").value = status.workspace || ".";
      state.doctor = doc.tools || [];
      renderReport(rep);
      renderPlaybooks(pbs.playbooks || []);
      renderMatrix(mat.matrix || []);
      renderHistory(hist);
      renderMCPCatalog(mcp.tools || []);
    } catch (err) {
      appendTelemetry("error", `Initial workbench load failed: ${err.message}`);
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
