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
    theme: "dark",
    mode: "simple",
    activeView: "simple-home",
    simpleUrgencyFilter: "",
    toastTimer: null,
  };

  function showToast(msg) {
    const pill = document.getElementById("toast-pill");
    if (!pill || !msg) return;
    pill.textContent = String(msg);
    pill.classList.add("visible");
    if (state.toastTimer) clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      pill.classList.remove("visible");
    }, 2600);
  }

  function applyTheme(theme, persist) {
    const next = theme === "light" ? "light" : "dark";
    state.theme = next;
    document.documentElement.dataset.theme = next;
    const lbl = document.getElementById("theme-toggle-label");
    if (lbl) lbl.textContent = next === "light" ? "Dark" : "Light";
    const btn = document.getElementById("btn-theme-toggle");
    if (btn) btn.setAttribute("aria-pressed", String(next === "light"));
    if (persist) {
      try {
        localStorage.setItem("raksa-theme", next);
      } catch {
        // ignore storage errors in restricted contexts
      }
    }
  }

  function initTheme() {
    let saved = "dark";
    try {
      const stored = localStorage.getItem("raksa-theme");
      if (stored === "light" || stored === "dark") saved = stored;
    } catch {
      saved = "dark";
    }
    applyTheme(saved, false);
  }

  function toggleTheme() {
    const next = state.theme === "light" ? "dark" : "light";
    applyTheme(next, true);
    showToast(`Switched to ${next === "light" ? "Light Glass" : "Dark Glass"} theme`);
  }

  function applyMode(mode, persist, targetViewOverride) {
    const next = mode === "pro" ? "pro" : "simple";
    state.mode = next;
    document.documentElement.dataset.mode = next;
    document.querySelectorAll("#mode-switch .mode-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.modeOpt === next);
    });
    if (persist) {
      try {
        localStorage.setItem("raksa-mode", next);
      } catch {
        // ignore storage errors
      }
    }
    if (targetViewOverride) {
      switchView(targetViewOverride);
      return;
    }
    const proViews = new Set(["overview", "findings", "matrix", "fixes", "siem"]);
    const simpleViews = new Set(["simple-home", "simple-issues", "simple-ask"]);
    if (next === "simple" && proViews.has(state.activeView)) {
      switchView("simple-home");
    } else if (next === "pro" && simpleViews.has(state.activeView)) {
      switchView("overview");
    }
  }

  function initMode() {
    let saved = "simple";
    try {
      const stored = localStorage.getItem("raksa-mode");
      if (stored === "simple" || stored === "pro") saved = stored;
    } catch {
      saved = "simple";
    }
    applyMode(saved, false, saved === "pro" ? "overview" : "simple-home");
  }

  function humanUrgency(sev) {
    switch (String(sev || "").toLowerCase()) {
      case "critical":
        return { key: "urgent", label: "Urgent", pillClass: "sev-critical", rank: 4 };
      case "high":
        return { key: "important", label: "Important", pillClass: "sev-high", rank: 3 };
      case "medium":
        return { key: "moderate", label: "Moderate", pillClass: "sev-medium", rank: 2 };
      default:
        return { key: "low", label: "Low", pillClass: "sev-low", rank: 1 };
    }
  }

  function humanLayerName(layer) {
    switch (String(layer || "").toLowerCase()) {
      case "network-defense":
        return "Network Security";
      case "host-hardening":
        return "Computer / Server";
      case "web-defense":
        return "Website Security";
      case "devsecops":
        return "Code & Secrets";
      case "ioc-defense":
        return "Files & Malware";
      case "siem":
        return "Security Monitor";
      default:
        return layer || "General";
    }
  }

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
    state.activeView = viewName;
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

  function renderGaugeInto(hostId, score, grade) {
    const host = document.getElementById(hostId);
    if (!host) return;
    clear(host);
    const s = Math.max(0, Math.min(100, Number(score || 0)));
    const circ = 276;
    const dash = Math.round((s * circ) / 100);
    const arcCls = s >= 90 ? "gauge-arc-good" : s >= 70 ? "gauge-arc-warn" : "gauge-arc-bad";

    const svg = svgEl("svg", { width: "126", height: "126", viewBox: "0 0 120 120" });
    svg.appendChild(svgEl("circle", { cx: "60", cy: "60", r: "44", class: "gauge-track" }));
    svg.appendChild(svgEl("circle", {
      cx: "60", cy: "60", r: "44",
      class: `gauge-arc ${arcCls}`,
      "stroke-dasharray": `${dash} ${circ}`,
      transform: "rotate(-90 60 60)",
    }));
    const scoreText = svgEl("text", { x: "60", y: "58", "text-anchor": "middle", class: "gauge-score-text" });
    scoreText.textContent = String(s);
    const gradeText = svgEl("text", { x: "60", y: "78", "text-anchor": "middle", class: "gauge-grade-text" });
    gradeText.textContent = `Grade ${grade || "-"}`;
    svg.appendChild(scoreText);
    svg.appendChild(gradeText);
    host.appendChild(svg);
  }

  function renderGauge(score, grade) {
    renderGaugeInto("overview-gauge-host", score, grade);
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
    const h = 86;
    const svg = svgEl("svg", { viewBox: `0 0 ${w} ${h}`, width: "100%", height: String(h) });
    const pts = ordered.map((r, i) => {
      const x = ordered.length === 1 ? w / 2 : Math.round((i * (w - 20)) / (ordered.length - 1)) + 10;
      const y = h - 12 - Math.round(((r.posture ? r.posture.score : 100) * (h - 24)) / 100);
      return [x, y, r];
    });
    if (pts.length > 1) {
      const d = pts.map(([x, y]) => `${x},${y}`).join(" ");
      const baseLine = h - 6;
      const areaPts = `${pts[0][0]},${baseLine} ${d} ${pts[pts.length - 1][0]},${baseLine}`;
      svg.appendChild(svgEl("polygon", { class: "spark-area", points: areaPts }));
      svg.appendChild(svgEl("polyline", { class: "spark-line", points: d }));
    }
    for (const [x, y, r] of pts) {
      const c = svgEl("circle", { cx: x, cy: y, r: "4", class: "spark-dot" });
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
      { x: 10, y: 18, w: 124, h: 60, label: "L1-L5 Sensors", sub: "Net / Host / Web / CI / IoC" },
      { x: 188, y: 18, w: 134, h: 60, label: "L7 Aggregator", sub: "Dedup + Waivers + Score" },
      { x: 376, y: 18, w: 134, h: 60, label: "L6 raksa-siem", sub: "Correlate + Attack Graph" },
      { x: 560, y: 18, w: 110, h: 60, label: "SHA-256 Ledger", sub: "runs.ndjson" },
    ];
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      svg.appendChild(svgEl("rect", { x: n.x, y: n.y, width: n.w, height: n.h, rx: "14", class: "flow-node-rect" }));
      const t1 = svgEl("text", { x: n.x + n.w / 2, y: n.y + 27, "text-anchor": "middle", class: "flow-node-title" });
      t1.textContent = n.label;
      const t2 = svgEl("text", { x: n.x + n.w / 2, y: n.y + 45, "text-anchor": "middle", class: "flow-node-sub" });
      t2.textContent = n.sub;
      svg.appendChild(t1);
      svg.appendChild(t2);
      if (i < nodes.length - 1) {
        const x1 = n.x + n.w + 4;
        const x2 = nodes[i + 1].x - 4;
        svg.appendChild(svgEl("line", { x1, y1: 48, x2, y2: 48, class: "flow-connector" }));
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
    renderSimpleHome(rep);
    renderSimpleIssues();
  }

  function renderSimpleHome(rep) {
    if (!rep) return;
    const s = rep.summary || {};
    const score = rep.posture ? rep.posture.score : 100;
    const grade = rep.posture ? rep.posture.grade : "A+";
    const total = Number(s.total || 0);
    const crit = Number(s.critical || 0);
    const high = Number(s.high || 0);

    const cntBadge = document.getElementById("simple-issues-count");
    if (cntBadge) cntBadge.textContent = String(total);

    renderGaugeInto("simple-gauge-host", score, grade);

    const pill = document.getElementById("simple-status-pill");
    const title = document.getElementById("simple-status-title");
    const desc = document.getElementById("simple-status-desc");
    const meta = document.getElementById("simple-hero-meta");

    if (meta) {
      meta.textContent = `Project: ${rep.target || "."} | Found ${total} issue(s)`;
    }

    if (pill && title && desc) {
      if (total === 0) {
        pill.className = "sev-pill sev-low";
        pill.textContent = "All Clear";
        title.textContent = "Your project looks safe";
        desc.textContent = "No active security issues were found in the latest read-only scan.";
      } else if (crit > 0) {
        pill.className = "sev-pill sev-critical";
        pill.textContent = "Action Needed";
        title.textContent = "Urgent issues need your attention";
        desc.textContent = `Found ${total} issue(s), including ${crit} urgent item(s) you should fix first.`;
      } else if (high > 0) {
        pill.className = "sev-pill sev-high";
        pill.textContent = "Needs Attention";
        title.textContent = "Some important risks found";
        desc.textContent = `Found ${total} issue(s), including ${high} important item(s) to fix before deploying.`;
      } else {
        pill.className = "sev-pill sev-medium";
        pill.textContent = "Fairly Good";
        title.textContent = "Minor hardening tips available";
        desc.textContent = `Found ${total} moderate or low tip(s) to strengthen security further.`;
      }
    }

    const host = document.getElementById("simple-priority-list");
    if (!host) return;
    clear(host);

    const findings = [...((rep && rep.findings) || [])].sort(
      (a, b) => humanUrgency(b.severity).rank - humanUrgency(a.severity).rank
    );

    if (findings.length === 0) {
      const okRow = el("div", "priority-row");
      const msg = el("div", "priority-row-text");
      msg.appendChild(el("strong", "", "Clean bill of health"));
      msg.appendChild(el("span", "muted", "Run any Quick Check above whenever you update code, headers, or server settings."));
      okRow.appendChild(msg);
      host.appendChild(okRow);
      return;
    }

    for (const f of findings.slice(0, 3)) {
      const u = humanUrgency(f.severity);
      const row = el("div", "priority-row");
      const left = el("div", "priority-row-main");
      left.appendChild(el("span", `sev-pill ${u.pillClass}`, u.label));

      const txt = el("div", "priority-row-text");
      txt.appendChild(el("strong", "", f.title || f.rule_id));
      txt.appendChild(el("span", "muted", `${humanLayerName(f.layer)} - ${f.target || "."}`));
      left.appendChild(txt);

      const fixBtn = el("button", "btn btn-ghost", "View Fix");
      fixBtn.type = "button";
      fixBtn.addEventListener("click", () => {
        const searchBox = document.getElementById("simple-issues-search");
        if (searchBox) searchBox.value = f.rule_id || "";
        state.simpleUrgencyFilter = "";
        document.querySelectorAll("#simple-urgency-pills .pill").forEach((p) => {
          p.classList.toggle("active", (p.dataset.urgency || "") === "");
        });
        renderSimpleIssues();
        switchView("simple-issues");
      });

      row.appendChild(left);
      row.appendChild(fixBtn);
      host.appendChild(row);
    }
  }

  function renderSimpleIssues() {
    const host = document.getElementById("simple-issues-list");
    if (!host) return;
    clear(host);

    const searchInp = document.getElementById("simple-issues-search");
    const q = searchInp ? searchInp.value.trim().toLowerCase() : "";
    const uf = state.simpleUrgencyFilter || "";
    const findings = [...((state.report && state.report.findings) || [])].sort(
      (a, b) => humanUrgency(b.severity).rank - humanUrgency(a.severity).rank
    );

    const filtered = findings.filter((f) => {
      const u = humanUrgency(f.severity);
      if (uf && u.key !== uf) return false;
      if (!q) return true;
      return (
        (f.title || "").toLowerCase().includes(q) ||
        (f.rule_id || "").toLowerCase().includes(q) ||
        (f.target || "").toLowerCase().includes(q) ||
        humanLayerName(f.layer).toLowerCase().includes(q) ||
        (f.remediation || "").toLowerCase().includes(q)
      );
    });

    if (filtered.length === 0) {
      const empty = el("div", "card");
      empty.appendChild(el("p", "muted", "No matching issues found. Everything looks clean under this filter."));
      host.appendChild(empty);
      return;
    }

    for (const f of filtered) {
      const u = humanUrgency(f.severity);
      const card = el("div", "simple-issue-card");

      const head = el("div", "simple-issue-head");
      const badges = el("div", "simple-issue-badges");
      badges.appendChild(el("span", `sev-pill ${u.pillClass}`, u.label));
      badges.appendChild(el("span", "badge", humanLayerName(f.layer)));
      head.appendChild(badges);

      const askBtn = el("button", "btn btn-ghost", "Ask Raksa");
      askBtn.type = "button";
      askBtn.addEventListener("click", () => {
        switchView("simple-ask");
        askSimpleAssistant(`Explain in simple terms how to fix ${f.rule_id} (${f.title}) on ${f.target}`);
      });
      head.appendChild(askBtn);
      card.appendChild(head);

      card.appendChild(el("h3", "simple-issue-title", f.title || f.rule_id));
      card.appendChild(el("div", "simple-issue-target", `Location: ${f.target || "."}`));

      const fixBox = el("div", "fix-callout");
      fixBox.appendChild(el("div", "fix-callout-label", "Recommended Fix"));
      fixBox.appendChild(el("div", "fix-callout-text", f.remediation || f.description || "Review this configuration and apply least-privilege defaults."));
      card.appendChild(fixBox);

      const det = document.createElement("details");
      det.className = "tech-details";
      const sum = document.createElement("summary");
      sum.textContent = `Technical Details (${f.rule_id || "info"})`;
      det.appendChild(sum);

      const meta = el("div", "drawer-kv");
      meta.appendChild(el("div", "", `Rule ID: ${f.rule_id} | Severity: ${f.severity} | Layer: ${f.layer}`));
      if (f.mitre_d3fend) meta.appendChild(el("div", "", `MITRE D3FEND: ${f.mitre_d3fend}`));
      if (f.compliance && f.compliance.length) meta.appendChild(el("div", "", `Controls: ${f.compliance.join(", ")}`));
      det.appendChild(meta);

      const pre = el("pre", "", JSON.stringify(f.evidence || { description: f.description }, null, 2));
      det.appendChild(pre);

      const waiveBtn = el("button", "btn btn-ghost", "Dismiss / Add Waiver");
      waiveBtn.type = "button";
      waiveBtn.addEventListener("click", () => openWaiverModal(f));
      det.appendChild(waiveBtn);

      card.appendChild(det);
      host.appendChild(card);
    }
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

      const layerScore = Math.max(0, Math.min(100, Number(ex.posture ? ex.posture.score : 100)));
      const scoreText = `${layerScore}/100 (${ex.posture ? ex.posture.grade : "A+"})`;
      card.appendChild(el("div", "layer-card-score", scoreText));

      const barSvg = svgEl("svg", { class: "mini-bar-svg", viewBox: "0 0 100 6", preserveAspectRatio: "none" });
      barSvg.appendChild(svgEl("rect", { x: "0", y: "0", width: "100", height: "6", rx: "3", class: "mini-bar-track" }));
      const fillCls = layerScore >= 90 ? "mini-bar-fill-good" : layerScore >= 70 ? "mini-bar-fill-warn" : "mini-bar-fill-bad";
      barSvg.appendChild(svgEl("rect", { x: "0", y: "0", width: String(layerScore), height: "6", rx: "3", class: fillCls }));
      card.appendChild(barSvg);

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
      showToast(`Audit complete: ${rep.posture.score}/100 (${rep.posture.grade})`);
    } catch (err) {
      appendTelemetry("error", `Scan failed: ${err.message}`);
      showToast(`Scan failed: ${err.message}`);
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
      showToast(`Playbook '${name}': ${rep.posture.score}/100 (${rep.posture.grade})`);
    } catch (err) {
      appendTelemetry("error", `Playbook '${name}' error: ${err.message}`);
      showToast(`Playbook '${name}' error: ${err.message}`);
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
      { label: "Mode: Switch Simple / Pro", hint: "mode", fn: () => applyMode(state.mode === "pro" ? "simple" : "pro", true) },
      { label: "Theme: Toggle Dark / Light Glass", hint: "theme", fn: () => toggleTheme() },
      { label: "View: User Guide", hint: "guide", fn: () => switchView("guide") },
      { label: "Assistant: Prioritize Top Risks", hint: "assistant", fn: () => askAssistant("Prioritize top risks") },
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
    const themeBtn = document.getElementById("btn-theme-toggle");
    if (themeBtn) themeBtn.addEventListener("click", toggleTheme);
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
      showToast("Copied unified patch diff to clipboard.");
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
      showToast("Copied 61-tool MCP config to clipboard.");
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
        showToast("Saved fail-closed waiver to .raksa.yml.");
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

    document.querySelectorAll("#mode-switch .mode-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const nextMode = btn.dataset.modeOpt || "simple";
        applyMode(nextMode, true);
        showToast(`Switched to ${nextMode === "pro" ? "Pro Workbench" : "Simple Mode"}`);
      });
    });

    const swProBtn = document.getElementById("btn-switch-to-pro");
    if (swProBtn) {
      swProBtn.addEventListener("click", () => {
        applyMode("pro", true, "overview");
        showToast("Switched to Pro Workbench");
      });
    }

    const simpleScanBtn = document.getElementById("btn-simple-scan");
    if (simpleScanBtn) simpleScanBtn.addEventListener("click", () => runScan({ profile: "full" }));

    const simpleGotoIssues = document.getElementById("btn-simple-goto-issues");
    if (simpleGotoIssues) simpleGotoIssues.addEventListener("click", () => switchView("simple-issues"));

    const simpleSeeAll = document.getElementById("btn-simple-see-all");
    if (simpleSeeAll) simpleSeeAll.addEventListener("click", () => switchView("simple-issues"));

    const simpleGotoAsk = document.getElementById("btn-simple-goto-ask");
    if (simpleGotoAsk) simpleGotoAsk.addEventListener("click", () => switchView("simple-ask"));

    document.querySelectorAll(".quick-check-card").forEach((card) => {
      card.addEventListener("click", () => {
        const prof = card.dataset.quickProfile || "full";
        runScan({ profile: prof });
      });
    });

    const simpleSearch = document.getElementById("simple-issues-search");
    if (simpleSearch) simpleSearch.addEventListener("input", renderSimpleIssues);

    document.querySelectorAll("#simple-urgency-pills .pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.simpleUrgencyFilter = btn.dataset.urgency || "";
        document.querySelectorAll("#simple-urgency-pills .pill").forEach((p) => p.classList.toggle("active", p === btn));
        renderSimpleIssues();
      });
    });

    const simpleAiSettingsBtn = document.getElementById("btn-simple-ai-settings");
    const simpleAiDrawer = document.getElementById("simple-ai-settings-drawer");
    if (simpleAiSettingsBtn && simpleAiDrawer) {
      simpleAiSettingsBtn.addEventListener("click", () => simpleAiDrawer.classList.toggle("hidden"));
    }

    const sModeSel = document.getElementById("simple-assistant-mode");
    const pModeSel = document.getElementById("assistant-mode");
    if (sModeSel && pModeSel) {
      sModeSel.addEventListener("change", () => { pModeSel.value = sModeSel.value; });
      pModeSel.addEventListener("change", () => { sModeSel.value = pModeSel.value; });
    }
    const sModelInp = document.getElementById("simple-assistant-model");
    const pModelInp = document.getElementById("assistant-model");
    if (sModelInp && pModelInp) {
      sModelInp.addEventListener("input", () => { pModelInp.value = sModelInp.value; });
      pModelInp.addEventListener("input", () => { sModelInp.value = pModelInp.value; });
    }

    document.querySelectorAll(".simple-ask-chip").forEach((btn) => {
      btn.addEventListener("click", () => askSimpleAssistant(btn.dataset.prompt || ""));
    });
    const simpleAskForm = document.getElementById("simple-ask-form");
    if (simpleAskForm) {
      simpleAskForm.addEventListener("submit", (ev) => {
        ev.preventDefault();
        const inp = document.getElementById("simple-ask-input");
        const text = inp.value.trim();
        if (!text) return;
        inp.value = "";
        askSimpleAssistant(text);
      });
    }

    const guideStart = document.getElementById("btn-guide-start");
    if (guideStart) {
      guideStart.addEventListener("click", () => {
        switchView(state.mode === "pro" ? "overview" : "simple-home");
      });
    }
    const guideSimple = document.getElementById("btn-guide-simple");
    if (guideSimple) guideSimple.addEventListener("click", () => applyMode("simple", true, "simple-home"));
    const guidePro = document.getElementById("btn-guide-pro");
    if (guidePro) guidePro.addEventListener("click", () => applyMode("pro", true, "overview"));

    document.querySelectorAll(".assistant-chip").forEach((btn) => {
      btn.addEventListener("click", () => askAssistant(btn.dataset.prompt || ""));
    });
    document.getElementById("assistant-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      const inp = document.getElementById("assistant-input");
      const text = inp.value.trim();
      if (!text) return;
      inp.value = "";
      askAssistant(text);
    });
  }

  function appendChatMessageTo(hostId, roleLabel, bodyText, isUser, toolCalls, citations, collapseTools) {
    const host = document.getElementById(hostId);
    if (!host) return;
    const box = el("div", `chat-msg ${isUser ? "chat-user" : "chat-bot"}`);
    box.appendChild(el("div", "chat-role", roleLabel));
    const body = el("div", "chat-body");
    for (const rawLine of String(bodyText || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      const isBullet = /^(-|\*|\d+\.)\s+/.test(line);
      body.appendChild(el("div", isBullet ? "chat-line chat-line-bullet" : "chat-line", line));
    }
    box.appendChild(body);

    const hasTools = toolCalls && toolCalls.length > 0;
    const hasCites = citations && citations.length > 0;
    if (hasTools || hasCites) {
      let targetContainer = box;
      if (collapseTools) {
        const det = document.createElement("details");
        det.className = "tool-checks-details";
        const sum = document.createElement("summary");
        sum.textContent = `Verified with ${hasTools ? toolCalls.length : 0} read-only check(s)`;
        det.appendChild(sum);
        box.appendChild(det);
        targetContainer = det;
      }

      if (hasTools) {
        const wrap = el("div", "tool-cards-wrap");
        for (const tc of toolCalls) {
          const card = el("div", "tool-card");
          card.appendChild(el("code", "", tc.name));
          card.appendChild(el("span", "muted", ` [${tc.status}] - ${tc.summary}`));
          wrap.appendChild(card);
        }
        targetContainer.appendChild(wrap);
      }

      if (hasCites) {
        const cwrap = el("div", "citations-wrap");
        for (const cite of citations) {
          cwrap.appendChild(el("span", "badge", cite));
        }
        targetContainer.appendChild(cwrap);
      }
    }

    host.appendChild(box);
    host.scrollTop = host.scrollHeight;
  }

  function appendChatMessage(roleLabel, bodyText, isUser, toolCalls, citations) {
    appendChatMessageTo("assistant-chat", roleLabel, bodyText, isUser, toolCalls, citations, false);
  }

  async function askAssistant(promptText) {
    if (!promptText) return;
    document.querySelectorAll(".rtab").forEach((t) => t.classList.toggle("active", t.dataset.rtab === "assistant"));
    document.querySelectorAll(".right-pane").forEach((p) => p.classList.toggle("active", p.id === "rtab-assistant"));

    const mode = document.getElementById("assistant-mode").value || "local";
    const model = document.getElementById("assistant-model").value.trim();
    appendChatMessage("Operator", promptText, true);
    try {
      const res = await apiJSON("/api/v1/assistant/chat", {
        method: "POST",
        body: JSON.stringify({ prompt: promptText, mode, model }),
      });
      const label = `Raksa Assistant (${res.mode}${res.model ? " / " + res.model : ""})`;
      appendChatMessage(label, res.reply, false, res.tool_calls || [], res.citations || []);
    } catch (err) {
      appendChatMessage("Assistant Error", err.message, false);
    }
  }

  async function askSimpleAssistant(promptText) {
    if (!promptText) return;
    const modeSel = document.getElementById("simple-assistant-mode");
    const modelInp = document.getElementById("simple-assistant-model");
    const mode = modeSel ? modeSel.value : "local";
    const model = modelInp ? modelInp.value.trim() : "";

    appendChatMessageTo("simple-chat-host", "You", promptText, true, null, null, true);
    try {
      const res = await apiJSON("/api/v1/assistant/chat", {
        method: "POST",
        body: JSON.stringify({ prompt: promptText, mode, model }),
      });
      appendChatMessageTo("simple-chat-host", "Raksa Assistant", res.reply, false, res.tool_calls || [], res.citations || [], true);
    } catch (err) {
      appendChatMessageTo("simple-chat-host", "Raksa Assistant", err.message, false, null, null, true);
    }
  }

  async function init() {
    initTheme();
    initMode();
    wireEvents();
    renderTelemetryFlow();
    connectSSE();
    try {
      const [status, doc, rep, pbs, mat, hist, mcp, astCfg] = await Promise.all([
        apiJSON("/api/v1/status"),
        apiJSON("/api/v1/doctor"),
        apiJSON("/api/v1/report"),
        apiJSON("/api/v1/playbooks"),
        apiJSON("/api/v1/attack-matrix"),
        apiJSON("/api/v1/history"),
        apiJSON("/api/v1/mcp-catalog"),
        apiJSON("/api/v1/assistant/config"),
      ]);
      state.status = status;
      document.getElementById("ui-version").textContent = `v${status.version || "0.3.1"}`;
      document.getElementById("ui-edition").textContent = String((status.edition && status.edition.edition) || "OSS").toUpperCase();
      document.getElementById("target-input").value = status.workspace || ".";
      if (astCfg && astCfg.default_model) {
        document.getElementById("assistant-model").placeholder = `Model (${astCfg.default_model})`;
        const sModel = document.getElementById("simple-assistant-model");
        if (sModel) sModel.placeholder = `Model (${astCfg.default_model})`;
      }
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
