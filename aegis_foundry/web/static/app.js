/* Aegis Foundry console — vanilla JS, no frameworks, no external assets.
 * Pinned API: GET /api/runs, /api/runs/{id}, /api/runs/{id}/flight,
 * /api/runs/{id}/evidence, /api/pending, /api/pipeline/status;
 * POST /api/pipeline/start, /api/approve.
 *
 * The console is a multi-view single page: a left nav switches between nine
 * feature views, all bound to one selected run's state.json + flight log.
 */
"use strict";

(() => {

  // ============================================================== constants
  const AGENTS = [
    "intel-scout", "coverage-cartographer", "detection-author",
    "backtest-engineer", "noise-forecaster", "tuning-optimizer",
    "governor", "deployer", "verifier",
  ];

  const AGENT_LABELS = {
    "intel-scout": "Intel Scout", "coverage-cartographer": "Cartographer",
    "detection-author": "Author", "backtest-engineer": "Backtest",
    "noise-forecaster": "Forecaster", "tuning-optimizer": "Tuner",
    "governor": "Governor", "deployer": "Deployer", "verifier": "Verifier",
  };

  const AGENT_SHORT = {
    "orchestrator": "orch", "intel-scout": "intel", "coverage-cartographer": "cartog",
    "detection-author": "author", "backtest-engineer": "backtest",
    "noise-forecaster": "forecast", "tuning-optimizer": "tuner",
    "governor": "governor", "deployer": "deployer", "verifier": "verifier",
  };

  // Per-agent metadata for the Pipeline view's agent cards.
  const AGENT_META = {
    "intel-scout": { n: "01", role: "Ingests advisories; extracts ATT&CK techniques" },
    "coverage-cartographer": { n: "02", role: "Maps live rules; finds the coverage gap" },
    "detection-author": { n: "03", role: "Drafts SPL; self-corrects against validation" },
    "backtest-engineer": { n: "04", role: "Replays labeled history; measures recall & precision" },
    "noise-forecaster": { n: "05", role: "Prices future alert volume with CDTSM" },
    "tuning-optimizer": { n: "06", role: "Tightens the rule until noise fits budget" },
    "governor": { n: "07", role: "Runs policy checks; builds the evidence pack; gates deploy" },
    "deployer": { n: "08", role: "Ships a native saved search with a rollback token" },
    "verifier": { n: "09", role: "Watches week one; confirms drift stays in band" },
  };

  const STAGE_TO_AGENT = {
    intel: "intel-scout", coverage: "coverage-cartographer",
    author: "detection-author", backtest: "backtest-engineer",
    forecast: "noise-forecaster", tune: "tuning-optimizer",
    govern: "governor", deploy: "deployer", verify: "verifier",
  };

  const LOOP_ACTIONS = {
    "backtest-engineer": ["backtest_completed", "backtest_failed"],
    "noise-forecaster": ["noise_forecast"],
    "tuning-optimizer": ["rule_tuned", "tuning_skipped"],
  };

  const TECH_CATALOG = {
    "T1059": ["Command and Scripting Interpreter", "Execution"],
    "T1059.001": ["PowerShell", "Execution"],
    "T1003": ["OS Credential Dumping", "Credential Access"],
    "T1003.001": ["LSASS Memory", "Credential Access"],
    "T1047": ["Windows Management Instrumentation", "Execution"],
    "T1053.005": ["Scheduled Task", "Execution"],
    "T1071.001": ["Web Protocols", "Command and Control"],
    "T1078": ["Valid Accounts", "Defense Evasion"],
    "T1110": ["Brute Force", "Credential Access"],
    "T1136.001": ["Local Account", "Persistence"],
    "T1566.001": ["Spearphishing Attachment", "Initial Access"],
  };

  const PRIORITY_KEYS = [
    "name", "rule_name", "title", "technique_id", "technique", "tactic",
    "decision", "approver", "mode", "action", "version", "rule_version",
    "predicted_weekly", "weekly_rate", "recall", "precision", "total_hits",
    "within_budget", "reason", "severity", "saved_search_name", "gap_id", "rule_id",
  ];

  const VIEW_META = {
    overview:    ["Command Center", "Live mission overview of the detection-engineering swarm"],
    pipeline:    ["Pipeline", "Nine governed agents, from intel to verified deployment"],
    coverage:    ["ATT&CK Coverage", "Gaps close themselves — cells flip to FORGED BY AEGIS"],
    noise:       ["Noise Lab", "Backtest, forecast, and the budget gate that blocks loud rules"],
    governance:  ["Governance", "Evidence-pack review and the human approval gate"],
    deployments: ["Deployments", "Native saved searches with rollback and post-deploy drift"],
    flight:      ["Flight Recorder", "Every agent action — immutable and Splunk-ingestible"],
    models:      ["AI Models", "The Cisco + Splunk model stack powering the swarm"],
    history:     ["Run History", "Every pipeline run and its headline outcome"],
  };

  const MODELS = [
    { name: "Foundation-Sec-1.1-8B", vendor: "Cisco Foundation AI",
      tag: "Security LLM — MITRE technique mapping & analyst rationale",
      powers: ["intel-scout", "governor"], accent: "violet" },
    { name: "Cisco Deep Time Series Model", vendor: "Splunk Cloud · AI Toolkit",
      tag: "Zero-shot alert-volume forecasting · | apply CDTSM",
      powers: ["noise-forecaster"], accent: "cyan", live: true },
    { name: "gpt-oss-120b / 20b", vendor: "Open weights · | ai command",
      tag: "SPL authoring and false-positive tuning",
      powers: ["detection-author", "tuning-optimizer"], accent: "brand" },
    { name: "Splunk MCP Server", vendor: "JSON-RPC 2.0 · token auth",
      tag: "Search execution, SPL validation, saved-search admin",
      powers: ["backtest-engineer", "deployer"], accent: "emerald" },
    { name: "Splunk AI Assistant (SAIA)", vendor: "saia_generate_spl",
      tag: "Natural-language → SPL generation tool",
      powers: ["detection-author"], accent: "gold" },
    { name: "EWMA Seasonal Fallback", vendor: "Air-gapped · deterministic",
      tag: "Honest forecasting when hosted models are offline",
      powers: ["noise-forecaster"], accent: "rose" },
  ];

  // ================================================================== state
  const S = {
    running: false, stage: null, lastStage: null, activeRunId: null,
    selectedRunId: null,        // explicit run pin; null = follow active/newest
    view: "overview",
    runs: [], runState: null, flight: [], lastEvents: [],
    pending: [], pendingKey: null,
    evidence: [], evidenceRunId: null,
    renderedStateKey: "", flightFilter: "",
  };
  let pollTimer = null, lastFlightKey = "";
  const stepEls = { overview: [], full: [] };

  const $ = (id) => document.getElementById(id);
  const qsa = (sel) => Array.from(document.querySelectorAll(sel));

  // ================================================================== utils
  const escapeHtml = (s) => String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  const fmtNum = (v) => (v == null || isNaN(Number(v)))
    ? "n/a" : String(Number(v).toFixed(1)).replace(/\.0$/, "");

  const fmtPct = (v) => (v == null || isNaN(Number(v))) ? "—" : `${Math.round(Number(v) * 100)}%`;

  const emptyBox = (msg) => `<div class="empty">${escapeHtml(msg)}</div>`;

  async function fetchJSON(url, options) {
    const res = await fetch(url, options);
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      const err = new Error(body && body.error ? body.error : `${res.status} ${res.statusText}`);
      err.status = res.status;
      throw err;
    }
    return body;
  }

  // ================================================================ toasts
  const toastTimes = {};
  function toast(msg, kind = "error") {
    const t = document.createElement("div");
    t.className = `toast toast-${kind}`;
    t.textContent = msg;
    $("toasts").appendChild(t);
    requestAnimationFrame(() => t.classList.add("show"));
    setTimeout(() => { t.classList.remove("show"); setTimeout(() => t.remove(), 300); }, 4200);
  }
  function toastOnce(key, msg, kind) {
    if ((toastTimes[key] || 0) + 10000 > Date.now()) return;
    toastTimes[key] = Date.now();
    toast(msg, kind);
  }

  // =============================================== minimal markdown renderer
  const inlineMd = (raw) => escapeHtml(raw)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");

  function mdTable(rows) {
    const cells = (row) => row.replace(/^\s*\|/, "").replace(/\|\s*$/, "")
      .split("|").map((c) => c.trim());
    const head = cells(rows[0]);
    let body = rows.slice(1);
    if (body.length && cells(body[0]).every((c) => /^:?-+:?$/.test(c))) body = body.slice(1);
    const ths = head.map((c) => `<th>${inlineMd(c)}</th>`).join("");
    const trs = body.map((row) =>
      `<tr>${cells(row).map((c) => `<td>${inlineMd(c)}</td>`).join("")}</tr>`).join("");
    return `<table class="md-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
  }

  function renderMarkdown(md) {
    const lines = String(md || "").split(/\r?\n/);
    const html = [];
    let para = [], inList = false, i = 0;
    const flushPara = () => { if (para.length) { html.push(`<p>${para.map(inlineMd).join(" ")}</p>`); para = []; } };
    const closeList = () => { if (inList) { html.push("</ul>"); inList = false; } };
    while (i < lines.length) {
      const line = lines[i];
      const fence = line.match(/^```(\w*)\s*$/);
      if (fence) {
        flushPara(); closeList();
        const lang = fence[1].toLowerCase(), buf = [];
        i += 1;
        while (i < lines.length && !/^```\s*$/.test(lines[i])) { buf.push(lines[i]); i += 1; }
        i += 1;
        if (lang === "diff") {
          const body = buf.map((l) => {
            const esc = escapeHtml(l);
            if (/^\+/.test(l)) return `<span class="diff-add">${esc}</span>`;
            if (/^-/.test(l)) return `<span class="diff-del">${esc}</span>`;
            return `<span>${esc}</span>`;
          }).join("");
          html.push(`<pre class="code code-diff">${body}</pre>`);
        } else {
          html.push(`<pre class="code code-${lang || "plain"}">${escapeHtml(buf.join("\n"))}</pre>`);
        }
        continue;
      }
      const head = line.match(/^(#{1,3})\s+(.*)$/);
      if (head) { flushPara(); closeList(); const lvl = head[1].length + 3;
        html.push(`<h${lvl}>${inlineMd(head[2])}</h${lvl}>`); i += 1; continue; }
      if (/^\s*\|.*\|\s*$/.test(line)) {
        flushPara(); closeList();
        const rows = [];
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { rows.push(lines[i]); i += 1; }
        html.push(mdTable(rows)); continue;
      }
      const li = line.match(/^\s*-\s+(.*)$/);
      if (li) {
        flushPara();
        if (!inList) { html.push("<ul>"); inList = true; }
        const cb = li[1].match(/^\[( |x|X)\]\s+(.*)$/);
        if (cb) {
          const on = cb[1].toLowerCase() === "x";
          html.push(`<li class="check-item"><span class="cbx${on ? " on" : ""}">${on ? "✓" : ""}</span>${inlineMd(cb[2])}</li>`);
        } else { html.push(`<li>${inlineMd(li[1])}</li>`); }
        i += 1; continue;
      }
      if (/^\s*$/.test(line)) { flushPara(); closeList(); i += 1; continue; }
      para.push(line); i += 1;
    }
    flushPara(); closeList();
    return html.join("\n");
  }

  // ============================================================ run helpers
  function effectiveRunId() {
    if (S.selectedRunId) return S.selectedRunId;
    if (S.running && S.activeRunId) return S.activeRunId;
    return S.runs[0] ? S.runs[0].run_id : null;
  }
  function currentRunSummary() {
    const rid = effectiveRunId();
    return S.runs.find((r) => r.run_id === rid) || S.runs[0] || null;
  }
  function currentHeadline() {
    const r = currentRunSummary();
    return r && r.headline ? r.headline : {};
  }
  function firstRuleId(st) {
    const rules = (st && st.rules) || {};
    return Object.keys(rules)[0] || null;
  }
  function stateKey(st) {
    if (!st) return "none";
    return [st.run_id, st.stage,
      Object.keys(st.rules || {}).length,
      Object.keys(st.deployments || {}).length,
      Object.keys(st.verifications || {}).length,
      Object.keys(st.decisions || {}).length,
      (st.audit || []).length].join(":");
  }

  // ============================================================ view router
  function setView(view) {
    if (!VIEW_META[view]) view = "overview";
    S.view = view;
    qsa(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
    qsa(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === view));
    const meta = VIEW_META[view];
    $("view-title").textContent = meta[0].replace("ATT&CK", "ATT&CK");
    $("view-caption").textContent = meta[1];
    if (location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`);
    document.body.classList.remove("nav-open");
    renderActiveView();
    window.scrollTo({ top: 0, behavior: "auto" });
  }

  function wireNav() {
    qsa(".nav-item").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
    const burger = $("burger");
    if (burger) burger.addEventListener("click", () => document.body.classList.toggle("nav-open"));
    window.addEventListener("hashchange", () => setView(location.hash.slice(1)));
  }

  // Render the heavy/per-run views (guarded by state changes elsewhere).
  function renderActiveView() {
    switch (S.view) {
      case "noise": renderNoise(); renderBacktestStats(); renderForecastChart(); break;
      case "governance": renderPending(true); renderPolicyGrid(); renderEvidencePacks(); break;
      case "deployments": renderDeployments(); break;
      case "pipeline": renderStepper(); renderAgentGrid(); break;
      case "coverage": renderCoverage(); renderIntel(); break;
      case "models": renderModels(); break;
      case "history": renderHistory(); break;
      case "overview": renderKPIs(); renderStepper(); renderStory(); renderFeed(); renderNoise(); break;
      default: break;
    }
  }

  // ================================================================ topbar
  function renderTopbar() {
    const pill = $("mode-pill");
    pill.textContent = S.running ? "RUNNING" : "IDLE";
    pill.className = `pill ${S.running ? "pill-run" : "pill-idle"}`;
    const stageEl = $("stage-indicator");
    stageEl.hidden = !(S.running && S.stage);
    if (S.running && S.stage) stageEl.textContent = `stage: ${S.stage}`;
    $("start-run").disabled = S.running;
    $("start-run").classList.toggle("running", S.running);
    const live = $("flight-live"); if (live) live.hidden = !S.running;
    const fdot = $("nav-flight-dot"); if (fdot) fdot.hidden = !S.running;
    const sb = $("nav-stage-badge");
    if (sb) { sb.hidden = !(S.running && S.stage); if (S.running && S.stage) sb.textContent = S.stage; }
    const ab = $("nav-approval-badge");
    if (ab) { ab.hidden = !S.pending.length; if (S.pending.length) ab.textContent = String(S.pending.length); }
  }

  function renderRunSelect() {
    const sel = $("run-select");
    if (!sel) return;
    const want = S.selectedRunId || "";
    const opts = ['<option value="">live · newest</option>'];
    for (const r of S.runs) {
      const lbl = `${r.run_id}${r.stage ? "  ·  " + r.stage : ""}`;
      opts.push(`<option value="${escapeHtml(r.run_id)}">${escapeHtml(lbl)}</option>`);
    }
    const joined = opts.join("");
    if (sel.dataset.sig !== joined + "|" + want) {
      sel.innerHTML = joined;
      sel.value = want;
      sel.dataset.sig = joined + "|" + want;
    }
  }

  // =============================================================== KPI grid
  function kpiCard(accent, label, big, sub, extra) {
    return `<div class="kpi kpi-${accent}">` +
      `<div class="kpi-label">${escapeHtml(label)}</div>` +
      `<div class="kpi-big">${big}</div>` +
      `<div class="kpi-sub">${sub}</div>` +
      (extra ? `<div class="kpi-extra">${extra}</div>` : "") +
      `</div>`;
  }

  function renderKPIs() {
    const grid = $("kpi-grid");
    if (!grid) return;
    const st = S.runState, h = currentHeadline(), rid = firstRuleId(st);
    const cards = [];

    // Noise reduction
    if (h.v1_weekly != null && h.final_weekly != null) {
      const cut = h.v1_weekly > 0 ? (1 - h.final_weekly / h.v1_weekly) * 100 : 0;
      cards.push(kpiCard("emerald", "Alert noise / week",
        `${fmtNum(h.v1_weekly)} <span class="kpi-arr">→</span> ${fmtNum(h.final_weekly)}`,
        cut > 0 ? `<span class="kpi-down">▼ ${cut.toFixed(1)}%</span> forecast reduction` : "forecast vs backtest"));
    } else {
      cards.push(kpiCard("emerald", "Alert noise / week", "—", "run the pipeline to measure"));
    }

    // Recall
    cards.push(kpiCard("cyan", "True positives",
      h.recall != null ? fmtPct(h.recall) : "—",
      h.recall != null ? "retained through tuning" : "awaiting backtest"));

    // Drift / verification
    let drift = null, band = null;
    if (st && rid && st.verifications && st.verifications[rid]) {
      drift = st.verifications[rid].drift_ratio;
      band = st.verifications[rid].within_forecast_band;
    }
    cards.push(kpiCard("violet", "Forecast drift",
      drift != null ? Number(drift).toFixed(2) : "—",
      drift != null ? (band ? "within 90% band ✓" : "outside band ✗") : "verified post-deploy"));

    // Policy gate
    let passed = null, total = null;
    if (st && rid && st.decisions && st.decisions[rid]) {
      const checks = st.decisions[rid].policy_checks || [];
      total = checks.length; passed = checks.filter((c) => c.passed).length;
    }
    cards.push(kpiCard("gold", "Policy gate",
      total != null ? `${passed}/${total}` : "—",
      total != null ? "checks passed" : "governed before deploy"));

    // Coverage forged
    const forged = st ? deriveCoverage(st).filter((c) => c.status === "forged").length : 0;
    const gaps = h.gaps != null ? h.gaps : (st ? (st.gaps || []).length : 0);
    cards.push(kpiCard("brand", "Coverage forged",
      st ? String(forged) : "—",
      st ? `of ${gaps} gap${gaps === 1 ? "" : "s"} this run` : "ATT&CK techniques"));

    // Stage / status
    const stage = (st && st.stage) || (S.running ? S.stage : null);
    cards.push(kpiCard("cyan", "Pipeline stage",
      stage ? `<span class="kpi-stage">${escapeHtml(stage)}</span>` : "idle",
      S.running ? "agents in flight" : (stage === "done" ? "run complete" : "ready")));

    grid.innerHTML = cards.join("");
  }

  // ================================================================ stepper
  function buildStepper(containerId, key) {
    const ol = $(containerId);
    if (!ol) return;
    ol.innerHTML = "";
    stepEls[key] = [];
    for (const agent of AGENTS) {
      const li = document.createElement("li");
      li.className = "step";
      li.title = agent;
      li.innerHTML = `<span class="pass-badge" hidden></span><span class="step-dot">` +
        `<svg class="step-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4L19 7"/></svg>` +
        `</span><span class="step-name">${escapeHtml(AGENT_LABELS[agent] || agent)}</span>`;
      ol.appendChild(li);
      stepEls[key].push(li);
    }
  }

  function passCount(events, agent) {
    const actions = LOOP_ACTIONS[agent];
    if (!actions) return 1;
    const perRule = {}; let max = 1;
    for (const e of events) {
      if (!actions.includes(e.action)) continue;
      const key = (e.detail && e.detail.rule_id) || "";
      perRule[key] = (perRule[key] || 0) + 1;
      if (perRule[key] > max) max = perRule[key];
    }
    return max;
  }

  function renderStepper() {
    const byAgent = {};
    for (const e of S.flight) (byAgent[e.agent] = byAgent[e.agent] || []).push(e);
    const activeAgent = S.running ? (STAGE_TO_AGENT[S.stage] || null) : null;
    for (const key of ["overview", "full"]) {
      const arr = stepEls[key];
      AGENTS.forEach((agent, idx) => {
        const li = arr[idx]; if (!li) return;
        li.classList.toggle("done", !!byAgent[agent]);
        li.classList.toggle("active", agent === activeAgent);
        const badge = li.querySelector(".pass-badge");
        const n = passCount(byAgent[agent] || [], agent);
        badge.hidden = n < 2;
        if (n >= 2) badge.textContent = `pass ${n}`;
      });
    }
    const note = $("ov-stage-note");
    if (note) {
      const stage = (S.runState && S.runState.stage) || S.stage;
      note.textContent = S.running ? `Stage in flight: ${stage || "…"}`
        : stage === "done" ? "Run complete — all nine agents reported." : "";
    }
    const ovRun = $("ov-pipeline-run"); if (ovRun) ovRun.textContent = effectiveRunId() || "";
    const plRun = $("pipeline-run"); if (plRun) plRun.textContent = effectiveRunId() || "";
  }

  // ============================================================= agent grid
  function latestEventFor(agent) {
    let best = null;
    for (const e of S.flight) if (e.agent === agent && (!best || (e.seq || 0) > (best.seq || 0))) best = e;
    return best;
  }

  function renderAgentGrid() {
    const grid = $("agent-grid");
    if (!grid) return;
    const byAgent = {};
    for (const e of S.flight) (byAgent[e.agent] = byAgent[e.agent] || []).push(e);
    const activeAgent = S.running ? (STAGE_TO_AGENT[S.stage] || null) : null;
    grid.innerHTML = AGENTS.map((agent) => {
      const meta = AGENT_META[agent] || { n: "", role: "" };
      const ran = !!byAgent[agent];
      const status = agent === activeAgent ? "active" : ran ? "done" : "idle";
      const last = latestEventFor(agent);
      const lastLine = last
        ? `<div class="ag-last"><span class="ag-act">${escapeHtml(String(last.action || "").replace(/_/g, " "))}</span>` +
          `<span class="ag-detail">${escapeHtml(summarizeDetail(last.detail))}</span></div>`
        : `<div class="ag-last ag-idle-note">awaiting dispatch</div>`;
      const statusLabel = status === "active" ? "running" : status === "done" ? "complete" : "idle";
      return `<article class="agent-card ag-${status}">` +
        `<div class="ag-top"><span class="ag-num mono">${meta.n}</span>` +
        `<span class="ag-status ag-status-${status}">${statusLabel}</span></div>` +
        `<h3 class="ag-name mono">${escapeHtml(agent)}</h3>` +
        `<p class="ag-role">${escapeHtml(meta.role)}</p>${lastLine}</article>`;
    }).join("");
  }

  // =============================================================== coverage
  function harvestNames(audit) {
    const found = {};
    for (const evt of audit) {
      const d = evt.detail;
      if (!d || typeof d !== "object") continue;
      const tid = d.technique_id || d.technique;
      if (typeof tid !== "string" || !tid.startsWith("T")) continue;
      const prev = found[tid] || ["", ""];
      found[tid] = [String(d.technique_name || "") || prev[0], String(d.tactic || "") || prev[1]];
    }
    return found;
  }

  function deriveCoverage(st) {
    const order = [], info = {};
    const rank = { covered: 0, gap: 1, forged: 2 };
    const put = (tid, status) => {
      if (!info[tid]) { info[tid] = { status: "covered", name: "", tactic: "", via: "" }; order.push(tid); }
      if (rank[status] > rank[info[tid].status]) info[tid].status = status;
    };
    const audit = st.audit || [];
    for (const evt of audit) {
      const d = evt.detail || {};
      if (evt.action === "coverage_mapped" && d.matrix && typeof d.matrix === "object") {
        for (const tid of Object.keys(d.matrix)) put(tid, d.matrix[tid] === "gap" ? "gap" : "covered");
      } else if (evt.action === "gap_identified" && typeof d.technique_id === "string") {
        put(d.technique_id, "gap");
        if (d.technique_name) info[d.technique_id].name = d.technique_name;
        if (d.tactic) info[d.technique_id].tactic = d.tactic;
      }
    }
    const rules = st.rules || {};
    for (const [rid, dep] of Object.entries(st.deployments || {})) {
      if (!dep || dep.rolled_back) continue;
      const rule = rules[rid] || {};
      for (const tid of rule.mitre_techniques || []) {
        put(tid, "forged");
        info[tid].via = String(dep.saved_search_name || rule.name || rid) + (dep.mode ? ` (${dep.mode})` : "");
      }
    }
    const harvested = harvestNames(audit);
    for (const tid of order) {
      const it = info[tid], hv = harvested[tid] || ["", ""], c = TECH_CATALOG[tid] || ["", ""];
      it.name = it.name || hv[0] || c[0] || "";
      it.tactic = it.tactic || hv[1] || c[1] || "";
    }
    order.sort((a, b) => (rank[info[b].status] - rank[info[a].status]) || a.localeCompare(b));
    return order.map((tid) => ({ tid, ...info[tid] }));
  }

  function coverageCard(e) {
    const badge = e.status === "forged" ? '<span class="badge badge-forged">FORGED BY AEGIS</span>'
      : e.status === "gap" ? '<span class="badge badge-gap">GAP</span>'
      : '<span class="badge badge-covered">COVERED</span>';
    const via = (e.status === "forged" && e.via)
      ? `<div class="cov-via" title="${escapeHtml(e.via)}">${escapeHtml(e.via)}</div>` : "";
    return `<div class="cov-card cov-${e.status}">` +
      `<div class="cov-head"><span class="cov-tid">${escapeHtml(e.tid)}</span>${badge}</div>` +
      `<div class="cov-name">${escapeHtml(e.name || "Unknown technique")}</div>` +
      `<div class="cov-tactic">${escapeHtml(e.tactic || "—")}</div>${via}</div>`;
  }

  function renderCoverage() {
    const wrap = $("coverage-cards");
    if (!wrap) return;
    if (!S.runState) { wrap.innerHTML = emptyBox("No runs yet — press Start run to map ATT&CK coverage.");
      const lg = $("cov-legend"); if (lg) lg.innerHTML = ""; return; }
    const entries = deriveCoverage(S.runState);
    wrap.innerHTML = entries.length ? entries.map(coverageCard).join("")
      : emptyBox("This run has not mapped any ATT&CK techniques yet.");
    const lg = $("cov-legend");
    if (lg) {
      const c = { covered: 0, gap: 0, forged: 0 };
      entries.forEach((e) => { c[e.status] += 1; });
      lg.innerHTML =
        `<span class="lg lg-forged">${c.forged} forged</span>` +
        `<span class="lg lg-gap">${c.gap} gap</span>` +
        `<span class="lg lg-covered">${c.covered} covered</span>`;
    }
  }

  // ================================================================= intel
  function renderIntel() {
    const wrap = $("intel-cards");
    if (!wrap) return;
    const intel = (S.runState && S.runState.intel) || [];
    if (!intel.length) { wrap.innerHTML = emptyBox("No advisories ingested yet."); return; }
    wrap.innerHTML = intel.map((it) => {
      const techs = (it.mitre_techniques || []).map((t) => `<span class="chip chip-tech">${escapeHtml(t)}</span>`).join("");
      return `<article class="intel-card">` +
        `<div class="intel-head"><span class="intel-sev sev-${escapeHtml(String(it.severity || "medium"))}">${escapeHtml(String(it.severity || "medium"))}</span>` +
        `<span class="intel-src mono">${escapeHtml(it.source || "")}</span></div>` +
        `<h3 class="intel-title">${escapeHtml(it.title || it.intel_id || "advisory")}</h3>` +
        `<p class="intel-desc">${escapeHtml(it.description || "")}</p>` +
        `<div class="intel-techs">${techs}</div></article>`;
    }).join("");
  }

  // ============================================================ noise chart
  function noiseChartInto(wrap, run) {
    const h = run && run.headline ? run.headline : null;
    if (!h || (h.v1_weekly == null && h.final_weekly == null)) {
      wrap.innerHTML = emptyBox("No noise measurements yet — run the pipeline to backtest and forecast.");
      return;
    }
    const bars = [];
    if (h.v1_weekly != null) bars.push({ label: "v1 backtest", value: Number(h.v1_weekly), cls: "bar-v1" });
    if (h.final_weekly != null) bars.push({ label: "final forecast", value: Number(h.final_weekly), cls: "bar-final" });
    const budget = typeof h.budget === "number" ? h.budget : null;

    const W = 560, H = 212, padL = 18, padR = 18, top = 28, bottom = 36;
    const plotH = H - top - bottom, baseY = H - bottom;
    const maxV = Math.max(budget || 0, 1, ...bars.map((b) => b.value));
    const yFor = (v) => baseY - plotH * Math.sqrt(Math.max(v, 0)) / Math.sqrt(maxV);

    const parts = [`<line x1="${padL}" y1="${baseY}" x2="${W - padR}" y2="${baseY}" class="axis"/>`];
    const slot = (W - padL - padR) / bars.length;
    bars.forEach((b, i) => {
      const cx = padL + slot * i + slot / 2;
      const barW = Math.min(110, slot * 0.42);
      const hgt = Math.max(baseY - yFor(b.value), 2);
      parts.push(`<rect x="${cx - barW / 2}" y="${baseY - hgt}" width="${barW}" height="${hgt}" rx="3" class="${b.cls} bar-grow"/>`);
      parts.push(`<text x="${cx}" y="${baseY - hgt - 8}" text-anchor="middle" class="bar-val">${fmtNum(b.value)}/wk</text>`);
      parts.push(`<text x="${cx}" y="${baseY + 19}" text-anchor="middle" class="bar-label">${escapeHtml(b.label)}</text>`);
    });
    if (budget != null) {
      const by = yFor(budget);
      parts.push(`<line x1="${padL}" y1="${by}" x2="${W - padR}" y2="${by}" class="budget-line"/>`);
      parts.push(`<text x="${W - padR}" y="${by - 6}" text-anchor="end" class="budget-label">budget ${fmtNum(budget)}/wk</text>`);
    }
    const svg = `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="xMidYMid meet" ` +
      `aria-label="Weekly alert noise: v1 backtest vs final forecast vs budget">${parts.join("")}</svg>`;
    let callout = "";
    if (h.v1_weekly != null && h.final_weekly != null && Number(h.v1_weekly) > 0) {
      const cut = (1 - Number(h.final_weekly) / Number(h.v1_weekly)) * 100;
      if (cut > 0) callout = `<div class="noise-callout"><span class="noise-big">${fmtNum(h.v1_weekly)} → ${fmtNum(h.final_weekly)}</span>` +
        ` alerts/week <span class="noise-cut">▼ ${cut.toFixed(1)}% noise</span></div>`;
    }
    wrap.innerHTML = `${callout}${svg}<div class="chart-note">weekly alert volume · square-root scale</div>`;
  }

  function renderNoise() {
    const run = currentRunSummary();
    const full = $("noise-chart"); if (full) noiseChartInto(full, run);
    const mini = $("noise-chart-mini"); if (mini) noiseChartInto(mini, run);
  }

  // ========================================================= backtest stats
  function renderBacktestStats() {
    const wrap = $("backtest-stats");
    if (!wrap) return;
    const st = S.runState, rid = firstRuleId(st);
    const bt = st && rid && st.backtests ? st.backtests[rid] : null;
    if (!bt) { wrap.innerHTML = emptyBox("No backtest yet — the Backtest Engineer replays 90 days of labeled history."); return; }
    const stat = (label, value, cls) =>
      `<div class="bt-stat"><div class="bt-v ${cls || ""}">${value}</div><div class="bt-l">${escapeHtml(label)}</div></div>`;
    wrap.innerHTML =
      `<div class="bt-grid">` +
        stat("recall", fmtPct(bt.recall), "ok") +
        stat("precision", fmtPct(bt.precision), "") +
        stat("true positives", `${bt.true_positives}/${bt.labeled_attack_events}`, "ok") +
        stat("false positives", String(bt.false_positives), bt.false_positives > 50 ? "bad" : "") +
        stat("total hits", String(bt.total_hits), "") +
        stat("window", `${bt.window_days}d`, "") +
      `</div>` +
      `<p class="bt-note">SPL replayed over ${bt.window_days} days of labeled history · ${bt.labeled_attack_events} ground-truth attack events · syntax ${bt.syntax_valid ? "valid ✓" : "invalid ✗"}</p>`;
  }

  // ======================================================== forecast chart
  function renderForecastChart() {
    const wrap = $("forecast-chart");
    if (!wrap) return;
    const st = S.runState, rid = firstRuleId(st);
    const fc = st && rid && st.forecasts ? st.forecasts[rid] : null;
    const modelTag = $("forecast-model");
    if (!fc) { wrap.innerHTML = emptyBox("No forecast yet — the Noise Forecaster prices future alert volume.");
      if (modelTag) modelTag.textContent = ""; return; }
    if (modelTag) modelTag.textContent = `${fc.model} · ${fc.conf_interval}% CI · ${fc.horizon_days}d`;

    const pts = Array.isArray(fc.points) ? fc.points : [];
    if (pts.length < 2) {
      const within = fc.within_budget;
      wrap.innerHTML =
        `<div class="fc-summary">` +
        `<div class="fc-big ${within ? "ok" : "bad"}">${fmtNum(fc.predicted_weekly_alerts)}<span class="fc-unit">/wk</span></div>` +
        `<div class="fc-band">90% band ${fmtNum(fc.lower_bound_weekly)} – ${fmtNum(fc.upper_bound_weekly)} /wk</div>` +
        `<div class="fc-verdict ${within ? "ok" : "bad"}">${within ? "within budget ✓" : "over budget — tuning required ✗"}</div>` +
        `</div>`;
      return;
    }

    const W = 720, H = 240, padL = 40, padR = 16, top = 18, bottom = 30;
    const plotH = H - top - bottom, plotW = W - padL - padR, baseY = H - bottom;
    const ys = pts.map((p) => Number(p.upper90 != null ? p.upper90 : p.predicted) || 0);
    // points are DAILY counts; the budget is weekly, so compare on a per-day basis.
    const budget = fc.fp_budget_weekly ? fc.fp_budget_weekly / 7 : null;
    const maxV = Math.max(1, budget || 0, ...ys) * 1.1;
    const xFor = (i) => padL + plotW * (i / (pts.length - 1));
    const yFor = (v) => baseY - plotH * (Math.max(v, 0) / maxV);

    const up = pts.map((p, i) => `${xFor(i)},${yFor(Number(p.upper90 != null ? p.upper90 : p.predicted))}`);
    const lo = pts.map((p, i) => `${xFor(i)},${yFor(Number(p.lower90 != null ? p.lower90 : p.predicted))}`).reverse();
    const band = `<polygon class="fc-area" points="${up.concat(lo).join(" ")}"/>`;
    const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${xFor(i)},${yFor(Number(p.predicted))}`).join(" ");

    const grid = [];
    for (let g = 0; g <= 3; g++) {
      const v = (maxV / 3) * g, y = yFor(v);
      grid.push(`<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" class="fc-grid"/>`);
      grid.push(`<text x="${padL - 6}" y="${y + 3}" text-anchor="end" class="fc-axis">${fmtNum(v)}</text>`);
    }
    let budgetEl = "";
    if (budget != null) {
      const by = yFor(budget);
      budgetEl = `<line x1="${padL}" y1="${by}" x2="${W - padR}" y2="${by}" class="budget-line"/>` +
        `<text x="${W - padR}" y="${by - 5}" text-anchor="end" class="budget-label">budget ${fmtNum(budget)}/day · ${fmtNum(fc.fp_budget_weekly)}/wk</text>`;
    }
    const dots = pts.map((p, i) => `<circle cx="${xFor(i)}" cy="${yFor(Number(p.predicted))}" r="2.4" class="fc-dot"/>`).join("");
    wrap.innerHTML =
      `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="xMidYMid meet" aria-label="Forecast with confidence band">` +
      grid.join("") + band + budgetEl + `<path class="fc-line" d="${line}"/>` + dots + `</svg>` +
      `<div class="chart-note">${escapeHtml(fc.model)} forecast · shaded = ${fc.conf_interval}% confidence band · ${pts.length} points</div>`;
  }

  // ========================================================= approval queue
  function approvalCard(req) {
    const card = document.createElement("article");
    card.className = "approval-card";
    const recallTxt = typeof req.recall === "number" ? `${Math.round(req.recall * 100)}% TPs retained` : "recall n/a";
    card.innerHTML =
      `<div class="appr-head">` +
        `<span class="appr-name" title="${escapeHtml(req.rule_id || "")}">${escapeHtml(req.rule_name || req.rule_id || "detection rule")}</span>` +
        `<span class="chip chip-version">v${escapeHtml(String(req.rule_version != null ? req.rule_version : "?"))}</span></div>` +
      `<div class="appr-meta">` +
        `<span class="chip chip-tech">${escapeHtml(req.technique || "unmapped")}</span>` +
        `<span class="chip chip-recall">${escapeHtml(recallTxt)}</span></div>` +
      `<div class="appr-numbers mono">` +
        `<span class="num-backtest" title="weekly hit rate in backtest">${fmtNum(req.weekly_backtest)}/wk</span>` +
        `<span class="num-arrow">→</span>` +
        `<span class="num-forecast" title="forecast weekly alerts">${fmtNum(req.weekly_forecast)}/wk</span>` +
        `<span class="num-vs">vs budget ${fmtNum(req.fp_budget_weekly)}/wk</span></div>`;
    if (req.evidence_markdown) {
      const det = document.createElement("details");
      det.className = "evidence"; det.open = true;
      const sum = document.createElement("summary"); sum.textContent = "Evidence pack";
      const body = document.createElement("div"); body.className = "md";
      body.innerHTML = renderMarkdown(req.evidence_markdown);
      det.append(sum, body);
      card.appendChild(det);
    }
    const row = document.createElement("div");
    row.className = "appr-actions";
    const btns = [];
    const mk = (label, cls, decision) => {
      const b = document.createElement("button");
      b.type = "button"; b.className = `btn ${cls}`; b.textContent = label;
      b.addEventListener("click", () => decide(req, decision, card, btns));
      row.appendChild(b); btns.push(b);
    };
    mk("Deploy Active", "btn-primary", "active");
    mk("Shadow", "btn-outline", "shadow");
    mk("Reject", "btn-danger", "reject");
    card.appendChild(row);
    return card;
  }

  async function decide(req, decision, card, btns) {
    btns.forEach((b) => { b.disabled = true; });
    try {
      await fetchJSON("/api/approve", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: req.request_id, decision }),
      });
      const verb = decision === "active" ? "deploying active" : decision === "shadow" ? "deploying shadow" : "rejected";
      toast(`${req.rule_name || req.rule_id || "rule"}: ${verb}`, "ok");
      S.pending = S.pending.filter((p) => p.request_id !== req.request_id);
      S.pendingKey = S.pending.map((p) => p.request_id).join("|");
      card.remove();
      if (!S.pending.length) renderPending(true);
      renderTopbar();
      setTimeout(refreshAll, 1600);
    } catch (err) {
      toast(`Approval failed: ${err.message}`);
      btns.forEach((b) => { b.disabled = false; });
    }
  }

  function renderPending(force) {
    const key = S.pending.map((p) => p.request_id).join("|");
    if (!force && key === S.pendingKey) return;
    S.pendingKey = key;
    const count = $("approval-count");
    if (count) { count.hidden = !S.pending.length; if (S.pending.length) count.textContent = `${S.pending.length} waiting`; }
    const wrap = $("approval-cards");
    if (!wrap) return;
    wrap.textContent = "";
    if (!S.pending.length) {
      wrap.innerHTML = emptyBox("No approvals waiting. Start a run with auto-approve off to review evidence packs here.");
      return;
    }
    for (const req of S.pending) wrap.appendChild(approvalCard(req));
  }

  // ============================================================ policy grid
  function renderPolicyGrid() {
    const grid = $("policy-grid");
    if (!grid) return;
    const st = S.runState, rid = firstRuleId(st);
    const dec = st && rid && st.decisions ? st.decisions[rid] : null;
    const tally = $("policy-tally");
    if (!dec || !(dec.policy_checks || []).length) {
      grid.innerHTML = emptyBox("Policy checks appear once the Governor evaluates a tuned rule.");
      if (tally) tally.textContent = "";
      return;
    }
    const checks = dec.policy_checks;
    const passed = checks.filter((c) => c.passed).length;
    if (tally) tally.textContent = `${passed}/${checks.length} passed · ${String(dec.decision || "").replace(/_/g, " ")}`;
    grid.innerHTML = checks.map((c) =>
      `<div class="pc ${c.passed ? "pc-ok" : "pc-bad"}">` +
        `<span class="pc-mark">${c.passed ? "✓" : "✗"}</span>` +
        `<span class="pc-body"><span class="pc-name">${escapeHtml(c.name)}</span>` +
        (c.detail ? `<span class="pc-detail">${escapeHtml(c.detail)}</span>` : "") + `</span></div>`).join("");
  }

  function renderEvidencePacks() {
    const wrap = $("evidence-packs");
    if (!wrap) return;
    if (!S.evidence.length) { wrap.innerHTML = ""; return; }
    wrap.innerHTML = `<div class="ep-head">Evidence packs (${S.evidence.length})</div>`;
    for (const pack of S.evidence) {
      const det = document.createElement("details");
      det.className = "evidence";
      const sum = document.createElement("summary");
      sum.textContent = `${pack.rule_id} · v${pack.version}`;
      const body = document.createElement("div");
      body.className = "md";
      body.innerHTML = renderMarkdown(pack.markdown);
      det.append(sum, body);
      wrap.appendChild(det);
    }
  }

  // ============================================================ deployments
  function renderDeployments() {
    const wrap = $("deploy-cards");
    if (!wrap) return;
    const st = S.runState;
    const deps = st && st.deployments ? st.deployments : {};
    const ids = Object.keys(deps);
    if (!ids.length) { wrap.innerHTML = emptyBox("No deployments yet — approved rules ship here as native saved searches."); return; }
    wrap.innerHTML = ids.map((rid) => {
      const d = deps[rid];
      const rule = (st.rules || {})[rid] || {};
      const ver = (st.verifications || {})[rid] || null;
      const modeCls = d.rolled_back ? "dep-rolled" : d.mode === "active" ? "dep-active" : "dep-shadow";
      const modeLabel = d.rolled_back ? "ROLLED BACK" : (d.mode || "shadow").toUpperCase();
      const techs = (rule.mitre_techniques || []).map((t) => `<span class="chip chip-tech">${escapeHtml(t)}</span>`).join("");
      let verEl = `<div class="dep-ver dep-ver-pending">verification pending</div>`;
      if (ver) {
        const ok = ver.action === "ok";
        verEl = `<div class="dep-ver ${ok ? "dep-ver-ok" : "dep-ver-warn"}">` +
          `<div class="dv-row"><span>observed</span><strong>${fmtNum(ver.observed_weekly_alerts)}/wk</strong></div>` +
          `<div class="dv-row"><span>forecast</span><strong>${fmtNum(ver.forecast_weekly_alerts)}/wk</strong></div>` +
          `<div class="dv-row"><span>drift</span><strong>${Number(ver.drift_ratio).toFixed(2)}×</strong></div>` +
          `<div class="dv-verdict">${ver.within_forecast_band ? "within 90% band" : "outside band"} · action: ${escapeHtml(ver.action)}</div>` +
          `</div>`;
      }
      return `<article class="deploy-card ${modeCls}">` +
        `<div class="dep-head"><span class="dep-name mono">${escapeHtml(d.saved_search_name || rule.name || rid)}</span>` +
        `<span class="dep-mode ${modeCls}">${modeLabel}</span></div>` +
        `<div class="dep-meta">${techs}<span class="chip">v${escapeHtml(String(d.rule_version != null ? d.rule_version : "?"))}</span>` +
        `<span class="chip chip-recall">${escapeHtml(rule.severity || "medium")}</span></div>` +
        `<div class="dep-rollback mono" title="rollback token">⟲ ${escapeHtml(d.rollback_token || "—")}</div>` +
        verEl + `</article>`;
    }).join("");
  }

  // ======================================================== flight recorder
  function fmtVal(v) {
    if (typeof v === "boolean") return v ? "yes" : "no";
    if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(Number(v.toFixed(2)));
    if (Array.isArray(v)) {
      const simple = v.every((x) => typeof x === "string" || typeof x === "number");
      return v.length <= 3 && simple ? v.join(",") : `[${v.length} items]`;
    }
    if (v && typeof v === "object") return `{${Object.keys(v).length} keys}`;
    const s = String(v);
    return s.length > 42 ? `${s.slice(0, 39)}...` : s;
  }

  function summarizeDetail(detail) {
    if (!detail || typeof detail !== "object") return "";
    const keys = PRIORITY_KEYS.filter((k) => k in detail);
    for (const k of Object.keys(detail)) if (!keys.includes(k)) keys.push(k);
    const s = keys.slice(0, 3).map((k) => `${k}=${fmtVal(detail[k])}`).join("  ");
    return s.length > 110 ? `${s.slice(0, 107)}...` : s;
  }

  const agentClass = (agent) => `agent-${String(agent || "").toLowerCase().replace(/[^a-z0-9-]/g, "")}`;

  function flightRows() {
    let rows = (S.flight && S.flight.length ? S.flight : S.lastEvents) || [];
    if (S.flightFilter) rows = rows.filter((r) => r.agent === S.flightFilter);
    return rows.slice().sort((a, b) => (b.seq || 0) - (a.seq || 0));
  }

  function renderFlight() {
    const body = $("flight-body");
    if (!body) return;
    const all = flightRows();
    const rows = all.slice(0, 60);
    const key = S.flightFilter + "|" + rows.map((r) => `${r.seq}${r.ts || ""}`).join("|");
    if (key === lastFlightKey) return;
    lastFlightKey = key;
    const count = $("flight-count"); if (count) count.textContent = all.length ? `${all.length} events` : "";
    // keep the agent filter populated
    const filt = $("flight-filter");
    if (filt && filt.dataset.built !== "1") {
      filt.innerHTML = '<option value="">all agents</option>' +
        AGENTS.map((a) => `<option value="${a}">${escapeHtml(AGENT_LABELS[a] || a)}</option>`).join("");
      filt.dataset.built = "1";
    }
    body.textContent = "";
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty-cell">Flight recorder idle — no events yet.</td></tr>';
      return;
    }
    for (const e of rows) {
      const tr = document.createElement("tr");
      const ts = typeof e.ts === "string" && e.ts.length >= 19 ? e.ts.slice(11, 19) : "";
      const agent = String(e.agent || "");
      tr.innerHTML =
        `<td class="mono ft-seq">${escapeHtml(String(e.seq != null ? e.seq : ""))}</td>` +
        `<td class="mono ft-time">${escapeHtml(ts)}</td>` +
        `<td><span class="agent-chip ${agentClass(agent)}" title="${escapeHtml(agent)}">${escapeHtml(AGENT_SHORT[agent] || agent)}</span></td>` +
        `<td class="ft-act" title="${escapeHtml(String(e.action || ""))}">${escapeHtml(String(e.action || "").replace(/_/g, " "))}</td>` +
        `<td class="ft-detail mono" title="${escapeHtml(JSON.stringify(e.detail || {}))}">${escapeHtml(summarizeDetail(e.detail))}</td>`;
      body.appendChild(tr);
    }
  }

  // ============================================================ live feed
  function renderFeed() {
    const ul = $("ov-feed");
    if (!ul) return;
    const rows = ((S.lastEvents && S.lastEvents.length ? S.lastEvents : S.flight) || [])
      .slice().sort((a, b) => (b.seq || 0) - (a.seq || 0)).slice(0, 9);
    if (!rows.length) { ul.innerHTML = `<li class="feed-empty">No events yet — start a run.</li>`; return; }
    ul.innerHTML = rows.map((e) => {
      const agent = String(e.agent || "");
      const ts = typeof e.ts === "string" && e.ts.length >= 19 ? e.ts.slice(11, 19) : "";
      return `<li class="feed-row">` +
        `<span class="agent-chip ${agentClass(agent)}">${escapeHtml(AGENT_SHORT[agent] || agent)}</span>` +
        `<span class="feed-act">${escapeHtml(String(e.action || "").replace(/_/g, " "))}</span>` +
        `<span class="feed-time mono">${escapeHtml(ts)}</span></li>`;
    }).join("");
  }

  // =============================================================== story
  function renderStory() {
    const el = $("ov-story");
    if (!el) return;
    const st = S.runState, h = currentHeadline(), rid = firstRuleId(st);
    if (!st) { el.innerHTML = emptyBox("Press Start run to watch nine agents forge a detection end to end."); return; }
    const cov = deriveCoverage(st);
    const gap = cov.find((c) => c.status === "gap") || cov.find((c) => c.status === "forged");
    const rule = rid ? (st.rules || {})[rid] : null;
    const ver = rid ? (st.verifications || {})[rid] : null;
    const steps = [];
    if (gap) steps.push(`<li><b>Gap found:</b> ${escapeHtml(gap.tid)} ${escapeHtml(gap.name || "")}</li>`);
    if (h.v1_weekly != null) steps.push(`<li><b>Backtested:</b> ${fmtNum(h.v1_weekly)}/wk at ${fmtPct(h.recall)} recall</li>`);
    if (h.v1_weekly != null && h.final_weekly != null) {
      const cut = h.v1_weekly > 0 ? (1 - h.final_weekly / h.v1_weekly) * 100 : 0;
      steps.push(`<li><b>Tuned:</b> down to ${fmtNum(h.final_weekly)}/wk (${cut.toFixed(0)}% quieter) under a ${fmtNum(h.budget)}/wk budget</li>`);
    }
    if (h.decision) steps.push(`<li><b>Governed:</b> ${escapeHtml(String(h.decision).replace(/_/g, " "))}${h.deployment_mode ? " → deployed " + escapeHtml(h.deployment_mode) : ""}</li>`);
    if (ver) steps.push(`<li><b>Verified:</b> ${fmtNum(ver.observed_weekly_alerts)}/wk observed, drift ${Number(ver.drift_ratio).toFixed(2)}× — ${ver.within_forecast_band ? "in band ✓" : "out of band"}</li>`);
    el.innerHTML = steps.length ? `<ol class="story-list">${steps.join("")}</ol>`
      : emptyBox("Run in progress — the story fills in as agents report.");
  }

  // =============================================================== models
  function renderModels() {
    const grid = $("models-grid");
    if (!grid) return;
    const st = S.runState, rid = firstRuleId(st);
    const fc = st && rid && st.forecasts ? st.forecasts[rid] : null;
    const liveModel = fc ? fc.model : null;
    const ml = $("models-live");
    if (ml) ml.textContent = liveModel ? `live forecaster: ${liveModel}` : "";
    grid.innerHTML = MODELS.map((m) => {
      const powers = m.powers.map((p) => `<span class="chip">${escapeHtml(AGENT_LABELS[p] || p)}</span>`).join("");
      let liveBadge = "";
      if (m.live && liveModel) {
        const isCDTSM = /cdtsm/i.test(liveModel);
        liveBadge = `<span class="model-live ${isCDTSM ? "ml-on" : "ml-fallback"}">${isCDTSM ? "● active" : "● fallback: " + escapeHtml(liveModel)}</span>`;
      }
      return `<article class="model-card mc-${m.accent}">` +
        `<div class="mc-bar"></div>` +
        `<div class="mc-head"><h3 class="mc-name">${escapeHtml(m.name)}</h3>${liveBadge}</div>` +
        `<div class="mc-vendor mono">${escapeHtml(m.vendor)}</div>` +
        `<p class="mc-tag">${escapeHtml(m.tag)}</p>` +
        `<div class="mc-powers"><span class="mc-powers-l">powers</span>${powers}</div></article>`;
    }).join("");
  }

  // =============================================================== history
  function renderHistory() {
    const wrap = $("history-list");
    if (!wrap) return;
    const count = $("history-count"); if (count) count.textContent = S.runs.length ? `${S.runs.length} run${S.runs.length === 1 ? "" : "s"}` : "";
    if (!S.runs.length) { wrap.innerHTML = emptyBox("No runs yet — press Start run to forge your first detections."); return; }
    const cur = effectiveRunId();
    wrap.innerHTML = S.runs.map((r) => {
      const h = r.headline || {};
      const sel = r.run_id === cur ? " hist-sel" : "";
      const stageCls = r.stage === "done" ? "hs-done" : r.stage === "failed" ? "hs-fail" : "hs-run";
      const cut = (h.v1_weekly && h.final_weekly && h.v1_weekly > 0) ? (1 - h.final_weekly / h.v1_weekly) * 100 : null;
      const metrics = [];
      if (h.gaps != null) metrics.push(`${h.gaps} gap${h.gaps === 1 ? "" : "s"}`);
      if (h.v1_weekly != null && h.final_weekly != null) metrics.push(`${fmtNum(h.v1_weekly)}→${fmtNum(h.final_weekly)}/wk`);
      if (cut != null) metrics.push(`<span class="hist-cut">▼${cut.toFixed(0)}%</span>`);
      if (h.recall != null) metrics.push(`${fmtPct(h.recall)} recall`);
      if (h.deployment_mode) metrics.push(`deployed ${escapeHtml(h.deployment_mode)}`);
      if (h.verification) metrics.push(`verified ${escapeHtml(h.verification)}`);
      const created = typeof r.created_at === "string" ? r.created_at.replace("T", " ").slice(0, 19) : "";
      return `<button type="button" class="hist-card${sel}" data-run="${escapeHtml(r.run_id)}">` +
        `<div class="hist-top"><span class="hist-id mono">${escapeHtml(r.run_id)}</span>` +
        `<span class="hist-stage ${stageCls}">${escapeHtml(r.stage || "")}</span></div>` +
        `<div class="hist-metrics">${metrics.map((m) => `<span>${m}</span>`).join("")}</div>` +
        `<div class="hist-time mono">${escapeHtml(created)}</div></button>`;
    }).join("");
    qsa(".hist-card").forEach((b) => b.addEventListener("click", () => {
      S.selectedRunId = b.dataset.run;
      renderRunSelect();
      refreshAll().then(() => setView("overview"));
    }));
  }

  // =========================================================== footer line
  function renderFooter() {
    const el = $("run-summary");
    if (!el) return;
    const run = currentRunSummary();
    if (!run) { el.innerHTML = "<span>No runs yet — press <strong>Start run</strong> to forge your first detections.</span>"; return; }
    const h = run.headline || {};
    const bits = [`<span class="mono">${escapeHtml(run.run_id || "")}</span>`];
    if (run.stage) bits.push(`stage <strong>${escapeHtml(run.stage)}</strong>`);
    if (typeof h.gaps === "number") bits.push(`${h.gaps} gap${h.gaps === 1 ? "" : "s"}`);
    if (typeof h.rules === "number") bits.push(`${h.rules} rule${h.rules === 1 ? "" : "s"}`);
    if (h.v1_weekly != null && h.final_weekly != null) bits.push(`v1 <strong>${fmtNum(h.v1_weekly)}/wk</strong> → final <strong>${fmtNum(h.final_weekly)}/wk</strong>`);
    else if (h.final_weekly != null) bits.push(`forecast <strong>${fmtNum(h.final_weekly)}/wk</strong>`);
    if (h.budget != null) bits.push(`budget ${fmtNum(h.budget)}/wk`);
    if (h.recall != null) bits.push(`<strong>${fmtPct(h.recall)}</strong> TPs retained`);
    if (h.decision) bits.push(escapeHtml(String(h.decision).replace(/_/g, " ")));
    if (h.deployment_mode) bits.push(`deployed <strong>${escapeHtml(h.deployment_mode)}</strong>`);
    if (h.verification) bits.push(`verified <strong>${escapeHtml(h.verification)}</strong>`);
    el.innerHTML = bits.join('<span class="sep">·</span>');
  }

  // ============================================== render everything (cheap)
  function renderAll() {
    renderTopbar();
    renderRunSelect();
    renderFooter();
    renderActiveView();
  }

  // =========================================================== data refresh
  async function refreshRuns() {
    try {
      const runs = await fetchJSON("/api/runs");
      S.runs = Array.isArray(runs) ? runs : [];
    } catch (err) { toastOnce("runs", `Could not load runs: ${err.message}`); }
  }

  async function refreshRunState(runId) {
    if (!runId) { S.runState = null; S.flight = []; S.evidence = []; S.evidenceRunId = null; return; }
    await Promise.all([
      fetchJSON(`/api/runs/${encodeURIComponent(runId)}`).then((st) => { S.runState = st; }).catch(() => {}),
      fetchJSON(`/api/runs/${encodeURIComponent(runId)}/flight`).then((fl) => { S.flight = Array.isArray(fl) ? fl : []; }).catch(() => {}),
    ]);
    // Evidence packs only re-fetched when the run changes (they rarely change mid-run).
    if (S.evidenceRunId !== runId) {
      S.evidenceRunId = runId;
      try { const ev = await fetchJSON(`/api/runs/${encodeURIComponent(runId)}/evidence`); S.evidence = Array.isArray(ev) ? ev : []; }
      catch { S.evidence = []; }
    }
  }

  async function refreshAll() {
    await refreshRuns();
    await refreshRunState(effectiveRunId());
    S.renderedStateKey = stateKey(S.runState);
    renderAll();
    renderFlight();
  }

  // ================================================================== polls
  async function pollStatus() {
    let st;
    try { st = await fetchJSON("/api/pipeline/status"); }
    catch (err) { toastOnce("status", `Console lost contact with the server: ${err.message}`); return; }
    const wasRunning = S.running;
    S.running = !!st.running;
    S.activeRunId = st.run_id || null;
    S.stage = st.stage || null;
    S.lastEvents = Array.isArray(st.last_events) ? st.last_events : [];
    if (st.error) toastOnce(`pipe:${st.error}`, `Pipeline error: ${st.error}`);
    renderTopbar();
    renderFlight();
    if (S.view === "overview") renderFeed();

    if (S.running && !S.selectedRunId) {
      if (S.stage !== S.lastStage) {
        S.lastStage = S.stage;
        await refreshRuns();
        await refreshRunState(S.activeRunId);
        S.renderedStateKey = stateKey(S.runState);
        renderAll();
      } else {
        // cheap live updates while a stage churns
        if (S.view === "overview" || S.view === "pipeline") { renderStepper(); renderAgentGrid(); renderKPIs(); }
      }
    }
    if (wasRunning && !S.running) { S.lastStage = null; await refreshAll(); }
  }

  async function pollPending() {
    try {
      const pending = await fetchJSON("/api/pending");
      S.pending = Array.isArray(pending) ? pending : [];
      renderTopbar();
      if (S.view === "governance" || S.view === "overview") renderPending(false);
    } catch (err) { toastOnce("pending", `Could not load the approval queue: ${err.message}`); }
  }

  const tick = () => { pollStatus(); pollPending(); };
  function startPolling() { if (pollTimer !== null) return; pollTimer = setInterval(tick, 1500); tick(); }
  function stopPolling() { if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; } }
  document.addEventListener("visibilitychange", () => { if (document.hidden) stopPolling(); else startPolling(); });

  // ================================================================ wiring
  function wireControls() {
    $("start-run").addEventListener("click", async () => {
      const btn = $("start-run");
      btn.disabled = true;
      let budget = parseFloat($("fp-budget") && $("fp-budget").value);
      if (!(budget > 0)) budget = 25;
      try {
        await fetchJSON("/api/pipeline/start", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ auto_approve: $("auto-approve").checked, fp_budget_weekly: budget }),
        });
        S.running = true;
        S.selectedRunId = null;           // follow the new live run
        renderRunSelect();
        renderTopbar();
        toast("Pipeline run started — nine agents on deck.", "ok");
      } catch (err) {
        toast(err.status === 409 ? "A run is already in progress." : `Could not start run: ${err.message}`);
        btn.disabled = S.running;
      }
    });

    const sel = $("run-select");
    if (sel) sel.addEventListener("change", () => {
      S.selectedRunId = sel.value || null;
      refreshAll();
    });

    const filt = $("flight-filter");
    if (filt) filt.addEventListener("change", () => { S.flightFilter = filt.value || ""; lastFlightKey = ""; renderFlight(); });
  }

  // ================================================================== init
  buildStepper("stepper", "overview");
  buildStepper("stepper-full", "full");
  wireNav();
  wireControls();
  setView((location.hash || "#overview").slice(1));
  renderTopbar();
  renderPending(true);
  renderFooter();
  refreshAll();
  startPolling();

})();
