/* Aegis Foundry console — vanilla JS, no frameworks, no external assets.
 * Pinned API: GET /api/runs, /api/runs/{id}, /api/runs/{id}/flight,
 * /api/pending, /api/pipeline/status; POST /api/pipeline/start, /api/approve.
 */
"use strict";

(() => {

  // ------------------------------------------------------------ constants
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

  const STAGE_TO_AGENT = {
    intel: "intel-scout", coverage: "coverage-cartographer",
    author: "detection-author", backtest: "backtest-engineer",
    forecast: "noise-forecaster", tune: "tuning-optimizer",
    govern: "governor", deploy: "deployer", verify: "verifier",
  };

  // Agents that repeat inside the measurement loop, and the actions that
  // mark one pass over a rule (drives the "pass N" badge on the stepper).
  const LOOP_ACTIONS = {
    "backtest-engineer": ["backtest_completed", "backtest_failed"],
    "noise-forecaster": ["noise_forecast"],
    "tuning-optimizer": ["rule_tuned", "tuning_skipped"],
  };

  // Offline name/tactic catalog for already-covered techniques (gap
  // techniques carry their own names in the audit events).
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

  // ---------------------------------------------------------------- state
  // runs: /api/runs (newest first) · runState/flight: active or latest run
  // lastEvents: status.last_events (flight panel) · pending: /api/pending
  const S = {
    running: false, stage: null, lastStage: null, activeRunId: null,
    runs: [], runState: null, flight: [], lastEvents: [],
    pending: [], pendingKey: null,
  };
  const stepEls = [];
  let lastFlightKey = "", pollTimer = null;

  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------------- utils
  const escapeHtml = (s) => String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  const fmtNum = (v) => (v == null || isNaN(Number(v)))
    ? "n/a" : String(Number(v).toFixed(1)).replace(/\.0$/, "");

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

  // ---------------------------------------------------------------- toasts
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

  // ---------------------------------------------- minimal markdown renderer
  // Escape first, then transform. Supports #/##/### headings, **bold**,
  // `inline code`, fenced code blocks (```spl, ```diff with +/- coloring),
  // tables, bullet lists and "- [x]" checkbox lists.
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
    const flushPara = () => {
      if (para.length) { html.push(`<p>${para.map(inlineMd).join(" ")}</p>`); para = []; }
    };
    const closeList = () => { if (inList) { html.push("</ul>"); inList = false; } };

    while (i < lines.length) {
      const line = lines[i];
      const fence = line.match(/^```(\w*)\s*$/);
      if (fence) {
        flushPara(); closeList();
        const lang = fence[1].toLowerCase(), buf = [];
        i += 1;
        while (i < lines.length && !/^```\s*$/.test(lines[i])) { buf.push(lines[i]); i += 1; }
        i += 1; // skip closing fence
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
      if (head) { // # -> h4, ## -> h5, ### -> h6
        flushPara(); closeList();
        const lvl = head[1].length + 3;
        html.push(`<h${lvl}>${inlineMd(head[2])}</h${lvl}>`);
        i += 1; continue;
      }
      if (/^\s*\|.*\|\s*$/.test(line)) {
        flushPara(); closeList();
        const rows = [];
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { rows.push(lines[i]); i += 1; }
        html.push(mdTable(rows));
        continue;
      }
      const li = line.match(/^\s*-\s+(.*)$/);
      if (li) {
        flushPara();
        if (!inList) { html.push("<ul>"); inList = true; }
        const cb = li[1].match(/^\[( |x|X)\]\s+(.*)$/);
        if (cb) {
          const on = cb[1].toLowerCase() === "x";
          html.push(`<li class="check-item"><span class="cbx${on ? " on" : ""}">${on ? "✓" : ""}</span>${inlineMd(cb[2])}</li>`);
        } else {
          html.push(`<li>${inlineMd(li[1])}</li>`);
        }
        i += 1; continue;
      }
      if (/^\s*$/.test(line)) { flushPara(); closeList(); i += 1; continue; }
      para.push(line);
      i += 1;
    }
    flushPara(); closeList();
    return html.join("\n");
  }

  // --------------------------------------------------------------- topbar
  function renderTopbar() {
    const pill = $("mode-pill");
    pill.textContent = S.running ? "RUNNING" : "IDLE";
    pill.className = `pill ${S.running ? "pill-run" : "pill-idle"}`;
    const stageEl = $("stage-indicator");
    stageEl.hidden = !(S.running && S.stage);
    if (S.running && S.stage) stageEl.textContent = `stage: ${S.stage}`;
    $("start-run").disabled = S.running;
    $("flight-live").hidden = !S.running;
  }

  // -------------------------------------------------------------- stepper
  function buildStepper() {
    const ol = $("stepper");
    for (const agent of AGENTS) {
      const li = document.createElement("li");
      li.className = "step";
      li.title = agent;
      li.innerHTML = `<span class="pass-badge" hidden></span><span class="step-dot"></span>` +
        `<span class="step-name">${escapeHtml(AGENT_LABELS[agent] || agent)}</span>`;
      ol.appendChild(li);
      stepEls.push(li);
    }
  }

  function passCount(events, agent) {
    const actions = LOOP_ACTIONS[agent];
    if (!actions) return 1;
    const perRule = {};
    let max = 1;
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
    AGENTS.forEach((agent, idx) => {
      const li = stepEls[idx];
      li.classList.toggle("done", !!byAgent[agent]);
      li.classList.toggle("active", agent === activeAgent);
      const badge = li.querySelector(".pass-badge");
      const n = passCount(byAgent[agent] || [], agent);
      badge.hidden = n < 2;
      if (n >= 2) badge.textContent = `pass ${n}`;
    });
  }

  // ------------------------------------------------------------- coverage
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
      if (!info[tid]) {
        info[tid] = { status: "covered", name: "", tactic: "", via: "" };
        order.push(tid);
      }
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
    // FORGED BY AEGIS: a deployed (not rolled back) Aegis rule covers it.
    const rules = st.rules || {};
    for (const [rid, dep] of Object.entries(st.deployments || {})) {
      if (!dep || dep.rolled_back) continue;
      const rule = rules[rid] || {};
      for (const tid of rule.mitre_techniques || []) {
        put(tid, "forged");
        info[tid].via = String(dep.saved_search_name || rule.name || rid) +
          (dep.mode ? ` (${dep.mode})` : "");
      }
    }
    const harvested = harvestNames(audit);
    for (const tid of order) {
      const it = info[tid], h = harvested[tid] || ["", ""], c = TECH_CATALOG[tid] || ["", ""];
      it.name = it.name || h[0] || c[0] || "";
      it.tactic = it.tactic || h[1] || c[1] || "";
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
    if (!S.runState) {
      wrap.innerHTML = emptyBox("No runs yet — press Start run to map ATT&CK coverage.");
      return;
    }
    const entries = deriveCoverage(S.runState);
    wrap.innerHTML = entries.length ? entries.map(coverageCard).join("")
      : emptyBox("This run has not mapped any ATT&CK techniques yet.");
  }

  // ------------------------------------------------------ noise SVG chart
  function renderNoise() {
    const wrap = $("noise-chart");
    const run = S.runs[0];
    const h = run && run.headline ? run.headline : null;
    if (!h || (h.v1_weekly == null && h.final_weekly == null)) {
      wrap.innerHTML = emptyBox("No noise measurements yet — run the pipeline to backtest and forecast alert volume.");
      return;
    }
    const bars = [];
    if (h.v1_weekly != null) bars.push({ label: "v1 backtest", value: Number(h.v1_weekly), cls: "bar-v1" });
    if (h.final_weekly != null) bars.push({ label: "final forecast", value: Number(h.final_weekly), cls: "bar-final" });
    const budget = typeof h.budget === "number" ? h.budget : null;

    const W = 560, H = 212, padL = 18, padR = 18, top = 28, bottom = 36;
    const plotH = H - top - bottom, baseY = H - bottom;
    const maxV = Math.max(budget || 0, 1, ...bars.map((b) => b.value));
    // Square-root scale keeps a 382-vs-2.7 comparison legible.
    const yFor = (v) => baseY - plotH * Math.sqrt(Math.max(v, 0)) / Math.sqrt(maxV);

    const parts = [`<line x1="${padL}" y1="${baseY}" x2="${W - padR}" y2="${baseY}" class="axis"/>`];
    const slot = (W - padL - padR) / bars.length;
    bars.forEach((b, i) => {
      const cx = padL + slot * i + slot / 2;
      const barW = Math.min(110, slot * 0.42);
      const hgt = Math.max(baseY - yFor(b.value), 2);
      parts.push(`<rect x="${cx - barW / 2}" y="${baseY - hgt}" width="${barW}" height="${hgt}" rx="3" class="${b.cls}"/>`);
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
      if (cut > 0) {
        callout = `<div class="noise-callout"><span class="noise-big">${fmtNum(h.v1_weekly)} → ${fmtNum(h.final_weekly)}</span>` +
          ` alerts/week <span class="noise-cut">▼ ${cut.toFixed(1)}% noise</span></div>`;
      }
    }
    wrap.innerHTML = `${callout}${svg}<div class="chart-note">weekly alert volume · square-root scale</div>`;
  }

  // ------------------------------------------------------- approval queue
  function approvalCard(req) {
    const card = document.createElement("article");
    card.className = "approval-card";
    const recallTxt = typeof req.recall === "number"
      ? `${Math.round(req.recall * 100)}% TPs retained` : "recall n/a";
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
      det.className = "evidence";
      const sum = document.createElement("summary");
      sum.textContent = "Evidence pack";
      const body = document.createElement("div");
      body.className = "md";
      body.innerHTML = renderMarkdown(req.evidence_markdown);
      det.append(sum, body);
      card.appendChild(det);
    }

    const row = document.createElement("div");
    row.className = "appr-actions";
    const btns = [];
    const mk = (label, cls, decision) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = `btn ${cls}`;
      b.textContent = label;
      b.addEventListener("click", () => decide(req, decision, card, btns));
      row.appendChild(b);
      btns.push(b);
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
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: req.request_id, decision }),
      });
      const verb = decision === "active" ? "deploying active"
        : decision === "shadow" ? "deploying shadow" : "rejected";
      toast(`${req.rule_name || req.rule_id || "rule"}: ${verb}`, "ok");
      S.pending = S.pending.filter((p) => p.request_id !== req.request_id);
      S.pendingKey = S.pending.map((p) => p.request_id).join("|");
      card.remove();
      if (!S.pending.length) renderPending(true);
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
    count.hidden = !S.pending.length;
    if (S.pending.length) count.textContent = String(S.pending.length);
    const wrap = $("approval-cards");
    wrap.textContent = "";
    if (!S.pending.length) {
      wrap.innerHTML = emptyBox("No approvals waiting. Start a run with auto-approve off to review evidence packs here.");
      return;
    }
    for (const req of S.pending) wrap.appendChild(approvalCard(req));
  }

  // ------------------------------------------------------ flight recorder
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

  const agentClass = (agent) =>
    `agent-${String(agent || "").toLowerCase().replace(/[^a-z0-9-]/g, "")}`;

  function renderFlight() {
    const rows = (S.lastEvents || []).slice()
      .sort((a, b) => (b.seq || 0) - (a.seq || 0)).slice(0, 12);
    const key = rows.map((r) => `${r.seq}${r.ts || ""}`).join("|");
    if (key === lastFlightKey) return;
    lastFlightKey = key;
    const body = $("flight-body");
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

  // ---------------------------------------------------------- footer line
  function renderFooter() {
    const el = $("run-summary");
    const run = S.runs[0];
    if (!run) {
      el.innerHTML = "<span>No runs yet — press <strong>Start run</strong> to forge your first detections.</span>";
      return;
    }
    const h = run.headline || {};
    const bits = [`<span class="mono">${escapeHtml(run.run_id || "")}</span>`];
    if (run.stage) bits.push(`stage <strong>${escapeHtml(run.stage)}</strong>`);
    if (typeof h.gaps === "number") bits.push(`${h.gaps} gap${h.gaps === 1 ? "" : "s"}`);
    if (typeof h.rules === "number") bits.push(`${h.rules} rule${h.rules === 1 ? "" : "s"}`);
    if (h.v1_weekly != null && h.final_weekly != null) {
      bits.push(`v1 <strong>${fmtNum(h.v1_weekly)}/wk</strong> → final <strong>${fmtNum(h.final_weekly)}/wk</strong>`);
    } else if (h.final_weekly != null) {
      bits.push(`forecast <strong>${fmtNum(h.final_weekly)}/wk</strong>`);
    }
    if (h.budget != null) bits.push(`budget ${fmtNum(h.budget)}/wk`);
    if (h.recall != null) bits.push(`<strong>${Math.round(Number(h.recall) * 100)}%</strong> TPs retained`);
    if (h.decision) bits.push(escapeHtml(String(h.decision).replace(/_/g, " ")));
    if (h.deployment_mode) bits.push(`deployed <strong>${escapeHtml(h.deployment_mode)}</strong>`);
    if (h.verification) bits.push(`verified <strong>${escapeHtml(h.verification)}</strong>`);
    el.innerHTML = bits.join('<span class="sep">·</span>');
  }

  // --------------------------------------------------------- data refresh
  async function refreshRuns() {
    try {
      const runs = await fetchJSON("/api/runs");
      S.runs = Array.isArray(runs) ? runs : [];
    } catch (err) {
      toastOnce("runs", `Could not load runs: ${err.message}`);
    }
    renderFooter();
    renderNoise();
  }

  async function refreshRunState(runId) {
    if (!runId) {
      S.runState = null;
      S.flight = [];
      $("pipeline-run").textContent = "";
    } else {
      $("pipeline-run").textContent = runId;
      // Either file may not exist yet on a brand-new run; keep prior data.
      await Promise.all([
        fetchJSON(`/api/runs/${encodeURIComponent(runId)}`)
          .then((st) => { S.runState = st; }).catch(() => {}),
        fetchJSON(`/api/runs/${encodeURIComponent(runId)}/flight`)
          .then((fl) => { S.flight = Array.isArray(fl) ? fl : []; }).catch(() => {}),
      ]);
    }
    renderCoverage();
    renderStepper();
  }

  async function refreshAll() {
    await refreshRuns();
    const target = (S.running && S.activeRunId) ? S.activeRunId
      : (S.runs[0] ? S.runs[0].run_id : null);
    await refreshRunState(target);
  }

  // ---------------------------------------------------------------- polls
  async function pollStatus() {
    let st;
    try {
      st = await fetchJSON("/api/pipeline/status");
    } catch (err) {
      toastOnce("status", `Console lost contact with the server: ${err.message}`);
      return;
    }
    const wasRunning = S.running;
    S.running = !!st.running;
    S.activeRunId = st.run_id || null;
    S.stage = st.stage || null;
    S.lastEvents = Array.isArray(st.last_events) ? st.last_events : [];
    if (st.error) toastOnce(`pipe:${st.error}`, `Pipeline error: ${st.error}`);
    renderTopbar();
    renderFlight();
    if (S.running) {
      if (S.stage !== S.lastStage) {
        S.lastStage = S.stage;
        refreshRuns();
        refreshRunState(S.activeRunId);
      } else {
        renderStepper();
      }
    }
    if (wasRunning && !S.running) {
      S.lastStage = null;
      refreshAll();
    }
  }

  async function pollPending() {
    try {
      const pending = await fetchJSON("/api/pending");
      S.pending = Array.isArray(pending) ? pending : [];
      renderPending(false);
    } catch (err) {
      toastOnce("pending", `Could not load the approval queue: ${err.message}`);
    }
  }

  const tick = () => { pollStatus(); pollPending(); };

  function startPolling() {
    if (pollTimer !== null) return;
    pollTimer = setInterval(tick, 1500);
    tick();
  }

  function stopPolling() {
    if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopPolling(); else startPolling();
  });

  // ------------------------------------------------------------ start run
  $("start-run").addEventListener("click", async () => {
    const btn = $("start-run");
    btn.disabled = true;
    try {
      await fetchJSON("/api/pipeline/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ auto_approve: $("auto-approve").checked, fp_budget_weekly: 25 }),
      });
      S.running = true;
      renderTopbar();
      toast("Pipeline run started — nine agents on deck.", "ok");
    } catch (err) {
      toast(err.status === 409 ? "A run is already in progress." : `Could not start run: ${err.message}`);
      btn.disabled = S.running;
    }
  });

  // ----------------------------------------------------------------- init
  buildStepper();
  renderTopbar();
  renderPending(true);
  renderFooter();
  renderNoise();
  renderCoverage();
  refreshAll();
  startPolling();

})();
