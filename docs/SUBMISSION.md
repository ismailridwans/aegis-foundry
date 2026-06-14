# Aegis Foundry — Devpost Submission Kit

Everything needed to submit in under 30 minutes. Deadline: **June 15, 2026, 9:00 AM PDT** (submit a day early). Devpost: splunk.devpost.com, Splunk Agentic Ops Hackathon.

---

## 1. Project name + elevator pitch

**Project name:** Aegis Foundry — the SOC that maintains itself

**Elevator pitch (2 sentences):**

> Aegis Foundry is an autonomous detection-engineering platform for Splunk: ten governed AI agents find MITRE ATT&CK coverage gaps, author SPL detections, backtest them against labeled history via the Splunk MCP Server, forecast their alert-noise cost with the Cisco Deep Time Series Model, red-team them against evasion variants, and deploy them only after a human approves the evidence pack. It attacks alert fatigue at its source — untuned detection logic upstream — and proves it with real numbers: a forecast of 382.3 alerts/week tuned down to 2.7 with all 17 labeled true positives retained, 88% adversarial recall against evasion, then verified against reality after deployment — quantified at ~$295k/year of analyst time saved.

---

## 2. Devpost text description (ready to paste)

### The problem

Detection engineering is the SOC's broken factory. Enterprises run hundreds of correlation searches; a large fraction are stale, broken by schema drift, or were never tuned to the environment they fire in. Covering a new threat technique takes days to weeks of manual authoring, historical validation, false-positive tuning, and change control. Downstream, analysts drown in alerts — but alert fatigue is a symptom. Every AI copilot that triages alerts faster is mopping the floor. Nobody fixed the faucet.

### What it does

Aegis Foundry closes the detection lifecycle loop inside Splunk with ten single-purpose agents under one orchestrated state machine: **Intel Scout** ingests advisories and extracts ATT&CK techniques; **Coverage Cartographer** maps them against the live saved-search inventory to find gaps; **Detection Author** drafts SPL, self-correcting against live syntax validation; **Backtest Engineer** replays each rule over 90 days of labeled history; **Noise Forecaster** predicts its future weekly alert volume; **Tuning Optimizer** iterates until the rule fits an explicit false-positive budget; **Red-Team** mutates the labeled attacks into MITRE-faithful evasion variants and proves the rule still fires; **Governor** runs eight policy checks, writes a Markdown evidence pack, and asks a human; **Deployer** ships the rule as a native Splunk saved search with a rollback token; **Verifier** then checks whether reality matched the forecast — and auto-rolls back runaway rules. The run closes by computing an ROI ledger and a NIST/CIS compliance attestation.

A stdlib-only web console (no frameworks, fully offline) presents this as an eleven-view operations dashboard: a Command Center with an ROI banner, the live pipeline stepper, ATT&CK coverage, a Noise Lab with the CDTSM confidence-band forecast, the Red-Team Gauntlet, browser-based Governance approvals with the full evidence pack, Deployments with rollback and drift, Compliance attestations, and a tamper-evident, hash-chained agent flight recorder.

### How it uses Splunk AI

- **Splunk MCP Server** is the agents' *only* read plane: search execution, SPL validation, and saved-search discovery over streamable HTTP with token auth.
- **Hosted model — Cisco Deep Time Series Model (CDTSM):** the Noise Forecaster runs `| apply CDTSM` through the search plane for zero-shot alert-volume forecasting; when unreachable it degrades to a deterministic EWMA model and honestly labels itself `fallback-ewma` in every forecast, evidence pack, and dashboard.
- **Hosted model — Foundation-Sec-1.1-8B:** security reasoning and MITRE technique mapping in the Coverage Cartographer.
- **Hosted models — gpt-oss-120b/20b:** detection authoring and tuning.
- **AI Toolkit `| ai` command:** an LLM client that routes completions through SPL, so data never leaves Splunk.
- **Splunk AI Assistant (`saia_*` MCP tools):** natural-language-to-SPL drafting path.
- **Splunk SDK app patterns + AppInspect:** ships as a packaged Splunk app (custom alert action, ATT&CK Coverage and Agent Flight Recorder dashboards), with AppInspect precert in CI — failures block the build.

### What's novel

1. **Upstream of triage.** Every other agentic SOC tool ranks or summarizes alerts. Aegis Foundry reduces the alerts that get created, by making detections continuously measured assets.
2. **Forecast-gated deployment.** A rule cannot deploy unless its *predicted* weekly alert volume fits the budget. Alert noise becomes a pre-deploy contract, not a post-deploy apology.
3. **Verified against the future, not just the past.** LLM hallucination is neutralized by construction: every rule must execute against 90 days of labeled history *and* survive a Red-Team gauntlet of MITRE-faithful evasion variants (88% adversarial recall on the demo) before it can reach a human. Backtest recall measures the past; the gauntlet measures resilience to an adversary who knows the rule exists.
4. **Agents audited INTO Splunk — tamper-evidently.** Every decision lands in an append-only flight recorder ingestible into a Splunk index *and* SHA-256 hash-chained, so editing any past entry provably breaks the chain. Observable and verifiable in the same pane of glass as the data it manages.
5. **It proves its own value.** The run quantifies an ROI ledger from measured numbers (~$295k/year of analyst time saved on the demo) and emits a NIST 800-53 / CIS Controls attestation — connecting detection engineering to the language executives and auditors fund.

### Governance

Evidence packs (SPL diff, backtest table, forecast band, adversarial-robustness results, eight policy checks including adversarial robustness and a blast-radius scan for destructive SPL), human-in-the-loop approval with shadow deployment as the safe default and timeout fallback, rollback tokens on every deployment, automatic rollback at >10x budget, a tamper-evident hash-chained audit ledger, and strict read/write separation: agents read via MCP; the only write path sits behind the Governor.

### The real numbers (one offline demo run)

Draft v1 backtested at 5,818 hits over 90 days — recall 100%, precision 0.3%, forecast **382.3 alerts/week**, far over the 25/week budget. One tuning pass later, v2 backtested at 42 hits with **all 17/17 labeled attack events retained**, precision 40%, forecast **2.7/week**. The Red-Team gauntlet then mutated the labeled attacks into 24 evasion variants — **21 still fire (88% adversarial recall)**, with the `-enc` alias flagged for hardening. Eight of eight policy checks pass; approved, deployed as a native saved search, and verified post-deploy at 3.0/week observed: **drift ratio 1.11, inside the 90% forecast band**. T1059.001 flipped from GAP to FORGED BY AEGIS. The run booked an ROI of **~$295k/year** and attested coverage of NIST 800-53 SI-4/SI-3 and CIS Controls v8.

### Track and bonus categories

**Track: Security.** Bonus categories targeted: **Splunk Hosted Models** (primary — CDTSM, Foundation-Sec, gpt-oss), **Splunk MCP Server**, and **Splunk Developer Tools** (SDK app patterns, AppInspect-validated packaging).

---

## 3. Three-minute video script

Voiceover paced at ~150 words per minute (~2.5 words/second). Total VO ~355 words — comfortable inside 3:00. Record the screen segments first, then narrate.

| Time | Screen | Voiceover |
|---|---|---|
| 0:00–0:12 | Title card: "Aegis Foundry — the SOC that maintains itself", then README hero line | "Every SOC has an AI that triages alerts faster. Nobody fixed why there are too many alerts. Aegis Foundry is the fix: autonomous detection engineering, inside Splunk." (27 words) |
| 0:12–0:35 | `architecture_diagram.md` system-overview diagram; slow pan across the ten agents and the Splunk MCP / hosted-models boxes | "Ten governed agents run the full detection lifecycle. Intel comes in; the Coverage Cartographer maps it against MITRE ATT&CK and the live saved-search inventory over the Splunk MCP Server. Foundation-Sec and gpt-oss — Splunk hosted models — do the security reasoning and SPL authoring." (43 words) |
| 0:35–1:05 | Terminal: `python demo/run_pipeline.py --auto-approve` — banner, agents 1–6 streaming, pause on the backtest and forecast lines, then the v2 numbers | "Watch a full run. The author drafts a PowerShell detection for the uncovered technique. Then the part nobody else does: the Backtest Engineer replays it over ninety days of labeled history — fifty-eight hundred hits. The forecaster predicts 382 alerts a week. Way over budget. So the Tuning Optimizer tightens the rule and re-measures: 2.7 a week, and all seventeen labeled attacks still caught." (64 words) |
| 1:05–1:45 | Web console at `http://127.0.0.1:8787`: click Start Run with auto-approve off; pipeline stepper advances live; approval card appears — scroll the embedded evidence pack (SPL diff, backtest table, policy checks); click **Approve active** | "Now the same pipeline from the web console — pure standard library, no frameworks, fully offline. The stepper tracks the agents live. When the Governor needs a human, an approval card appears with the full evidence pack: the SPL diff, the backtest table, the forecast band, seven policy checks, and the model's rationale. I approve it as active, right from the browser, and the pipeline deploys it as a native Splunk saved search with a rollback token." (77 words) |
| 1:45–2:15 | Red-Team Gauntlet view (88% adversarial-recall ring), then the flight-recorder panel — zoom the verifier event and the "tamper-evident ledger verified" badge | "But backtest recall only measures the past. The Red-Team agent mutates those attacks into evasion variants and replays them — eighty-eight percent still fire, and the one gap is flagged for hardening. Then the Verifier grades reality against the forecast: drift one-point-one-one, inside the band. And every decision landed in a hash-chained, tamper-evident flight recorder — ingestible into Splunk itself." (60 words) |
| 2:15–2:40 | Console ATT&CK panel: the T1059.001 cell flips to **FORGED BY AEGIS**; quick cut to the `splunk_app` ATT&CK Coverage and Agent Flight Recorder dashboards | "On the ATT&CK panel, the gap cell flips to FORGED BY AEGIS — T-1059.001 went from gap to covered in one governed run. And it ships as a real Splunk app: AppInspect-validated, with coverage and flight-recorder dashboards bundled." (38 words) |
| 2:40–3:00 | Command Center ROI banner ("$295k/yr"), then README quickstart and closing card with repo URL and "Track: Security" | "And it proves its worth: this one rule books roughly two-hundred-ninety-five-thousand dollars a year in analyst time saved. Everything runs offline in sixty seconds — pip install, one command. Flip one variable and the same ten agents drive real Splunk, with CDTSM forecasting through the AI Toolkit. Aegis Foundry: the SOC that maintains itself." (52 words) |

Recording notes: capture the terminal at a large font (16pt+), keep the cursor still during pauses, and pre-run one pipeline so `runs/` has data for the console's run list before recording the web segment.

---

## 4. Submission checklist (mapped to the official rules)

- [ ] **Public repo** — push to GitHub and set visibility to public; confirm the repo loads in a logged-out/incognito window.
- [ ] **Visible OSS license** — `LICENSE` (Apache-2.0) is at the repo root; confirm GitHub shows the license badge on the repo page.
- [ ] **README with setup instructions** — verify the 60-second quickstart from a clean clone: `pip install -e .` → `python demo/run_pipeline.py --auto-approve` → `aegis-foundry audit` / `heatmap` / `ui`, plus `pytest` (39 tests).
- [ ] **`architecture_diagram.md` at repo root** — required artifact (`architecture_diagram.(md|pdf|png)`); confirm the Mermaid diagrams render on GitHub.
- [ ] **Video under 3 minutes, public** — upload to YouTube (public or unlisted-public per rules), verify playback while logged out, paste the link into the Devpost form. The video must show the project functioning.
- [ ] **Stage-1 pass/fail gate (theme + API fit)** — Splunk AI usage must be unmistakable in the first 30 seconds of the video and the top of the README (MCP Server, hosted models, AI Toolkit). Already covered by the script above; do not trim that section.
- [ ] **Track selection: Security** — select it explicitly in the Devpost form.
- [ ] **Bonus categories** — declare Hosted Models (primary), MCP Server, and Developer Tools usage in the description (a project can win at most one overall/track prize plus one bonus prize).
- [ ] **Tools/APIs/SDKs declared on the form** — Splunk MCP Server (Splunkbase app, token auth), Splunk AI Toolkit 5.7+ (`| ai`, `| apply CDTSM`), Splunk-hosted models (CDTSM, Foundation-Sec-1.1-8B, gpt-oss-120b/20b), Splunk AI Assistant `saia_*` tools, Splunk Management REST API, AppInspect, Python 3.10+ (stdlib-only runtime).
- [ ] **Team info** — max 2 members; both registered on Devpost and added to the submission.
- [ ] **Most Valuable Feedback form** — each teammate files it individually (5 separate individual prizes; independent of the project submission).
- [ ] **Paste from this kit** — project name, elevator pitch, and description from sections 1–2; no edits needed.
- [ ] **Final sweep** — judging is two-stage; Stage 2 weighs Technological Implementation, Design, Potential Impact, Quality of Idea equally (tiebreak in that order). Re-watch the video once against those four words.

---

## 5. Judge Q&A prep

**Q1. The rules are written by an LLM — what about hallucination?**
The architecture makes hallucinated detections structurally impossible to ship. Every generated rule must *execute* — SPL is syntax-validated live, with a self-correction loop in the Detection Author — and then *score* against 90 days of labeled history. The Governor's true-positive-preservation policy check hard-fails any rule that loses a labeled attack event (our demo rule retained 17/17 through tuning). The model's prose can be wrong; the backtest numbers in the evidence pack cannot. The agent's output is intrinsically verifiable, which is exactly the property triage copilots lack.

**Q2. Why not just use MLTK?**
MLTK gives you models; it has no lifecycle. It won't find your coverage gaps, write the SPL, decide whether a rule is too noisy to deploy, route it through change control, or notice post-deploy drift. We do use Splunk's model stack where it fits — CDTSM via `| apply` for zero-shot forecasting, which beats training a bespoke MLTK model per rule — but the contribution is the governed closed loop around the models, not the models.

**Q3. How does live mode actually differ from the mock demo?**
Same ten agents, same orchestrator, same state machine — the factory swaps adapters. In live mode the MCP client speaks to a real Splunk MCP Server, backtests run as real searches over a labeled index (e.g. BOTS v3), the Deployer writes real saved searches via the Management REST API, and LLM calls go through `| ai` or any OpenAI-compatible endpoint. Mock mode replays recorded fixtures over a synthetic BOTS-style labeled corpus so judges can run everything offline. The state files, evidence packs, and flight recorder are byte-identical in shape across both modes — the tests assert it.

**Q4. CDTSM is Splunk Cloud-only. What if a judge can't reach it?**
Then the Noise Forecaster degrades to a deterministic EWMA-plus-seasonal model and labels itself `fallback-ewma` in every forecast, evidence pack, and dashboard — honest degradation, never silent substitution. The demo runs fully offline on the fallback; on Splunk Cloud with AI Toolkit 5.7+ the identical code path issues `| apply CDTSM`. The budget-gating logic is model-agnostic by design.

**Q5. Why a 25-alerts/week budget? Isn't that arbitrary?**
The number is a configurable default (`--fp-budget`); 25/week is roughly what one analyst can triage per rule without fatigue. The point isn't the constant — it's that the budget is *explicit, per-rule, and enforced before deployment*. Today that contract doesn't exist anywhere: rules ship, then noise gets discovered in production. Any SOC can set its own number per severity tier.

**Q6. What breaks at enterprise scale — 500 rules, not one?**
Three things, all with clear paths. (1) Backtest cost: 90-day replays per version get expensive; move to sampled or summary-index backtests and parallelize the measurement loop, which is serial per rule today. (2) Approval throughput: one card per rule won't survive 50 pending rules; the broker contract already supports a queue, so batch review with portfolio-level noise budgeting is the v2 answer. (3) Cross-run memory is JSONL; at scale it belongs in a KV store or its own index. The state machine and governance gates themselves don't change.

**Q7. How is this different from detection-as-code CI/CD?**
CI validates syntax and maybe runs unit fixtures; it answers "does it parse?" Aegis answers "does it *work* and what will it *cost*?" — measured recall and precision against labeled history, plus a forecast of future alert volume enforced as a deploy gate. CI also doesn't author rules from threat intel, and it stops at deploy; our Verifier closes the loop afterward, measuring forecast drift and auto-rolling back runaways. Detection-as-code is the plumbing; Aegis is the engineer.

**Q8. What would v2 add?**
Live intel feeds (TAXII/MISP) replacing the advisory fixture; Enterprise Security integration so deployments land as ES correlation searches with risk-based alerting; a learned per-environment tuning policy from the cross-run episodic memory (the data is already collected every run); portfolio-level noise budgeting across the whole rule estate; SOAR handoff on verified detections; and RBAC on the approval console so approve-active and approve-shadow can be separated by role.
