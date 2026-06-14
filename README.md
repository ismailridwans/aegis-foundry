# Aegis Foundry

**The SOC that maintains itself.** An autonomous detection-engineering platform for Splunk: ten governed AI agents that find MITRE ATT&CK coverage gaps, author SPL detections, **backtest them against labeled history via the Splunk MCP Server**, **forecast their alert-noise burden with the Cisco Deep Time Series Model before deployment**, tune them to a false-positive budget, **red-team them against MITRE-faithful evasion variants**, route them through human approval with a full evidence pack, deploy them as native Splunk saved searches — then verify that reality matched the forecast, **quantify the dollar impact**, and **attest the framework controls** they satisfy. Every agent action is recorded in a **tamper-evident, hash-chained audit ledger**.

![CI](../../actions/workflows/ci.yml/badge.svg)
**Track:** Security · **Built for the Splunk Agentic Ops Hackathon**

---

## The problem

Detection engineering is the SOC's broken factory. Enterprises run hundreds of correlation searches; a large fraction are stale, broken by schema drift, or were never tuned to the environment they run in. Covering a new threat technique takes days to weeks, because every rule needs authoring, historical validation, false-positive tuning, and change control — all manual.

Downstream, analysts drown in alerts. But alert fatigue is a *symptom*: the cause is untuned, unmeasured detection logic upstream. Every AI copilot that triages alerts faster is mopping the floor. Nobody fixed the faucet.

Aegis Foundry closes the loop *inside Splunk*: gap detection → authoring → backtest → noise forecast → tune → governed deploy → post-deploy verification. Detections stop being artifacts someone wrote once — they become continuously measured, continuously maintained assets.

## What it does (the demo storyline, with real numbers)

One offline run of `demo/run_pipeline.py` reproduces this end-to-end:

1. **Intel Scout** ingests a threat advisory (encoded-PowerShell credential theft, CISA-AA26-117A) → extracts **T1059.001** and **T1003.001**.
2. **Coverage Cartographer** inventories the existing saved searches via MCP → T1003.001 is covered, **T1059.001 is a gap**.
3. **Detection Author** drafts a detection, self-correcting its SPL against live syntax validation.
4. **Backtest Engineer** replays it over 90 days of labeled history via the MCP search plane: **5,818 hits (~382/week)** — recall 100%, precision 0.3%.
5. **Noise Forecaster** forecasts the rule's future fire-rate: **massively over the 25-alerts/week budget**.
6. **Tuning Optimizer** tightens the rule (encoded-command flag, excludes the automation account) → re-backtest: **42 hits (~2.7/week predicted), all 17/17 labeled true positives retained**, precision 40%.
7. **Red-Team** mutates the labeled attacks into 24 MITRE-faithful evasion variants (case folding, flag aliasing, whitespace tricks, payload swaps) and replays them: **21/24 still fire — 88% adversarial recall.** The one gap (the `-enc` abbreviation) is flagged as a hardening opportunity.
8. **Governor** runs **8 policy checks** (now including adversarial robustness), writes a Markdown **evidence pack** (SPL diff, backtest table, forecast verdict, gauntlet results), and asks a human — or auto-approves in demo mode.
9. **Deployer** ships it as a native Splunk saved search (with rollback token).
10. **Verifier** watches the first post-deploy week: **observed 3.0/week vs forecast 2.7/week — inside the 90% band.** The ATT&CK heatmap cell flips from GAP to **FORGED BY AEGIS**.

The run closes with an **ROI ledger** (≈449.8 alerts/week avoided ≈ **$295k/year** of analyst time, plus authoring cost and MTTD compression) and a **compliance attestation** mapping the new detection to NIST 800-53 (SI-4, SI-3) and CIS Controls v8. Every agent action lands in a **tamper-evident, hash-chained flight recorder** that is itself Splunk-ingestible: the agentic system is observable *and provable* in the same pane of glass as the security data it manages.

## 60-second quickstart (no Splunk, no credentials)

```bash
pip install -e .
python demo/run_pipeline.py --auto-approve   # full 10-agent pipeline, offline
aegis-foundry audit                          # the agent flight recorder
aegis-foundry heatmap                        # ATT&CK coverage before/after
```

Drop `--auto-approve` to experience the human-in-the-loop governance gate: the Governor prints the evidence summary and waits for `[a]ctive / [s]hadow / [r]eject`.

Run the tests: `pip install -e .[dev] && pytest` (39 tests, including the full end-to-end storyline, the Red-Team gauntlet, the ROI ledger, the tamper-evident audit chain, compliance mapping, and a real-HTTP web-approval flow).

## Web console

```bash
aegis-foundry ui          # then open http://127.0.0.1:8787
```

A stdlib-only web console — no frameworks, no CDN, works fully offline — built as an **eleven-view, navigation-driven operations dashboard** in liquid-glass design: a **Command Center** with an ROI banner and headline KPIs, the **live pipeline** stepper as the ten agents hand off, **ATT&CK coverage**, a **Noise Lab** (backtest vs forecast + CDTSM confidence-band chart), the **Red-Team Gauntlet** (adversarial-recall rings and the evasion-variant ledger), **Governance** with browser-based approvals and the 8-check policy gate, **Deployments** with rollback tokens and drift, **Compliance** attestations, the tamper-evident **Flight Recorder**, the **AI Model** stack, and **Run History**. Recommended demo flow: start a run with auto-approve **off** (the default), then make the active/shadow/reject call from the browser — the Governor blocks on your decision and falls back to safe shadow deployment on timeout.

## Live mode (real Splunk)

Set `AEGIS_MODE=live` and the **same ten agents** drive a real deployment. Copy [.env.example](.env.example) and fill in:

| Variable | Purpose |
|---|---|
| `SPLUNK_MCP_URL` / `SPLUNK_MCP_TOKEN` | Splunk MCP Server (Splunkbase app), bearer-token auth — OAuth is not yet GA |
| `SPLUNK_REST_URL` / `SPLUNK_REST_TOKEN` | Management REST API used by the Deployer (the governed write plane) |
| `AEGIS_BACKTEST_INDEX` | Labeled historical data — e.g. the public Splunk **BOTS v3** dataset (`botsv3`) |
| `AEGIS_LLM_BASE_URL` | Any OpenAI-compatible endpoint for the authoring models |

**Models, two ways:**

- **Splunk Cloud (hosted models):** AI Toolkit 5.7+ gives the Noise Forecaster real `| apply CDTSM` zero-shot forecasting and the `| ai` command path to Splunk-hosted **Foundation-Sec-1.1-8B** and **gpt-oss** — data never leaves Splunk.
- **Anywhere else (open weights):** `docker compose up -d splunk ollama`, then `ollama pull gpt-oss:20b` (and/or serve `fdtn-ai/Foundation-Sec-1.1-8B-Instruct` via vLLM). When CDTSM is unreachable the forecaster degrades to a deterministic EWMA + seasonal model and **labels itself honestly** (`fallback-ewma`) in every forecast, evidence pack, and dashboard.

## How this uses Splunk's AI stack

| Splunk capability | Where it lives in Aegis Foundry |
|---|---|
| **Splunk MCP Server** (streamable HTTP, token auth) | [`core/mcp_client.py`](aegis_foundry/core/mcp_client.py) — the agents' *only* read plane: search execution, SPL validation, saved-search discovery |
| **Hosted model: Cisco Deep Time Series Model** | [`core/hosted_models.py`](aegis_foundry/core/hosted_models.py) — `| apply CDTSM` via the search plane (`forecast_from_spl`), honest labeled fallback |
| **Hosted model: Foundation-Sec-1.1-8B** | Security reasoning + MITRE mapping ([`agents/coverage_cartographer.py`](aegis_foundry/agents/coverage_cartographer.py)); servable open-weight for judges |
| **Hosted models: gpt-oss-120b / 20b** | Detection authoring + tuning ([`agents/detection_author.py`](aegis_foundry/agents/detection_author.py), [`agents/tuning_optimizer.py`](aegis_foundry/agents/tuning_optimizer.py)) |
| **AI Toolkit `\| ai` command** | [`core/llm.py`](aegis_foundry/core/llm.py) `SplunkAICommandLLM` — completions routed through SPL so data stays in Splunk |
| **Splunk AI Assistant (`saia_*` MCP tools)** | `generate_spl` in the MCP client — NL→SPL drafting path |
| **Python SDK app patterns** | [`splunk_app/`](splunk_app/) — packaged app with custom alert action (`aegis_triage`), modular-input-style intel feed, ATT&CK Coverage + Flight Recorder dashboards |
| **AppInspect / dev tools** | [`scripts/package_app.py`](scripts/package_app.py) + [`ci.yml`](.github/workflows/ci.yml) `appinspect` job (precert mode, failures block the build) |

## Governance & safety

Agentic ops without governance is a liability. Aegis Foundry treats trust as a feature:

- **Evidence packs** — every proposal ships with the SPL diff, backtest table, forecast band, adversarial-robustness results, and **8 explicit policy checks** (true-positive preservation, noise budget, adversarial robustness, blast-radius scan for destructive SPL, …). See a real one in [`runs/`](runs/) after any demo run.
- **Human-in-the-loop** — interactive approval with shadow-deploy as the safe default; `auto-approve` is an explicit demo/CI flag. This implements the human-oversight guidance from the Foundation-Sec model card.
- **Shadow mode & rollback** — every deployment returns a rollback token; the Verifier auto-rolls back runaway rules (>10× budget).
- **Tamper-evident flight recorder** — append-only JSONL audit of every agent decision, **SHA-256 hash-chained** (each event binds the prior event's hash, so editing any past entry breaks the chain — `verify_audit_chain()` pinpoints where). Ingestible into the `aegis_audit` index and visualized in the bundled **Agent Flight Recorder** dashboard.
- **Read/write separation** — agents read through MCP; the only write path (deployment) sits behind the Governor.

## Beyond the baseline — four deep capabilities

Most detection tooling stops at "the agent wrote a rule." Aegis Foundry goes further:

- **Adversarial Robustness Gauntlet** (a 10th agent, the `HARDEN` stage) — backtest recall only measures the *past*. The Red-Team agent mutates each within-budget rule's labeled true positives into MITRE-faithful evasion variants and replays them against the rule's own SPL predicate, reporting **adversarial recall** and concrete hardening gaps. It feeds an 8th Governor policy check. [`agents/red_team.py`](aegis_foundry/agents/red_team.py), [`core/spl_match.py`](aegis_foundry/core/spl_match.py)
- **ROI ledger** — converts the run's *measured* numbers (noise avoided, detections shipped, time-to-coverage) into analyst-hours, dollars, and MTTD-days saved (~**$295k/yr** on the demo). [`core/roi.py`](aegis_foundry/core/roi.py)
- **Tamper-evident audit ledger** — the flight recorder is a verifiable hash chain. [`state.py`](aegis_foundry/state.py) `verify_audit_chain()`, exposed at `GET /api/runs/{id}/audit`.
- **Compliance attestation** — maps each forged technique to NIST 800-53 and CIS Controls v8 safeguards for an auditor-facing record. [`core/compliance.py`](aegis_foundry/core/compliance.py)

## Architecture

See **[architecture_diagram.md](architecture_diagram.md)** (required diagrams + data flow + trust boundaries).

```
aegis_foundry/          the platform
  agents/               the ten agents (intel_scout ... red_team ... verifier)
  core/                 MCP client, hosted models, LLM clients, audit, memory,
                        roi, compliance, spl_match, factory
  orchestrator.py       the lifecycle state machine
  web/                  stdlib console server + the eleven-view dashboard
  cli.py                run | audit | heatmap | ui
demo/                   offline golden path + synthetic BOTS-style labeled corpus
splunk_app/             installable Splunk app (dashboards, alert action, conf)
scripts/package_app.py  builds dist/aegis_foundry.spl
tests/                  39 tests incl. the full e2e storyline + deep-feature suites
```

## Submission

- **[docs/SUBMISSION.md](docs/SUBMISSION.md)** — the Devpost kit: elevator pitch, paste-ready description, 3-minute video script, rules checklist, and judge Q&A.

---

*Built for the **Splunk Agentic Ops Hackathon** (Security track). Designed to showcase the **Splunk MCP Server**, **Splunk Hosted Models** (CDTSM, Foundation-Sec, gpt-oss), and **Splunk Developer Tools** (SDK app patterns, AppInspect-validated packaging).*
