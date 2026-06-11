# Aegis Foundry

**The SOC that maintains itself.** An autonomous detection-engineering platform for Splunk: nine governed AI agents that find MITRE ATT&CK coverage gaps, author SPL detections, **backtest them against labeled history via the Splunk MCP Server**, **forecast their alert-noise burden with the Cisco Deep Time Series Model before deployment**, tune them to a false-positive budget, route them through human approval with a full evidence pack, deploy them as native Splunk saved searches — and then verify that reality matched the forecast.

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
7. **Governor** runs 7 policy checks, writes a Markdown **evidence pack** (SPL diff, backtest table, forecast verdict), and asks a human — or auto-approves in demo mode.
8. **Deployer** ships it as a native Splunk saved search (with rollback token).
9. **Verifier** watches the first post-deploy week: **observed 3.0/week vs forecast 2.7/week — inside the 90% band.** The ATT&CK heatmap cell flips from GAP to **COVERED BY AEGIS**.

Every agent action lands in an immutable **flight recorder** that is itself Splunk-ingestible: the agentic system is observable in the same pane of glass as the security data it manages.

## 60-second quickstart (no Splunk, no credentials)

```bash
pip install -e .
python demo/run_pipeline.py --auto-approve   # full 9-agent pipeline, offline
aegis-foundry audit                          # the agent flight recorder
aegis-foundry heatmap                        # ATT&CK coverage before/after
```

Drop `--auto-approve` to experience the human-in-the-loop governance gate: the Governor prints the evidence summary and waits for `[a]ctive / [s]hadow / [r]eject`.

Run the tests: `pip install -e .[dev] && pytest` (21 tests, including the full end-to-end storyline).

## Live mode (real Splunk)

Set `AEGIS_MODE=live` and the **same nine agents** drive a real deployment. Copy [.env.example](.env.example) and fill in:

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

- **Evidence packs** — every proposal ships with the SPL diff, backtest table, forecast band, and 7 explicit policy checks (true-positive preservation, noise budget, blast-radius scan for destructive SPL, …). See a real one in [`runs/`](runs/) after any demo run.
- **Human-in-the-loop** — interactive approval with shadow-deploy as the safe default; `auto-approve` is an explicit demo/CI flag. This implements the human-oversight guidance from the Foundation-Sec model card.
- **Shadow mode & rollback** — every deployment returns a rollback token; the Verifier auto-rolls back runaway rules (>10× budget).
- **Flight recorder** — append-only JSONL audit of every agent decision, ingestible into the `aegis_audit` index and visualized in the bundled **Agent Flight Recorder** dashboard.
- **Read/write separation** — agents read through MCP; the only write path (deployment) sits behind the Governor.

## Architecture

See **[architecture_diagram.md](architecture_diagram.md)** (required diagrams + data flow + trust boundaries).

```
aegis_foundry/          the platform
  agents/               the nine agents (intel_scout ... verifier)
  core/                 MCP client, hosted models, LLM clients, audit, memory, factory
  orchestrator.py       the lifecycle state machine
  cli.py                run | audit | heatmap
demo/                   offline golden path + synthetic BOTS-style labeled corpus
splunk_app/             installable Splunk app (dashboards, alert action, conf)
scripts/package_app.py  builds dist/aegis_foundry.spl
tests/                  21 tests incl. the full e2e storyline
```

---

*Built for the **Splunk Agentic Ops Hackathon** (Security track). Designed to showcase the **Splunk MCP Server**, **Splunk Hosted Models** (CDTSM, Foundation-Sec, gpt-oss), and **Splunk Developer Tools** (SDK app patterns, AppInspect-validated packaging).*
