# Aegis Foundry — Architecture

How the nine-agent detection-engineering pipeline interacts with Splunk, how the AI models are
integrated, and how data flows between components.

## System overview

```mermaid
graph TD
    subgraph Inputs
        ADV[Threat advisories /<br/>closed incidents /<br/>red-team findings]
    end

    subgraph "Aegis Foundry agent swarm (aegis_foundry/agents)"
        IS[1 Intel Scout]
        CC[2 Coverage Cartographer]
        DA[3 Detection Author<br/>self-correcting SPL]
        BE[4 Backtest Engineer]
        NF[5 Noise Forecaster]
        TO[6 Tuning Optimizer]
        GOV[7 Governor<br/>7 policy checks + evidence pack]
        DEP[8 Deployer]
        VER[9 Verifier]
    end

    subgraph "Splunk platform"
        MCP[Splunk MCP Server<br/>token auth, streamable HTTP<br/>READ PLANE]
        REST[Management REST API<br/>WRITE PLANE]
        IDX[(Indexes:<br/>botsv3 labeled history,<br/>aegis_audit flight recorder)]
        SS[savedsearches<br/>deployed detections]
        DASH[Aegis Foundry app:<br/>ATT&CK Coverage +<br/>Agent Flight Recorder dashboards]
    end

    subgraph "AI models"
        FSEC[Foundation-Sec-1.1-8B<br/>MITRE mapping, rationale]
        GPT[gpt-oss-120b / 20b<br/>authoring, tuning]
        CDTSM[Cisco Deep Time Series Model<br/>apply CDTSM / labeled EWMA fallback]
        SAIA[Splunk AI Assistant<br/>saia_generate_spl]
    end

    HUMAN([Human operator<br/>approve / shadow / reject])

    ADV --> IS --> CC --> DA --> BE --> NF --> TO
    TO -- "over budget: new version" --> BE
    TO -- "within budget" --> GOV
    GOV --- HUMAN
    GOV --> DEP --> VER
    VER -- "drift: retune" --> BE
    VER -- "runaway: rollback" --> REST

    CC <--> MCP
    BE <--> MCP
    VER <--> MCP
    DA <--> MCP
    MCP <--> IDX
    DA -.-> SAIA
    CC -.-> FSEC
    DA -.-> GPT
    TO -.-> GPT
    NF -.-> CDTSM
    CDTSM -.-> MCP
    DEP --> REST --> SS
    IS & CC & DA & BE & NF & TO & GOV & DEP & VER -- "audit events" --> FR[flight_recorder.jsonl]
    FR --> IDX --> DASH
```

## One rule's lifecycle (sequence, with the demo's real numbers)

```mermaid
sequenceDiagram
    participant Intel as Intel Scout
    participant Cov as Coverage Cartographer
    participant Auth as Detection Author
    participant Back as Backtest Engineer
    participant Fore as Noise Forecaster
    participant Tune as Tuning Optimizer
    participant Gov as Governor
    participant Hum as Human
    participant Dep as Deployer
    participant Ver as Verifier
    participant Spl as Splunk (MCP/REST)

    Intel->>Cov: CISA-AA26-117A -> T1059.001, T1003.001
    Cov->>Spl: list saved searches (MCP)
    Cov->>Auth: gap = T1059.001 (T1003.001 already covered)
    Auth->>Spl: validate SPL (MCP) - self-correct on error
    Auth->>Back: rule v1 (syntax valid)
    Back->>Spl: replay v1 over 90d labeled history (MCP)
    Back->>Fore: 5,818 hits (~382/wk), recall 17/17
    Fore->>Fore: forecast >> budget 25/wk
    Fore->>Tune: over budget
    Tune->>Back: rule v2 (+EncodedCommand, -svc_deploy)
    Back->>Spl: replay v2 (MCP)
    Back->>Fore: 42 hits, recall 17/17, precision 40%
    Fore->>Gov: predicted 2.7/wk - WITHIN BUDGET
    Gov->>Hum: evidence pack (SPL diff, stats, 7 policy checks)
    Hum->>Gov: approve [a]ctive
    Gov->>Dep: APPROVE_ACTIVE
    Dep->>Spl: create saved search (REST) + rollback token
    Ver->>Spl: observe first week (MCP)
    Ver->>Ver: observed 3.0/wk vs forecast 2.7/wk - drift 1.11, in band
    Ver-->>Spl: status VERIFIED -> heatmap flips to COVERED BY AEGIS
```

## Deployment modes and the audit path

```mermaid
graph LR
    subgraph "Mode A: Splunk Cloud (hosted models)"
        A1[AI Toolkit 5.7+] --> A2["apply CDTSM (zero-shot forecast)"]
        A1 --> A3["ai command -> Foundation-Sec / gpt-oss<br/>data never leaves Splunk"]
    end
    subgraph "Mode B: Anywhere (open weights)"
        B1[docker compose: splunk + ollama] --> B2["gpt-oss:20b via Ollama<br/>Foundation-Sec via vLLM"]
        B1 --> B3["fallback-ewma forecaster<br/>(honestly labeled in every artifact)"]
    end
    subgraph "Audit path (both modes)"
        C1[9 agents] --> C2[flight_recorder.jsonl] --> C3[(aegis_audit index)] --> C4[Flight Recorder dashboard]
    end
```

## Data flow

1. **Ingest** — Intel Scout loads advisories (live: Splunk modular-input pattern; demo: `demo/fixtures/advisories.json`) and extracts MITRE techniques with the security LLM.
2. **Map** — Coverage Cartographer pulls the saved-search inventory through the **Splunk MCP Server**, maps each rule to techniques, and emits coverage gaps with risk scores.
3. **Author** — Detection Author drafts SPL (gpt-oss / `saia_generate_spl`), then validates syntax through MCP and self-corrects on parser errors.
4. **Measure** — Backtest Engineer replays the rule over labeled history (`botsv3`) via MCP and computes hits, precision, recall, and a continuous daily hit timeline. Noise Forecaster feeds that series to **CDTSM** (`| apply CDTSM`, or the labeled EWMA fallback) and converts the 14-day forecast into a predicted weekly alert rate vs. the false-positive budget.
5. **Tune** — over-budget rules go back to the Tuning Optimizer for a tightened version; the loop re-measures until within budget or attempts are exhausted.
6. **Govern** — the Governor runs 7 policy checks, writes the evidence pack, and gates on a human decision (active / shadow / reject).
7. **Deploy** — the Deployer creates the saved search through the **management REST API** with a rollback token; shadow deployments track without alerting.
8. **Verify** — the Verifier compares the first post-deploy week against the forecast band; drift triggers a re-tune, runaway noise triggers automatic rollback.
9. **Audit** — every step lands in the flight recorder (JSONL → `aegis_audit` index → dashboards): the agents are observable in Splunk itself.

## Trust boundaries

- **Read plane vs. write plane** — all agent *reads* go through the Splunk MCP Server (scoped bearer token, RBAC enforced server-side). The only *write* path (saved-search deployment, rollback) is the REST admin client, and it is reachable solely from the Deployer/Verifier **after** a Governor decision. A compromised or hallucinating authoring agent cannot deploy anything.
- **Model boundary** — in Splunk Cloud mode, prompts and telemetry stay inside the Splunk perimeter (hosted models via `| ai` / `apply CDTSM`). In open-weight mode, models run on infrastructure you control; no third-party AI API is required anywhere.
- **Human boundary** — `auto_approve` is an explicit demo/CI flag; the default path requires a human verdict, with shadow deploy as the safe default and rollback tokens on every change.
