# Demo fixtures — provenance

Everything in this directory is **synthetic**. No real telemetry, hosts,
users, or commands appear here. The data is BOTS-style Windows
process-creation telemetry fabricated by `generate_fixtures.py` so the entire
Aegis Foundry pipeline runs offline, deterministically, with zero credentials.

## Files

| File | Contents |
| --- | --- |
| `generate_fixtures.py` | Deterministic generator (seed `1337`, fixed anchor `2026-06-14T12:00:00Z`, 90-day window). Verifies storyline invariants with assertions before writing. |
| `attack_events.json` | ~7,000 labeled events: 17 malicious encoded-PowerShell executions (T1059.001), ~5,800 benign PowerShell (mostly `svc_deploy` scheduled jobs plus admin/helpdesk usage), ~25 benign encoded-admin events, ~1,200 non-PowerShell noise. |
| `advisories.json` | One `ThreatIntel` record: CISA AA26-117A (encoded PowerShell → LSASS credential theft; T1059.001 + T1003.001). |
| `existing_saved_searches.json` | Four pre-existing detections. T1003.001 is covered; **nothing covers T1059.001** — that is the demo's coverage gap. |

## Event schema (`attack_events.json`)

```json
{
  "_time": "ISO-8601 UTC timestamp",
  "index": "botsv3",
  "sourcetype": "WinEventLog:Security",
  "host": "WS-FIN-042",
  "user": "jsmith",
  "EventCode": "4688",
  "process_name": "powershell.exe",
  "CommandLine": "powershell.exe -NoProfile -EncodedCommand JAB...",
  "label": "malicious | benign",
  "technique": "T1059.001 | null"
}
```

`label` and `technique` are ground-truth annotations used only by the mock
backtester to score precision/recall; a real Splunk index would not have them
inline (see live mode below).

## Regenerating

From the repository root:

```
python demo/fixtures/generate_fixtures.py
```

The script is fully deterministic (fixed seed and anchor): repeated runs
produce byte-identical files. It asserts the pinned counts (v1 draft matches
~5,800 events; tuned v2 matches exactly 17 malicious + 25 benign; the final
7 days contain 2–3 v2 hits) and prints them on success.

## Swapping in the real Splunk BOTS v3 dataset (live mode)

In live mode (`AEGIS_MODE=live`) the agents search a real Splunk deployment
through the Splunk MCP Server instead of these fixtures:

1. Install the [Splunk BOTS v3 dataset](https://github.com/splunk/botsv3)
   into an index named `botsv3` (or set `AEGIS_BACKTEST_INDEX` to your index).
2. The demo SPL targets `sourcetype="WinEventLog:Security"` `EventCode=4688`
   process-creation events, which BOTS v3 contains natively.
3. Ground-truth labels are not inline in real data. Provide them as a lookup
   (e.g. `attack_labels.csv` with `_time, host, CommandLine, label, technique`
   columns, enriched via `| lookup attack_labels ...`), or let the backtester
   fall back to scoring against the advisory's indicator list.
4. `advisories.json` and `existing_saved_searches.json` remain useful in live
   mode as the intel feed and as a floor for the saved-search inventory; the
   live client merges them with whatever `list_saved_searches` returns.
