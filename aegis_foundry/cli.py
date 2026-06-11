"""Command-line interface for Aegis Foundry.

Subcommands:

- ``run``      execute the nine-agent detection pipeline (mock or live).
- ``audit``    pretty-print a run's agent flight recorder as a table.
- ``heatmap``  render a terminal ATT&CK coverage mini-matrix for a run.

The console-script entry point (``aegis-foundry = aegis_foundry.cli:main``)
returns an exit code: 0 when the pipeline reached DONE, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Optional

from aegis_foundry.config import AppConfig
from aegis_foundry.orchestrator import paint, run_pipeline, summarize_detail
from aegis_foundry.state import PipelineStage

__all__ = ["main"]


# Minimal offline catalog so covered (non-gap) techniques still render with a
# human-readable name and tactic. Gap techniques carry their own names in the
# state, which always takes precedence over this table.
_TECHNIQUE_CATALOG: dict[str, tuple[str, str]] = {
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1053.005": ("Scheduled Task", "Execution"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
}


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _resolve_run_dir(runs_dir: Path, run_id: Optional[str]) -> Optional[Path]:
    """Locate a run directory: explicit --run-id, or the most recent run."""
    if run_id:
        candidate = runs_dir / run_id
        return candidate if candidate.is_dir() else None
    if not runs_dir.is_dir():
        return None
    candidates = [
        p for p in runs_dir.iterdir()
        if p.is_dir() and ((p / "flight_recorder.jsonl").exists()
                           or (p / "state.json").exists())
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _load_state_dict(run_dir: Path) -> Optional[dict[str, Any]]:
    """Load runs/<run_id>/state.json as a plain dict, or None if absent."""
    state_path = run_dir / "state.json"
    if not state_path.exists():
        return None
    with open(state_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _names_from_audit(audit: list[dict[str, Any]]) -> dict[str, tuple[str, str]]:
    """Harvest technique names/tactics from coverage audit-event details."""
    found: dict[str, tuple[str, str]] = {}
    for evt in audit:
        detail = evt.get("detail") or {}
        if not isinstance(detail, dict):
            continue
        tid = detail.get("technique_id") or detail.get("technique")
        if not (isinstance(tid, str) and tid.startswith("T")):
            continue
        name = str(detail.get("technique_name") or "")
        tactic = str(detail.get("tactic") or "")
        prev_name, prev_tactic = found.get(tid, ("", ""))
        found[tid] = (name or prev_name, tactic or prev_tactic)
    return found


def _existing_rule_for(technique: str, existing_rules: list[dict[str, Any]]) -> str:
    """Best-effort name of the pre-existing saved search covering a technique."""
    for rule in existing_rules:
        try:
            blob = json.dumps(rule, default=str)
        except (TypeError, ValueError):
            blob = str(rule)
        if technique in blob:
            return str(rule.get("name") or rule.get("title") or "existing saved search")
    return ""


# --------------------------------------------------------------------------
# Subcommand: run
# --------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    """Build AppConfig from env, apply CLI overrides, run the pipeline."""
    cfg = AppConfig.from_env()
    if args.mode:
        cfg.mode = args.mode
    if args.auto_approve:
        cfg.auto_approve = True
    if args.fp_budget is not None:
        cfg.fp_budget_weekly = float(args.fp_budget)
    if args.max_tuning_iterations is not None:
        cfg.max_tuning_iterations = int(args.max_tuning_iterations)
    if args.fixtures_dir:
        cfg.fixtures_dir = Path(args.fixtures_dir)
    state = run_pipeline(cfg)
    return 0 if state.stage is PipelineStage.DONE else 1


# --------------------------------------------------------------------------
# Subcommand: audit (agent flight recorder view)
# --------------------------------------------------------------------------


def cmd_audit(args: argparse.Namespace) -> int:
    """Pretty-print the flight-recorder JSONL of a run as a table."""
    runs_dir = Path(AppConfig.from_env().runs_dir)
    run_dir = _resolve_run_dir(runs_dir, args.run_id)
    if run_dir is None:
        print(f"no run found under '{runs_dir}'"
              + (f" with id '{args.run_id}'" if args.run_id else ""))
        return 1
    recorder = run_dir / "flight_recorder.jsonl"
    if not recorder.exists():
        print(f"flight recorder not found: {recorder}")
        return 1

    events: list[dict[str, Any]] = []
    for line in recorder.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    width = shutil.get_terminal_size((120, 24)).columns
    detail_w = max(24, width - (4 + 1 + 8 + 1 + 22 + 1 + 26 + 1))

    print(paint(f"AGENT FLIGHT RECORDER - {run_dir.name}", "bold"))
    header = f"{'SEQ':>4} {'TIME':<8} {'AGENT':<22} {'ACTION':<26} DETAIL"
    print(paint(header, "bold"))
    print("-" * min(width, len(header) + detail_w))
    for evt in events:
        ts = str(evt.get("ts", ""))
        time_part = ts[11:19] if len(ts) >= 19 else ts
        agent = str(evt.get("agent", ""))
        action = str(evt.get("action", ""))
        detail = summarize_detail(evt.get("detail") or {}, max_len=detail_w)
        row = (f"{evt.get('seq', 0):>4} {time_part:<8} {agent:<22.22} "
               f"{action:<26.26} {detail}")
        print(paint(row, "red") if action in ("error", "agent_failed") else row)
    print(f"\n{len(events)} audit events - {recorder}")
    return 0


# --------------------------------------------------------------------------
# Subcommand: heatmap (terminal ATT&CK coverage mini-matrix)
# --------------------------------------------------------------------------


def cmd_heatmap(args: argparse.Namespace) -> int:
    """Render technique coverage for a run, grouped by ATT&CK tactic."""
    runs_dir = Path(AppConfig.from_env().runs_dir)
    run_dir = _resolve_run_dir(runs_dir, args.run_id)
    if run_dir is None:
        print(f"no run found under '{runs_dir}'"
              + (f" with id '{args.run_id}'" if args.run_id else ""))
        return 1
    data = _load_state_dict(run_dir)
    if data is None:
        print(f"state file not found: {run_dir / 'state.json'}")
        return 1

    gaps = {g.get("technique_id", ""): g for g in data.get("gaps", [])}
    rules = data.get("rules", {})
    existing_rules = data.get("existing_rules", [])
    audit_names = _names_from_audit(data.get("audit", []))

    # Techniques newly covered by an Aegis deployment this run.
    aegis_cover: dict[str, dict[str, str]] = {}
    for rid, dep in data.get("deployments", {}).items():
        if dep.get("rolled_back"):
            continue
        rule = rules.get(rid) or {}
        for tid in rule.get("mitre_techniques", []):
            aegis_cover[tid] = {
                "search": str(dep.get("saved_search_name") or rule.get("name") or rid),
                "mode": str(dep.get("mode") or ""),
            }

    universe: list[str] = list(dict.fromkeys(
        [t for item in data.get("intel", []) for t in item.get("mitre_techniques", [])]
        + list(gaps.keys())
        + list(aegis_cover.keys())
    ))
    if not universe:
        print(f"run {run_dir.name} references no ATT&CK techniques")
        return 0

    def resolve(tid: str) -> tuple[str, str]:
        gap = gaps.get(tid) or {}
        name = str(gap.get("technique_name") or "")
        tactic = str(gap.get("tactic") or "")
        a_name, a_tactic = audit_names.get(tid, ("", ""))
        c_name, c_tactic = _TECHNIQUE_CATALOG.get(tid, ("", ""))
        return (name or a_name or c_name, tactic or a_tactic or c_tactic)

    by_tactic: dict[str, list[str]] = {}
    for tid in universe:
        _, tactic = resolve(tid)
        by_tactic.setdefault(tactic or "Uncategorized", []).append(tid)

    print(paint(f"ATT&CK COVERAGE - {run_dir.name}", "bold"))
    print("-" * 78)
    for tactic, tids in by_tactic.items():
        print(paint(tactic, "bold"))
        for tid in tids:
            name, _ = resolve(tid)
            if tid in aegis_cover:
                tag, color = "[COVERED BY AEGIS]", "cyan"
                info = aegis_cover[tid]
                via = f"via '{info['search']}'"
                if info["mode"]:
                    via += f" ({info['mode']} mode)"
            elif tid in gaps:
                tag, color = "[GAP]", "red"
                partial = gaps[tid].get("existing_rule_names") or []
                via = (f"partial: {', '.join(partial)}" if partial
                       else "no existing detection")
            else:
                tag, color = "[COVERED]", "green"
                rule_name = _existing_rule_for(tid, existing_rules)
                via = f"via '{rule_name}'" if rule_name else "existing coverage"
            print(f"  {tid:<11} {name:<32.32} {paint(f'{tag:<19}', color)} {via}")
    print("-" * 78)

    closed = sum(1 for t in universe if t in gaps and t in aegis_cover)
    open_gaps = sum(1 for t in universe if t in gaps and t not in aegis_cover)
    covered = len(universe) - closed - open_gaps
    print(f"techniques: {len(universe)} | already covered: {covered} | "
          f"closed by aegis this run: {closed} | open gaps: {open_gaps}")
    return 0


# --------------------------------------------------------------------------
# Parser / entry point
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construct the aegis-foundry argument parser."""
    parser = argparse.ArgumentParser(
        prog="aegis-foundry",
        description=("Aegis Foundry - autonomous detection engineering for "
                     "Splunk: gap-finding, SPL authoring, backtesting, noise "
                     "forecasting, governed deployment."),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="execute the nine-agent detection pipeline")
    run_p.add_argument("--mode", choices=("mock", "live"), default=None,
                       help="override AEGIS_MODE (mock = offline fixtures)")
    run_p.add_argument("--auto-approve", action="store_true",
                       help="let the Governor auto-approve instead of prompting")
    run_p.add_argument("--fp-budget", type=float, default=None,
                       help="max acceptable expected alerts/week per rule")
    run_p.add_argument("--max-tuning-iterations", type=int, default=None,
                       help="cap on tuning passes per rule")
    run_p.add_argument("--fixtures-dir", type=str, default=None,
                       help="override the demo fixtures directory (mock mode)")
    run_p.set_defaults(func=cmd_run)

    audit_p = sub.add_parser(
        "audit", help="pretty-print a run's agent flight recorder")
    audit_p.add_argument("--run-id", default=None,
                         help="run directory name (default: latest run)")
    audit_p.set_defaults(func=cmd_audit)

    heat_p = sub.add_parser(
        "heatmap", help="terminal ATT&CK coverage mini-matrix for a run")
    heat_p.add_argument("--run-id", default=None,
                        help="run directory name (default: latest run)")
    heat_p.set_defaults(func=cmd_heatmap)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns a process exit code (0 success, 1 failure)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
