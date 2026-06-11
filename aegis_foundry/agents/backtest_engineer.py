"""Backtest Engineer agent.

Replays each candidate detection's SPL over a historical window (default 90
days) through the Splunk MCP search plane and measures how it would have
behaved: total hits, true/false positives against the labeled ground truth,
precision, recall, a continuous daily hit timeline (the fixed-resolution
series the Noise Forecaster consumes), and a handful of sample hits for the
evidence pack.

The agent is deliberately dumb about SPL semantics: it asks the MCP client
for the raw matching events and computes every metric in plain Python, so the
exact same code paths run against the deterministic mock corpus and a live
Splunk deployment.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import MCPError, SearchResult
from aegis_foundry.state import (
    BacktestResult,
    PipelineStage,
    PipelineState,
    RuleStatus,
)

#: Length of the historical replay window, in days.
WINDOW_DAYS: int = 90

#: Splunk-style earliest-time bound matching :data:`WINDOW_DAYS`.
EARLIEST: str = f"-{WINDOW_DAYS}d"

#: Upper bound on events fetched per backtest search.
MAX_RESULTS: int = 10000

#: The only fields surfaced in ``BacktestResult.sample_hits``.
SAMPLE_FIELDS: tuple[str, ...] = ("_time", "host", "user", "process_name", "CommandLine")


def _parse_event_time(raw: Any) -> Optional[datetime]:
    """Parse an event ``_time`` value into an aware UTC datetime.

    Accepts ISO-8601 strings (including a trailing ``Z``). Returns ``None``
    for missing or unparseable values so a single malformed event cannot
    abort an entire backtest.
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_hit_timeline(events: list[dict[str, Any]], window_days: int) -> list[dict[str, Any]]:
    """Bucket events into a continuous daily series covering the full window.

    Every day between the start and end of the window appears exactly once,
    including zero-count days, because the downstream forecaster requires a
    fixed-resolution series. The window is anchored on the most recent event
    day (or today, UTC, when there are no events) and extends back at least
    ``window_days`` days — further if an event predates that bound, so no hit
    is ever dropped from the series.

    Returns ``[{"_time": "YYYY-MM-DDT00:00:00+00:00", "count": n}, ...]``
    in ascending day order.
    """
    day_counts: dict[date, int] = {}
    for event in events:
        dt = _parse_event_time(event.get("_time"))
        if dt is None:
            continue
        day = dt.date()
        day_counts[day] = day_counts.get(day, 0) + 1

    if day_counts:
        end_day = max(day_counts)
        start_day = min(min(day_counts), end_day - timedelta(days=window_days - 1))
    else:
        end_day = datetime.now(timezone.utc).date()
        start_day = end_day - timedelta(days=window_days - 1)

    timeline: list[dict[str, Any]] = []
    day = start_day
    while day <= end_day:
        timeline.append(
            {"_time": f"{day.isoformat()}T00:00:00+00:00", "count": day_counts.get(day, 0)}
        )
        day += timedelta(days=1)
    return timeline


class BacktestEngineer(Agent):
    """Measures every pending rule version against the historical corpus."""

    name = "backtest-engineer"

    def run(self, state: PipelineState) -> PipelineState:
        """Backtest each rule awaiting measurement, then advance to FORECAST.

        Rules are eligible when their status is ``SYNTAX_VALID`` (fresh from
        the Detection Author) or ``TUNED`` (a new version from the Tuning
        Optimizer) and no backtest is stored yet for their current version —
        the version guard keeps the orchestrator's measure/tune loop from
        re-running finished work.
        """
        ground_truth: Optional[list[dict[str, Any]]] = None  # fetched lazily, once per run

        for rule in list(state.rules.values()):
            if rule.status not in (RuleStatus.SYNTAX_VALID, RuleStatus.TUNED):
                continue
            existing = state.backtests.get(rule.rule_id)
            if existing is not None and existing.rule_version == rule.version:
                continue  # this version is already measured

            try:
                result = self.ctx.mcp.run_search(
                    rule.spl, earliest=EARLIEST, max_results=MAX_RESULTS
                )
            except MCPError as exc:
                result = SearchResult(spl=rule.spl, error=str(exc))

            if result.error:
                state.backtests[rule.rule_id] = BacktestResult(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    window_days=WINDOW_DAYS,
                    syntax_valid=False,
                    error=result.error,
                )
                self.fail(
                    state,
                    f"backtest search failed for {rule.rule_id} v{rule.version}: {result.error}",
                )
                continue

            events = result.results
            total_hits = len(events)
            techniques = set(rule.mitre_techniques)
            true_positives = sum(
                1
                for e in events
                if e.get("label") == "malicious" and e.get("technique") in techniques
            )
            false_positives = total_hits - true_positives

            if ground_truth is None:
                ground_truth = self._fetch_ground_truth(state)
            labeled_attack_events = sum(
                1 for e in ground_truth if e.get("technique") in techniques
            )

            precision = true_positives / total_hits if total_hits else 0.0
            recall = (
                true_positives / labeled_attack_events if labeled_attack_events else 1.0
            )
            timeline = build_hit_timeline(events, WINDOW_DAYS)
            sample_hits = [
                {field: e.get(field, "") for field in SAMPLE_FIELDS} for e in events[:5]
            ]

            state.backtests[rule.rule_id] = BacktestResult(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                window_days=WINDOW_DAYS,
                syntax_valid=True,
                total_hits=total_hits,
                true_positives=true_positives,
                false_positives=false_positives,
                precision=precision,
                recall=recall,
                labeled_attack_events=labeled_attack_events,
                hit_timeline=timeline,
                sample_hits=sample_hits,
            )

            # Status change only — same version, fresh object so rule_history
            # keeps the pre-backtest snapshot intact.
            state.upsert_rule(
                replace(
                    rule,
                    status=RuleStatus.BACKTESTED,
                    mitre_techniques=list(rule.mitre_techniques),
                    tuning_notes=list(rule.tuning_notes),
                )
            )

            weekly_rate = round(total_hits / (WINDOW_DAYS / 7), 1)
            self.emit(
                state,
                "backtest_completed",
                {
                    "rule_id": rule.rule_id,
                    "version": rule.version,
                    "total_hits": total_hits,
                    "weekly_rate": weekly_rate,
                    "precision": round(precision, 4),
                    "recall": round(recall, 4),
                },
            )

        state.stage = PipelineStage.FORECAST
        return state

    # ---- internals ----

    def _fetch_ground_truth(self, state: PipelineState) -> list[dict[str, Any]]:
        """Fetch all labeled attack events in the window via a second search.

        The SPL only filters on the label; per-rule technique filtering
        happens in Python so one fetch serves every rule in the run. Returns
        an empty list (and records a non-fatal error) if the search fails,
        in which case recall defaults to 1.0 per the labeled==0 rule.
        """
        spl = f'index={self.ctx.config.splunk.backtest_index} label="malicious"'
        try:
            result = self.ctx.mcp.run_search(spl, earliest=EARLIEST, max_results=MAX_RESULTS)
        except MCPError as exc:
            self.fail(state, f"ground-truth search failed: {exc}")
            return []
        if result.error:
            self.fail(state, f"ground-truth search failed: {result.error}")
            return []
        return [e for e in result.results if e.get("label") == "malicious"]
