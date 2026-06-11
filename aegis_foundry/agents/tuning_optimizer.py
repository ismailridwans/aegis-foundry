"""Tuning Optimizer agent.

When a rule's forecast blows the weekly false-positive budget, this agent
asks the LLM to tighten the SPL — armed with the backtest statistics, the
noisiest false-positive users/processes, and the budget itself — and mints a
new rule version carrying the tuned SPL. Rules already within budget are
left untouched (a ``tuning_skipped`` audit records the decision), and rules
that have burned through the tuning allowance are marked RETUNE_REQUIRED for
a human.

The agent never advances the pipeline stage: the orchestrator inspects the
resulting state to decide whether to loop back to BACKTEST (new versions
need re-measurement) or move on to GOVERN (everything within budget or
exhausted).
"""

from __future__ import annotations

import json
from typing import Any, Optional

from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import LLMError, MCPError
from aegis_foundry.state import (
    BacktestResult,
    DetectionRule,
    ForecastResult,
    PipelineState,
    RuleStatus,
)

#: System prompt steering the model toward machine-parseable output.
SYSTEM_PROMPT: str = (
    "You are a senior Splunk detection engineer who tightens noisy SPL "
    "detections without losing a single true positive. Respond with strict "
    'JSON only — no markdown, no commentary — of the form: '
    '{"spl": "<tightened SPL>", "tuning_note": "<one-sentence rationale>"}'
)

#: Maximum number of false-positive users surfaced in the tuning prompt.
TOP_FP_USERS: int = 5


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract the first JSON object from an LLM response.

    Tolerates surrounding prose and markdown code fences, but the object
    itself must be strict JSON. Raises ``ValueError`` when no parseable
    object is present.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(cleaned)):
            ch = cleaned[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
            elif ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(cleaned[start : i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                    break
        start = cleaned.find("{", start + 1)
    raise ValueError("no JSON object found in model response")


class TuningOptimizer(Agent):
    """Tightens over-budget rules into new versions via the LLM."""

    name = "tuning-optimizer"

    def run(self, state: PipelineState) -> PipelineState:
        """Tune every rule whose current-version forecast exceeds the budget.

        For each rule with a forecast matching its current version:

        - within budget: audit ``tuning_skipped`` and leave the rule as-is;
        - over budget but out of iterations (``version`` greater than
          ``state.max_tuning_iterations``): record the failure and mark the
          rule RETUNE_REQUIRED;
        - over budget with iterations remaining: prompt the LLM for a
          tightened SPL, parse strict JSON ``{spl, tuning_note}``, and upsert
          a new version (history preserves the old one).

        The pipeline stage is intentionally left unchanged — the orchestrator
        decides whether to loop back to BACKTEST or advance to GOVERN.
        """
        for rule in list(state.rules.values()):
            forecast = state.forecasts.get(rule.rule_id)
            if forecast is None or forecast.rule_version != rule.version:
                continue  # no verdict yet for this version

            if forecast.within_budget:
                self.emit(
                    state,
                    "tuning_skipped",
                    {
                        "rule_id": rule.rule_id,
                        "version": rule.version,
                        "reason": "within budget",
                        "predicted_weekly": round(forecast.predicted_weekly_alerts, 1),
                        "fp_budget_weekly": state.fp_budget_weekly,
                    },
                )
                continue

            if rule.status == RuleStatus.RETUNE_REQUIRED:
                continue  # already flagged for a human; stay idempotent

            if rule.version > state.max_tuning_iterations:
                self.fail(
                    state,
                    f"tuning budget exhausted for {rule.rule_id} at v{rule.version} "
                    f"(max {state.max_tuning_iterations} iterations) — marking RETUNE_REQUIRED",
                )
                exhausted = DetectionRule(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    spl=rule.spl,
                    mitre_techniques=list(rule.mitre_techniques),
                    severity=rule.severity,
                    status=RuleStatus.RETUNE_REQUIRED,
                    version=rule.version,
                    parent_version=rule.parent_version,
                    gap_id=rule.gap_id,
                    cron_schedule=rule.cron_schedule,
                    tuning_notes=list(rule.tuning_notes),
                    created_at=rule.created_at,
                )
                state.upsert_rule(exhausted)
                continue

            backtest = state.backtests.get(rule.rule_id)
            prompt = self._build_prompt(state, rule, backtest, forecast)
            try:
                raw = self.ctx.llm.complete(
                    prompt,
                    system=SYSTEM_PROMPT,
                    model=self.ctx.config.models.general_model,
                    max_tokens=self.ctx.config.models.max_tokens,
                )
            except LLMError as exc:
                self.fail(
                    state,
                    f"LLM tuning call failed for {rule.rule_id} v{rule.version}: {exc}",
                )
                continue

            try:
                payload = extract_json_object(raw)
                new_spl = str(payload["spl"]).strip()
                tuning_note = str(payload["tuning_note"]).strip()
                if not new_spl:
                    raise ValueError("model returned an empty 'spl'")
            except (KeyError, ValueError) as exc:
                self.fail(
                    state,
                    f"could not parse tuning response for {rule.rule_id} "
                    f"v{rule.version}: {exc}",
                )
                continue

            tuned = DetectionRule(
                rule_id=rule.rule_id,
                name=rule.name,
                description=rule.description,
                spl=new_spl,
                mitre_techniques=list(rule.mitre_techniques),
                severity=rule.severity,
                status=RuleStatus.TUNED,
                version=rule.version + 1,
                parent_version=rule.version,
                gap_id=rule.gap_id,
                cron_schedule=rule.cron_schedule,
                tuning_notes=list(rule.tuning_notes) + [tuning_note],
            )
            state.upsert_rule(tuned)

            self.emit(
                state,
                "rule_tuned",
                {
                    "rule_id": rule.rule_id,
                    "old_version": rule.version,
                    "new_version": tuned.version,
                    "tuning_note": tuning_note,
                },
            )

        return state

    # ---- internals ----

    def _build_prompt(
        self,
        state: PipelineState,
        rule: DetectionRule,
        backtest: Optional[BacktestResult],
        forecast: ForecastResult,
    ) -> str:
        """Assemble the tuning prompt from backtest evidence and the budget."""
        budget = state.fp_budget_weekly
        lines: list[str] = [
            f"Detection rule '{rule.name}' ({rule.rule_id}, version {rule.version}) "
            f"covers MITRE techniques {', '.join(rule.mitre_techniques) or 'n/a'}.",
            "Current SPL:",
            rule.spl,
            "",
        ]

        if backtest is not None and backtest.syntax_valid:
            window_days = backtest.window_days or 90
            weekly_rate = round(backtest.total_hits / (window_days / 7), 1)
            lines += [
                f"Backtest over the last {window_days} days:",
                f"- total hits: {backtest.total_hits} (~{weekly_rate} alerts/week)",
                f"- true positives: {backtest.true_positives}, "
                f"false positives: {backtest.false_positives}",
                f"- precision: {round(backtest.precision, 4)}, "
                f"recall: {round(backtest.recall, 4)}",
            ]
            sample_users = sorted(
                {str(h.get("user", "")) for h in backtest.sample_hits if h.get("user")}
            )
            sample_processes = sorted(
                {
                    str(h.get("process_name", ""))
                    for h in backtest.sample_hits
                    if h.get("process_name")
                }
            )
            if sample_users:
                lines.append(
                    f"- users seen in sample false-positive hits: {', '.join(sample_users)}"
                )
            if sample_processes:
                lines.append(
                    f"- processes seen in sample hits: {', '.join(sample_processes)}"
                )
            fp_by_user = self._aggregate_fp_by_user(rule, window_days)
            if fp_by_user:
                lines.append(
                    "- false-positive event count by user (top "
                    f"{TOP_FP_USERS}): {json.dumps(fp_by_user)}"
                )
        else:
            lines.append("Backtest statistics are unavailable for this version.")

        lines += [
            "",
            f"The weekly false-positive budget is {budget} alerts/week. The noise "
            f"forecast predicts {round(forecast.predicted_weekly_alerts, 1)} alerts/week "
            f"(90% upper bound {round(forecast.upper_bound_weekly, 1)}), which "
            "exceeds the false-positive budget - tighten the detection while "
            "preserving every true positive.",
            "",
            "Keep the same index and sourcetype. Respond with strict JSON only: "
            '{"spl": "...", "tuning_note": "..."}',
        ]
        return "\n".join(lines)

    def _aggregate_fp_by_user(
        self, rule: DetectionRule, window_days: int
    ) -> dict[str, int]:
        """Re-run the rule's SPL and count false-positive events per user.

        Gives the model a concrete picture of who generates the noise (e.g.
        a benign service account). True positives — labeled malicious events
        in the rule's techniques — are excluded. Returns the top
        :data:`TOP_FP_USERS` users by descending count, or an empty dict when
        the search is unavailable (the prompt simply omits the section).
        """
        try:
            result = self.ctx.mcp.run_search(
                rule.spl, earliest=f"-{window_days}d", max_results=10000
            )
        except MCPError:
            return {}
        if result.error:
            return {}

        techniques = set(rule.mitre_techniques)
        counts: dict[str, int] = {}
        for event in result.results:
            if (
                event.get("label") == "malicious"
                and event.get("technique") in techniques
            ):
                continue
            user = str(event.get("user") or "unknown")
            counts[user] = counts.get(user, 0) + 1
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_FP_USERS]
        return dict(top)
