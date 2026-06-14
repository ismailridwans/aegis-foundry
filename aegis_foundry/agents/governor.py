"""Governor agent: the policy gate between tuned detections and production.

The Governor is the judged governance layer of Aegis Foundry. Every rule that
survives backtesting and noise forecasting must pass a battery of explicit
policy checks (syntax validity, true-positive preservation, noise budget,
MITRE mapping, severity hygiene, description quality, and a blast-radius scan
for destructive SPL commands) before any deployment is allowed. For each
candidate the Governor renders a human-readable EVIDENCE PACK — a markdown
dossier with the SPL, a version diff, backtest statistics, the forecast
verdict, the full policy-check ledger, tuning notes, and an LLM-written
analyst rationale — then records a :class:`GovernanceDecision`.

Decision modes:

- Any failed policy check  -> automatic ``REJECT`` (approver ``policy:governor``).
- ``state.auto_approve``   -> ``APPROVE_ACTIVE`` (approver ``policy:auto-approve-demo``),
  used by the scripted demo so the pipeline runs unattended.
- Otherwise the Governor goes interactive: it prints the evidence summary and
  asks the operator to approve active, approve shadow, or reject. An empty
  answer or EOF (e.g. CI with no stdin) defaults to the safe choice: shadow.

Rules arriving with ``RETUNE_REQUIRED`` status exhausted their tuning budget
without meeting the false-positive budget and are auto-rejected with notes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import LLMError
from aegis_foundry.state import (
    BacktestResult,
    CoverageGap,
    Decision,
    DetectionRule,
    ForecastResult,
    GovernanceDecision,
    PipelineStage,
    PipelineState,
    PolicyCheck,
    RobustnessResult,
    RuleStatus,
    iso_now,
)

#: Minimum adversarial recall (Red-Team gauntlet) required to pass governance.
_ROBUSTNESS_THRESHOLD = 0.75

#: Destructive / data-exfiltrating SPL commands a detection rule must never
#: contain. Matched case-insensitively after a pipe, tolerating whitespace.
_DESTRUCTIVE_SPL = ("delete", "outputlookup", "sendemail", "script", "collect")
_DESTRUCTIVE_RE = re.compile(
    r"\|\s*(" + "|".join(_DESTRUCTIVE_SPL) + r")\b", re.IGNORECASE
)

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class Governor(Agent):
    """Gate tuned rules behind explicit policy checks and an evidence pack."""

    name: str = "governor"

    def run(self, state: PipelineState) -> PipelineState:
        """Adjudicate every governance-ready rule, then advance to DEPLOY.

        - ``BACKTESTED`` rules whose latest forecast is within the
          false-positive budget get the full evidence-pack + decision flow.
        - ``RETUNE_REQUIRED`` rules (tuning budget exhausted, still noisy)
          are auto-rejected with explanatory notes.
        - Everything else is left untouched for the orchestrator's loops.
        """
        for rule_id, rule in list(state.rules.items()):
            if rule.status == RuleStatus.RETUNE_REQUIRED:
                self._auto_reject_retune(state, rule)
                continue
            if rule.status != RuleStatus.BACKTESTED:
                continue
            forecast = state.forecasts.get(rule_id)
            if forecast is None or not forecast.within_budget:
                # Still owned by the forecast/tune loop; not governance-ready.
                continue
            self._adjudicate(state, rule, forecast)

        state.stage = PipelineStage.DEPLOY
        return state

    # ------------------------------------------------------------------
    # Decision flows
    # ------------------------------------------------------------------

    def _adjudicate(
        self, state: PipelineState, rule: DetectionRule, forecast: ForecastResult
    ) -> None:
        """Run policy checks, write the evidence pack, and record a decision."""
        backtest = state.backtests.get(rule.rule_id)
        robustness = state.robustness.get(rule.rule_id)
        checks = self._build_policy_checks(rule, backtest, forecast, robustness)
        failed = [c for c in checks if not c.passed]

        rationale = self._analyst_rationale(rule, backtest, forecast)
        evidence_path = self._write_evidence_pack(
            state, rule, backtest, forecast, checks, rationale, robustness
        )

        if failed:
            decision_value = Decision.REJECT
            approver = "policy:governor"
            notes = "Rejected by policy: failed checks -> " + ", ".join(
                c.name for c in failed
            )
        elif state.auto_approve:
            decision_value = Decision.APPROVE_ACTIVE
            approver = "policy:auto-approve-demo"
            notes = "Auto-approved for active deployment (demo auto-approve flag)."
        else:
            decision_value = self._interactive_decision(
                state, rule, backtest, forecast, evidence_path
            )
            approver = "human:operator"
            notes = "Interactive operator decision via evidence-pack review."

        decision = GovernanceDecision(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            decision=decision_value,
            approver=approver,
            policy_checks=checks,
            evidence_pack_path=evidence_path,
            notes=notes,
        )
        state.decisions[rule.rule_id] = decision

        if decision_value in (Decision.APPROVE_ACTIVE, Decision.APPROVE_SHADOW):
            rule.status = RuleStatus.APPROVED
        else:
            rule.status = RuleStatus.REJECTED

        detail: dict[str, object] = {
            "rule_id": rule.rule_id,
            "rule_version": rule.version,
            "decision": decision_value.value,
            "approver": approver,
            "evidence_pack": evidence_path,
        }
        if failed:
            detail["failed_checks"] = [c.name for c in failed]
        self.emit(state, "governance_decision", detail)

    def _auto_reject_retune(self, state: PipelineState, rule: DetectionRule) -> None:
        """Auto-reject a rule that exhausted tuning without meeting budget."""
        forecast = state.forecasts.get(rule.rule_id)
        backtest = state.backtests.get(rule.rule_id)
        checks: list[PolicyCheck] = []
        if forecast is not None:
            checks.append(
                PolicyCheck(
                    name="noise-within-budget",
                    passed=False,
                    detail=(
                        f"predicted {forecast.predicted_weekly_alerts:.1f} alerts/week "
                        f"exceeds budget {forecast.fp_budget_weekly:.1f}/week "
                        f"(90% upper bound {forecast.upper_bound_weekly:.1f})"
                    ),
                )
            )
        notes = (
            "Auto-rejected: rule still exceeds the weekly false-positive budget "
            f"after {state.max_tuning_iterations} tuning iteration(s); "
            "no compliant variant could be produced."
        )
        evidence_path: Optional[str] = None
        if backtest is not None and forecast is not None:
            evidence_path = self._write_evidence_pack(
                state,
                rule,
                backtest,
                forecast,
                checks,
                "Tuning budget exhausted without meeting the false-positive "
                "budget; the Governor rejected this rule automatically to "
                "protect the SOC from runaway alert noise.",
            )

        decision = GovernanceDecision(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            decision=Decision.REJECT,
            approver="policy:governor",
            policy_checks=checks,
            evidence_pack_path=evidence_path,
            notes=notes,
        )
        state.decisions[rule.rule_id] = decision
        rule.status = RuleStatus.REJECTED
        self.emit(
            state,
            "governance_decision",
            {
                "rule_id": rule.rule_id,
                "rule_version": rule.version,
                "decision": Decision.REJECT.value,
                "approver": "policy:governor",
                "failed_checks": [c.name for c in checks if not c.passed],
                "evidence_pack": evidence_path,
                "notes": notes,
            },
        )

    def _interactive_decision(
        self,
        state: PipelineState,
        rule: DetectionRule,
        backtest: Optional[BacktestResult],
        forecast: ForecastResult,
        evidence_path: Optional[str] = None,
    ) -> Decision:
        """Ask a human for a verdict — via the web console when it is running,
        otherwise on stdin.

        Web path: submit to the process-wide ApprovalBroker and block until the
        operator clicks Deploy Active / Shadow / Reject in the browser; on
        timeout fall back to the safe default (shadow). CLI path: empty input
        defaults to shadow; EOF (no stdin, e.g. CI) is treated as shadow as
        well so unattended runs never hang.
        """
        technique = ", ".join(rule.mitre_techniques) or "unmapped"
        bt_weekly = _weekly_rate(backtest)
        recall = backtest.recall if backtest is not None else 0.0

        from aegis_foundry.web.approvals import ApprovalRequest, get_broker

        broker = get_broker()
        if broker is not None:
            request = ApprovalRequest(
                run_id=state.run_id,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                rule_version=rule.version,
                technique=technique,
                weekly_backtest=round(bt_weekly, 1),
                weekly_forecast=round(forecast.predicted_weekly_alerts, 1),
                fp_budget_weekly=forecast.fp_budget_weekly,
                recall=recall,
                evidence_pack_path=evidence_path,
            )
            self.emit(
                state,
                "approval_requested",
                {"rule_id": rule.rule_id, "request_id": request.request_id, "via": "web"},
            )
            decision = broker.submit(request)
            if decision is not None:
                return decision
            # Timed out waiting for the browser: fail safe to shadow.
            return Decision.APPROVE_SHADOW
        print()
        print("=" * 70)
        print(f"GOVERNANCE REVIEW: {rule.name} (v{rule.version})")
        print(f"  Technique:    {technique}")
        print(
            f"  Weekly noise: {bt_weekly:.1f}/wk observed in backtest -> "
            f"{forecast.predicted_weekly_alerts:.1f}/wk forecast "
            f"(budget {forecast.fp_budget_weekly:.1f}/wk)"
        )
        print(f"  Recall:       {recall:.2f}")
        print("=" * 70)
        try:
            answer = input("Approve? [a]ctive / [s]hadow / [r]eject: ")
        except EOFError:
            # No interactive stdin (CI / piped run): fail safe to shadow.
            answer = "s"
        choice = answer.strip().lower()[:1]
        if choice == "a":
            return Decision.APPROVE_ACTIVE
        if choice == "r":
            return Decision.REJECT
        return Decision.APPROVE_SHADOW

    # ------------------------------------------------------------------
    # Policy checks
    # ------------------------------------------------------------------

    def _build_policy_checks(
        self,
        rule: DetectionRule,
        backtest: Optional[BacktestResult],
        forecast: ForecastResult,
        robustness: Optional[RobustnessResult] = None,
    ) -> list[PolicyCheck]:
        """Evaluate every governance policy against the rule and its evidence."""
        checks: list[PolicyCheck] = []

        syntax_valid = bool(backtest is not None and backtest.syntax_valid)
        checks.append(
            PolicyCheck(
                name="syntax-valid",
                passed=syntax_valid,
                detail=(
                    "SPL parsed cleanly during backtest"
                    if syntax_valid
                    else "SPL failed syntax validation (or no backtest available)"
                ),
            )
        )

        if backtest is not None:
            tp_ok = backtest.recall == 1.0 or backtest.labeled_attack_events == 0
            tp_detail = (
                f"{backtest.true_positives}/{backtest.labeled_attack_events} "
                f"labeled attack events retained (recall {backtest.recall:.2f})"
            )
        else:
            tp_ok = False
            tp_detail = "no backtest available to verify attack-event retention"
        checks.append(
            PolicyCheck(name="true-positive-preservation", passed=tp_ok, detail=tp_detail)
        )

        checks.append(
            PolicyCheck(
                name="noise-within-budget",
                passed=forecast.within_budget,
                detail=(
                    f"predicted {forecast.predicted_weekly_alerts:.1f} alerts/week vs "
                    f"budget {forecast.fp_budget_weekly:.1f}/week "
                    f"(90% upper bound {forecast.upper_bound_weekly:.1f}, "
                    f"hard cap {forecast.fp_budget_weekly * 1.5:.1f})"
                ),
            )
        )

        checks.append(
            PolicyCheck(
                name="mitre-mapped",
                passed=bool(rule.mitre_techniques),
                detail=(
                    "mapped to " + ", ".join(rule.mitre_techniques)
                    if rule.mitre_techniques
                    else "rule has no MITRE ATT&CK technique mapping"
                ),
            )
        )

        sev_ok = rule.severity in _VALID_SEVERITIES
        checks.append(
            PolicyCheck(
                name="severity-valid",
                passed=sev_ok,
                detail=(
                    f"severity '{rule.severity}' is "
                    + ("a recognized level" if sev_ok else "not one of low/medium/high/critical")
                ),
            )
        )

        desc_ok = len(rule.description) > 20
        checks.append(
            PolicyCheck(
                name="description-present",
                passed=desc_ok,
                detail=(
                    f"description present ({len(rule.description)} chars)"
                    if desc_ok
                    else f"description too short ({len(rule.description)} chars; need > 20)"
                ),
            )
        )

        destructive = sorted({m.group(1).lower() for m in _DESTRUCTIVE_RE.finditer(rule.spl)})
        checks.append(
            PolicyCheck(
                name="blast-radius",
                passed=not destructive,
                detail=(
                    "no destructive SPL commands detected"
                    if not destructive
                    else "destructive SPL command(s) found: | " + ", | ".join(destructive)
                ),
            )
        )

        if robustness is not None and robustness.variants_total > 0:
            rob_ok = robustness.adversarial_recall >= _ROBUSTNESS_THRESHOLD
            missed = ", ".join(robustness.missed_mutations) if robustness.missed_mutations else "none"
            rob_detail = (
                f"caught {robustness.variants_caught}/{robustness.variants_total} evasion variants "
                f"(adversarial recall {robustness.adversarial_recall:.0%}, "
                f"threshold {_ROBUSTNESS_THRESHOLD:.0%}); missed: {missed}"
            )
        else:
            rob_ok = True
            rob_detail = (
                "not evaluated — no labeled attack samples for this technique "
                "(the gauntlet currently ships PowerShell/process-execution mutations)"
            )
        checks.append(
            PolicyCheck(name="adversarial-robustness", passed=rob_ok, detail=rob_detail)
        )
        return checks

    # ------------------------------------------------------------------
    # Evidence pack
    # ------------------------------------------------------------------

    def _write_evidence_pack(
        self,
        state: PipelineState,
        rule: DetectionRule,
        backtest: Optional[BacktestResult],
        forecast: ForecastResult,
        checks: list[PolicyCheck],
        rationale: str,
        robustness: Optional[RobustnessResult] = None,
    ) -> str:
        """Render the markdown evidence pack and return its path (POSIX style)."""
        evidence_dir = Path(self.ctx.config.runs_dir) / state.run_id / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        path = evidence_dir / f"{rule.rule_id}_v{rule.version}.md"

        gap = _find_gap(state, rule)
        technique = ", ".join(rule.mitre_techniques) or "unmapped"
        technique_line = technique
        tactic = gap.tactic if gap is not None else "unknown"
        if gap is not None and gap.technique_name:
            technique_line = f"{technique} — {gap.technique_name}"

        lines: list[str] = []
        lines.append(f"# Evidence Pack: {rule.name}")
        lines.append("")
        lines.append(f"- **Rule ID:** `{rule.rule_id}`")
        lines.append(f"- **Version:** {rule.version}")
        lines.append(f"- **Status:** {rule.status.value}")
        lines.append(f"- **Severity:** {rule.severity}")
        lines.append(f"- **MITRE technique:** {technique_line}")
        lines.append(f"- **MITRE tactic:** {tactic}")
        lines.append(f"- **Run:** {state.run_id}")
        lines.append(f"- **Generated:** {iso_now()}")
        lines.append("")
        lines.append("## Detection SPL")
        lines.append("")
        lines.append("```spl")
        lines.append(rule.spl)
        lines.append("```")
        lines.append("")

        if rule.version > 1:
            parent = _find_parent_rule(state, rule)
            lines.append(
                f"## Change From Version {parent.version if parent else rule.version - 1}"
            )
            lines.append("")
            lines.append("```diff")
            if parent is not None:
                for old_line in parent.spl.splitlines() or [""]:
                    lines.append(f"- {old_line}")
            else:
                lines.append("- (parent version SPL unavailable)")
            for new_line in rule.spl.splitlines() or [""]:
                lines.append(f"+ {new_line}")
            lines.append("```")
            lines.append("")

        lines.append("## Backtest Statistics")
        lines.append("")
        if backtest is not None:
            lines.append("| Metric | Value |")
            lines.append("| --- | --- |")
            lines.append(f"| Window | {backtest.window_days} days |")
            lines.append(f"| Total hits | {backtest.total_hits} |")
            lines.append(f"| Weekly hit rate | {_weekly_rate(backtest):.1f}/week |")
            lines.append(f"| True positives | {backtest.true_positives} |")
            lines.append(f"| False positives | {backtest.false_positives} |")
            lines.append(f"| Precision | {backtest.precision:.3f} |")
            lines.append(f"| Recall | {backtest.recall:.3f} |")
            lines.append(f"| Labeled attack events | {backtest.labeled_attack_events} |")
        else:
            lines.append("_No backtest result available for this version._")
        lines.append("")

        verdict = "WITHIN BUDGET" if forecast.within_budget else "OVER BUDGET"
        lines.append("## Noise Forecast")
        lines.append("")
        lines.append(f"- **Model:** {forecast.model}")
        lines.append(f"- **Horizon:** {forecast.horizon_days} days")
        lines.append(
            f"- **Predicted weekly alerts:** {forecast.predicted_weekly_alerts:.1f}"
        )
        lines.append(
            f"- **{forecast.conf_interval}% band:** "
            f"[{forecast.lower_bound_weekly:.1f}, {forecast.upper_bound_weekly:.1f}]"
        )
        lines.append(
            f"- **Budget verdict:** {verdict} "
            f"({forecast.predicted_weekly_alerts:.1f} predicted vs "
            f"{forecast.fp_budget_weekly:.1f}/week budget)"
        )
        lines.append("")

        if robustness is not None and robustness.variants_total > 0:
            lines.append("## Adversarial Robustness (Red-Team Gauntlet)")
            lines.append("")
            lines.append(f"- **Model:** {robustness.model}")
            lines.append(
                f"- **Evasion variants caught:** {robustness.variants_caught}/"
                f"{robustness.variants_total}"
            )
            lines.append(
                f"- **Adversarial recall:** {robustness.adversarial_recall:.0%} "
                f"(threshold {_ROBUSTNESS_THRESHOLD:.0%})"
            )
            if robustness.missed_mutations:
                lines.append(
                    "- **Hardening opportunities (evaded):** "
                    + ", ".join(robustness.missed_mutations)
                )
            else:
                lines.append("- **Hardening opportunities (evaded):** none")
            lines.append("")

        lines.append("## Policy Checks")
        lines.append("")
        for check in checks:
            box = "x" if check.passed else " "
            lines.append(f"- [{box}] **{check.name}** — {check.detail}")
        lines.append("")

        lines.append("## Tuning Notes")
        lines.append("")
        if rule.tuning_notes:
            for note in rule.tuning_notes:
                lines.append(f"- {note}")
        else:
            lines.append("- (none — first draft)")
        lines.append("")

        lines.append("## Analyst Rationale")
        lines.append("")
        lines.append(rationale)
        lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path.as_posix()

    def _analyst_rationale(
        self,
        rule: DetectionRule,
        backtest: Optional[BacktestResult],
        forecast: ForecastResult,
    ) -> str:
        """Ask the LLM for a short analyst rationale; degrade gracefully."""
        bt_summary = (
            f"backtest over {backtest.window_days} days: {backtest.total_hits} hits, "
            f"{backtest.true_positives} true positives, "
            f"{backtest.false_positives} false positives, "
            f"precision {backtest.precision:.2f}, recall {backtest.recall:.2f}"
            if backtest is not None
            else "no backtest available"
        )
        prompt = (
            "Write a 2-3 sentence analyst rationale for deploying this Splunk "
            "detection rule. Be specific about detection value and noise.\n"
            f"Rule: {rule.name}\n"
            f"MITRE techniques: {', '.join(rule.mitre_techniques) or 'none'}\n"
            f"SPL: {rule.spl}\n"
            f"Evidence: {bt_summary}; forecast {forecast.predicted_weekly_alerts:.1f} "
            f"alerts/week against a budget of {forecast.fp_budget_weekly:.1f}/week."
        )
        try:
            text = self.ctx.llm.complete(
                prompt,
                system=(
                    "You are a senior detection engineer writing concise "
                    "governance rationale for a SOC change-approval board."
                ),
            )
            text = text.strip()
            if text:
                return text
        except LLMError:
            pass
        # Deterministic fallback so the evidence pack is never empty.
        return (
            f"This rule targets {', '.join(rule.mitre_techniques) or 'an unmapped technique'} "
            f"and retained all labeled attack activity in backtesting ({bt_summary}). "
            f"Forecast noise of {forecast.predicted_weekly_alerts:.1f} alerts/week sits "
            f"within the {forecast.fp_budget_weekly:.1f}/week false-positive budget, so the "
            "detection adds coverage without overloading the SOC queue."
        )


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------


def _weekly_rate(backtest: Optional[BacktestResult]) -> float:
    """Average weekly hit rate observed during the backtest window."""
    if backtest is None or backtest.window_days <= 0:
        return 0.0
    return backtest.total_hits / backtest.window_days * 7.0


def _find_gap(state: PipelineState, rule: DetectionRule) -> Optional[CoverageGap]:
    """Locate the coverage gap this rule was authored against, if any."""
    if rule.gap_id:
        for gap in state.gaps:
            if gap.gap_id == rule.gap_id:
                return gap
    for gap in state.gaps:
        if any(t in gap.technique_id for t in rule.mitre_techniques):
            return gap
    return None


def _find_parent_rule(state: PipelineState, rule: DetectionRule) -> Optional[DetectionRule]:
    """Find the version this rule was tuned from in the rule history."""
    target = rule.parent_version if rule.parent_version is not None else rule.version - 1
    history = state.rule_history.get(rule.rule_id, [])
    parent: Optional[DetectionRule] = None
    for candidate in history:
        if candidate.version == target:
            parent = candidate
    return parent
