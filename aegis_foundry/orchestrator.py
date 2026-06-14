"""Pipeline conductor for Aegis Foundry.

The Orchestrator owns the detection-lifecycle state machine and is the only
component that sequences agents. Agents stay single-purpose (``run(state) ->
state``); the conductor decides *when* each one runs, persists the state after
every stage transition, narrates progress to the console for the judged demo,
and records its own decisions in the same flight recorder the agents use.

State machine::

    INTEL -> COVERAGE -> AUTHOR
        -> [measurement loop: BACKTEST -> FORECAST -> TUNE]*
        -> GOVERN -> DEPLOY -> VERIFY
        -> (one optional corrective measurement loop + GOVERN + DEPLOY
            if verification flagged RETUNE_REQUIRED)
        -> DONE

The measurement loop repeats while at least one rule's latest version still
lacks a within-budget forecast, that rule has tuning attempts remaining, and
the previous pass actually changed something (the Tuning Optimizer produced a
new version). A hard cap of ``max_tuning_iterations + 1`` passes guarantees
termination. Backtest/forecast agents guard on rule versions, so re-running
them after a tune re-measures only the new versions.
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path
from typing import Any, Optional

from aegis_foundry.agents.backtest_engineer import BacktestEngineer
from aegis_foundry.agents.base import Agent
from aegis_foundry.agents.coverage_cartographer import CoverageCartographer
from aegis_foundry.agents.deployer import Deployer
from aegis_foundry.agents.detection_author import DetectionAuthor
from aegis_foundry.agents.governor import Governor
from aegis_foundry.agents.intel_scout import IntelScout
from aegis_foundry.agents.noise_forecaster import NoiseForecaster
from aegis_foundry.agents.red_team import RedTeam
from aegis_foundry.agents.tuning_optimizer import TuningOptimizer
from aegis_foundry.agents.verifier import Verifier
from aegis_foundry.config import AppConfig
from aegis_foundry.core.compliance import build_attestations
from aegis_foundry.core.factory import build_context
from aegis_foundry.core.roi import compute_roi, v1_weekly_for_rule
from aegis_foundry.state import (
    Decision,
    DetectionRule,
    PipelineStage,
    PipelineState,
    RuleStatus,
    iso_now,
)

__all__ = ["Orchestrator", "run_pipeline", "paint", "summarize_detail"]


# --------------------------------------------------------------------------
# Console helpers (stdlib-only; colors only when stdout is a real terminal)
# --------------------------------------------------------------------------

_ANSI_RESET = "\033[0m"
_ANSI_CODES: dict[str, str] = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "magenta": "35",
    "cyan": "36",
}


def _color_enabled() -> bool:
    """True when stdout is an interactive terminal (ANSI colors are safe)."""
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def paint(text: str, *styles: str) -> str:
    """Wrap ``text`` in ANSI style codes when stdout is a TTY, else pass through."""
    if not styles or not _color_enabled():
        return text
    codes = ";".join(_ANSI_CODES[s] for s in styles if s in _ANSI_CODES)
    if not codes:
        return text
    return f"\033[{codes}m{text}{_ANSI_RESET}"


def _enable_windows_ansi() -> None:
    """Enable virtual-terminal processing on legacy Windows consoles.

    ``os.system("")`` flips the console into VT mode on Windows 10+; it is a
    no-op everywhere else and costs nothing when output is piped.
    """
    if os.name == "nt" and _color_enabled():
        os.system("")


# --------------------------------------------------------------------------
# Audit-detail formatting (shared with the CLI's flight-recorder view)
# --------------------------------------------------------------------------

_PRIORITY_KEYS: tuple[str, ...] = (
    "name", "rule_name", "title", "technique_id", "technique", "tactic",
    "version", "rule_version", "decision", "approver", "mode", "verdict",
    "action", "status", "syntax_valid", "within_budget",
    "predicted_weekly_alerts", "upper_bound_weekly", "recall", "precision",
    "true_positives", "false_positives", "total_hits", "count", "gaps_found",
    "saved_search_name", "rollback_token", "evidence_pack_path", "path",
    "message", "rule_id",
)


def _format_value(value: Any) -> str:
    """Render one audit-detail value compactly for a single console line."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, (list, tuple)):
        if len(value) <= 3 and all(isinstance(x, (str, int, float)) for x in value):
            return ",".join(str(x) for x in value)
        return f"[{len(value)} items]"
    if isinstance(value, dict):
        return f"{{{len(value)} keys}}"
    text = str(value)
    if len(text) > 48:
        text = text[:45] + "..."
    if isinstance(value, str) and (" " in text or text == ""):
        return f"'{text}'"
    return text


def summarize_detail(detail: Optional[dict[str, Any]], *, max_items: int = 4,
                     max_len: int = 110) -> str:
    """Compress an audit-event detail dict into one short ``k=v`` line.

    Keys known to carry demo-relevant signal (rule names, versions, budgets,
    decisions) are shown first; everything else follows in insertion order.
    """
    if not detail:
        return ""
    ordered = [k for k in _PRIORITY_KEYS if k in detail]
    ordered += [k for k in detail if k not in ordered]
    parts = [f"{k}={_format_value(detail[k])}" for k in ordered[:max_items]]
    text = "  ".join(parts)
    if len(text) > max_len:
        text = text[: max(0, max_len - 3)] + "..."
    return text


def _plural(n: int) -> str:
    return "" if n == 1 else "s"


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------


class Orchestrator:
    """Conducts one end-to-end run of the nine-agent detection pipeline."""

    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self.state = PipelineState(
            fp_budget_weekly=cfg.fp_budget_weekly,
            max_tuning_iterations=cfg.max_tuning_iterations,
            auto_approve=cfg.auto_approve,
        )
        self.ctx = build_context(cfg, self.state.run_id)
        self.run_dir: Path = Path(cfg.runs_dir) / self.state.run_id
        self.state_path: Path = self.run_dir / "state.json"
        self.flight_recorder_path: Path = self.run_dir / "flight_recorder.jsonl"

        self.intel_scout = IntelScout(self.ctx)
        self.coverage_cartographer = CoverageCartographer(self.ctx)
        self.detection_author = DetectionAuthor(self.ctx)
        self.backtest_engineer = BacktestEngineer(self.ctx)
        self.noise_forecaster = NoiseForecaster(self.ctx)
        self.tuning_optimizer = TuningOptimizer(self.ctx)
        self.red_team = RedTeam(self.ctx)
        self.governor = Governor(self.ctx)
        self.deployer = Deployer(self.ctx)
        self.verifier = Verifier(self.ctx)

        self._roster: list[Agent] = [
            self.intel_scout,
            self.coverage_cartographer,
            self.detection_author,
            self.backtest_engineer,
            self.noise_forecaster,
            self.tuning_optimizer,
            self.red_team,
            self.governor,
            self.deployer,
            self.verifier,
        ]
        self._agent_no: dict[str, int] = {
            agent.name: i for i, agent in enumerate(self._roster, start=1)
        }
        # Forecasts in state are keyed by rule_id and overwritten per version;
        # this snapshot keeps every (rule, version) -> weekly prediction so the
        # final summary can show "v1 noise vs final noise" honestly.
        self._forecast_history: dict[str, dict[int, float]] = {}
        _enable_windows_ansi()

    # ---- public API ----

    def run(self) -> PipelineState:
        """Execute the full state machine and return the final state."""
        self._print_header()
        self._audit("run_started", {
            "mode": self.cfg.mode,
            "fp_budget_weekly": self.state.fp_budget_weekly,
            "max_tuning_iterations": self.state.max_tuning_iterations,
            "auto_approve": self.state.auto_approve,
        })
        self._save()
        self._execute()
        self._print_final_summary()
        self._append_memory_summary()
        return self.state

    # ---- state machine ----

    def _execute(self) -> bool:
        """Run every stage; returns False if any stage failed terminally."""
        if not self._run_agent(self.intel_scout, PipelineStage.INTEL,
                               "ingesting threat advisories and incident intel"):
            return False

        if not self._run_agent(self.coverage_cartographer, PipelineStage.COVERAGE,
                               self._desc_coverage()):
            return False

        if not self.state.gaps:
            self._audit("no_gaps_found", {
                "intel_count": len(self.state.intel),
                "existing_rules": len(self.state.existing_rules),
            })
            self.state.stage = PipelineStage.DONE
            self._save()
            print(paint(
                "\nEvery technique referenced by intel is already covered - "
                "nothing to author this run.", "green"))
            return True

        if not self._run_agent(self.detection_author, PipelineStage.AUTHOR,
                               self._desc_author()):
            return False

        if not self.state.rules:
            message = "detection authoring produced no usable rules"
            self.state.errors.append(f"[orchestrator] {message}")
            self._audit("no_rules_authored", {"gaps": len(self.state.gaps)})
            self.state.stage = PipelineStage.FAILED
            self._save()
            print(paint(f"\n{message} - aborting run.", "red"))
            return False

        if not self._measurement_loop():
            return False

        if not self._run_agent(self.red_team, PipelineStage.HARDEN,
                               self._desc_harden()):
            return False
        if not self._run_agent(self.governor, PipelineStage.GOVERN,
                               self._desc_govern()):
            return False
        if not self._run_agent(self.deployer, PipelineStage.DEPLOY,
                               self._desc_deploy()):
            return False
        if not self._run_agent(self.verifier, PipelineStage.VERIFY,
                               self._desc_verify()):
            return False

        retune_ids = [r.rule_id for r in self.state.rules.values()
                      if r.status is RuleStatus.RETUNE_REQUIRED]
        if retune_ids:
            print(paint(
                f"\n--- verification flagged {len(retune_ids)} "
                f"rule{_plural(len(retune_ids))} for retuning - running one "
                "corrective pass ---", "yellow"))
            self._audit("retune_pass_started", {"rules": retune_ids})
            if not self._measurement_loop(label="retune"):
                return False
            if not self._run_agent(self.red_team, PipelineStage.HARDEN,
                                   self._desc_harden()):
                return False
            if not self._run_agent(self.governor, PipelineStage.GOVERN,
                                   self._desc_govern()):
                return False
            if not self._run_agent(self.deployer, PipelineStage.DEPLOY,
                                   self._desc_deploy()):
                return False

        self._finalize_impact()
        self.state.stage = PipelineStage.DONE
        self._save()
        return True

    def _finalize_impact(self) -> None:
        """Compute the run's ROI ledger and compliance attestation from final state."""
        try:
            self.state.roi = compute_roi(self.state)
            roi = self.state.roi
            self._audit("roi_computed", {
                "alerts_avoided_weekly": roi.alerts_avoided_weekly,
                "annualized_dollars_saved": roi.annualized_dollars_saved,
                "total_annual_value": roi.total_annual_value,
                "detections_shipped": roi.detections_shipped,
            })
        except Exception as exc:  # noqa: BLE001 - impact is advisory, never fatal
            self.state.errors.append(f"[orchestrator] ROI computation failed: {exc}")
        try:
            self.state.compliance = build_attestations(self.state)
            controls = sum(len(a.controls) for a in self.state.compliance)
            self._audit("compliance_attested", {
                "detections": len(self.state.compliance),
                "controls_satisfied": controls,
            })
        except Exception as exc:  # noqa: BLE001 - attestation is advisory, never fatal
            self.state.errors.append(f"[orchestrator] compliance mapping failed: {exc}")

    def _measurement_loop(self, label: str = "measurement") -> bool:
        """Run BACKTEST -> FORECAST -> TUNE passes until rules converge.

        Repeats while some rule's latest version lacks a within-budget
        forecast, that rule still has tuning attempts left, and the previous
        pass produced a new version. Hard-capped at
        ``max_tuning_iterations + 1`` passes.
        """
        max_passes = max(1, int(self.cfg.max_tuning_iterations) + 1)
        for pass_no in range(1, max_passes + 1):
            tag = f"{label} pass {pass_no}"
            versions_before = {rid: r.version for rid, r in self.state.rules.items()}

            if not self._run_agent(self.backtest_engineer, PipelineStage.BACKTEST,
                                   f"{tag}: {self._desc_backtest()}"):
                return False
            if not self._run_agent(self.noise_forecaster, PipelineStage.FORECAST,
                                   f"{tag}: {self._desc_forecast()}"):
                return False
            self._snapshot_forecasts()
            if not self._run_agent(self.tuning_optimizer, PipelineStage.TUNE,
                                   f"{tag}: {self._desc_tune()}"):
                return False

            versions_after = {rid: r.version for rid, r in self.state.rules.items()}
            changed = versions_after != versions_before
            pending = [r for r in self.state.rules.values()
                       if not self._within_budget(r) and self._tuning_attempts_left(r)]
            if not pending:
                break
            if not changed:
                self._audit("tuning_converged_without_change", {
                    "pass": pass_no,
                    "pending_rules": [r.rule_id for r in pending],
                })
                break
        return True

    # ---- agent execution wrapper ----

    def _run_agent(self, agent: Agent, stage: PipelineStage, description: str) -> bool:
        """Transition the stage, run one agent, persist, and narrate.

        Any exception is captured as a traceback summary in ``state.errors``,
        the stage flips to FAILED, and the state is still persisted so the
        flight recorder and partial results survive for the audit view.
        """
        idx = self._agent_no.get(agent.name, 0)
        total = len(self._roster)
        self.state.stage = stage
        self._save()
        print(paint(f"\n=== [{idx}/{total}] {agent.name} - {description} ===",
                    "bold", "cyan"))
        audit_start = len(self.state.audit)
        try:
            self.state = agent.run(self.state)
        except Exception as exc:  # noqa: BLE001 - the conductor must never crash mid-demo
            location = self._traceback_summary(exc)
            message = f"{type(exc).__name__}: {exc}"
            if location:
                message = f"{message} ({location})"
            self.state.errors.append(f"[{agent.name}] {message}")
            self.state.stage = PipelineStage.FAILED
            self._audit("agent_failed", {"agent": agent.name, "error": message})
            self._save()
            print(paint(f"    FAILED - {message}", "red"))
            return False
        self._save()
        new_events = self.state.audit[audit_start:]
        had_error = any(e.action == "error" for e in new_events)
        outcome = self._outcome_line(agent.name, new_events)
        print(paint(f"    {outcome}", "yellow" if had_error else "green"))
        return True

    @staticmethod
    def _traceback_summary(exc: BaseException) -> str:
        """One-line ``file:line in func`` summary of where an exception rose."""
        frames = traceback.extract_tb(exc.__traceback__)
        if not frames:
            return ""
        last = frames[-1]
        return f"{Path(last.filename).name}:{last.lineno} in {last.name}"

    @staticmethod
    def _outcome_line(agent_name: str, new_events: list[Any]) -> str:
        """Build the post-agent one-liner from the newest audit events."""
        own = [e for e in new_events if e.agent == agent_name]
        events = own or list(new_events)
        if not events:
            return "completed (no audit events emitted)"
        informative = [e for e in events if e.action != "error"]
        evt = (informative or events)[-1]
        label = evt.action.replace("_", " ").replace("-", " ")
        summary = summarize_detail(evt.detail)
        return f"{label} - {summary}" if summary else label

    # ---- convergence predicates ----

    def _within_budget(self, rule: DetectionRule) -> bool:
        """True when the rule's *latest version* has a within-budget forecast."""
        fc = self.state.forecasts.get(rule.rule_id)
        return fc is not None and fc.rule_version == rule.version and fc.within_budget

    def _tuning_attempts_left(self, rule: DetectionRule) -> bool:
        """True while the rule has been tuned fewer than the allowed times.

        Authors start rules at version 1 and the Tuning Optimizer increments
        the version once per tune, so ``version - 1`` is the tune count.
        """
        return (rule.version - 1) < self.state.max_tuning_iterations

    def _version_chain(self, rule_id: str) -> list[int]:
        """Distinct version numbers a rule went through, in order.

        Agents re-upsert a rule on status changes, so the raw history can
        contain duplicate versions; this collapses them.
        """
        seen: list[int] = []
        for entry in self.state.rule_history.get(rule_id, []):
            if entry.version not in seen:
                seen.append(entry.version)
        return seen

    def _needs_backtest(self, rule: DetectionRule) -> bool:
        bt = self.state.backtests.get(rule.rule_id)
        return bt is None or bt.rule_version != rule.version

    def _needs_forecast(self, rule: DetectionRule) -> bool:
        fc = self.state.forecasts.get(rule.rule_id)
        return fc is None or fc.rule_version != rule.version

    def _snapshot_forecasts(self) -> None:
        """Record per-version weekly predictions before tuning overwrites them."""
        for rid, fc in self.state.forecasts.items():
            self._forecast_history.setdefault(rid, {})[int(fc.rule_version)] = float(
                fc.predicted_weekly_alerts)

    # ---- banner descriptions ----

    def _desc_coverage(self) -> str:
        n = len(self.state.intel)
        return (f"mapping {n} intel item{_plural(n)} against the "
                "saved-search inventory")

    def _desc_author(self) -> str:
        n = len(self.state.gaps)
        return f"drafting detections for {n} coverage gap{_plural(n)}"

    def _desc_backtest(self) -> str:
        n = sum(1 for r in self.state.rules.values() if self._needs_backtest(r))
        if n:
            return f"replaying {n} rule version{_plural(n)} over labeled history"
        return "re-checking already-measured rule versions"

    def _desc_forecast(self) -> str:
        n = sum(1 for r in self.state.rules.values() if self._needs_forecast(r))
        if n:
            return f"forecasting weekly alert noise for {n} rule version{_plural(n)}"
        return "confirming existing alert-noise forecasts"

    def _desc_tune(self) -> str:
        over = sum(1 for r in self.state.rules.values() if not self._within_budget(r))
        if over:
            return (f"tuning {over} over-budget rule{_plural(over)} toward "
                    f"{self.state.fp_budget_weekly:g} alerts/week")
        return "verifying every rule sits within the noise budget"

    def _desc_harden(self) -> str:
        n = sum(1 for r in self.state.rules.values()
                if r.status is RuleStatus.BACKTESTED and self._within_budget(r))
        return (f"red-teaming {n} within-budget rule{_plural(n)} with MITRE-faithful "
                "evasion variants")

    def _desc_govern(self) -> str:
        n = sum(1 for r in self.state.rules.values()
                if r.status is RuleStatus.BACKTESTED)
        return f"reviewing evidence packs for {n} candidate rule{_plural(n)}"

    def _desc_deploy(self) -> str:
        n = sum(1 for d in self.state.decisions.values()
                if d.decision in (Decision.APPROVE_ACTIVE, Decision.APPROVE_SHADOW))
        return (f"deploying {n} approved rule{_plural(n)} as native Splunk "
                "saved searches")

    def _desc_verify(self) -> str:
        n = sum(1 for d in self.state.deployments.values() if not d.rolled_back)
        return f"checking {n} deployment{_plural(n)} against the forecast"

    # ---- persistence / audit ----

    def _save(self) -> None:
        """Persist the full state to runs/<run_id>/state.json."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.state.save(str(self.state_path))

    def _audit(self, action: str, detail: Optional[dict[str, Any]] = None) -> None:
        """Record an orchestrator decision in state + the flight recorder."""
        evt = self.state.add_audit("orchestrator", action, detail or {})
        if self.ctx.audit is not None:
            self.ctx.audit.write(evt)

    # ---- console output ----

    def _print_header(self) -> None:
        line = "=" * 70
        approve = "on" if self.state.auto_approve else "off"
        print(paint(line, "bold"))
        print(paint(" AEGIS FOUNDRY - autonomous detection engineering pipeline", "bold"))
        print(f" run: {self.state.run_id} | mode: {self.cfg.mode} | "
              f"fp budget: {self.state.fp_budget_weekly:g} alerts/week | "
              f"auto-approve: {approve}")
        print(paint(line, "bold"))

    def _print_final_summary(self) -> None:
        st = self.state
        line = "=" * 70
        done = st.stage is PipelineStage.DONE
        print("\n" + paint(line, "bold"))
        print(paint(f" RUN SUMMARY - {st.run_id}", "bold"))
        print(paint(line, "bold"))
        print(" outcome:           " +
              paint(st.stage.value.upper(), "green" if done else "red", "bold"))
        gap_bits = ", ".join(f"{g.technique_id} {g.technique_name}".strip()
                             for g in st.gaps) or "none"
        print(f" coverage gaps:     {len(st.gaps)} ({gap_bits})")
        total_versions = sum(len(self._version_chain(rid)) or 1 for rid in st.rules)
        print(f" rule versions:     {total_versions} across {len(st.rules)} "
              f"rule{_plural(len(st.rules))}")

        for rid, rule in st.rules.items():
            versions = self._version_chain(rid) or [rule.version]
            chain = " -> ".join(f"v{v}" for v in versions)
            print(f"\n   {paint(rule.name, 'bold')}  [{rid}]")
            print(f"     versions tried:  {chain}")

            v1_observed = v1_weekly_for_rule(st, rid)  # observed v1 backtest rate (matches console + ROI)
            v1_forecast = self._forecast_history.get(rid, {}).get(1)  # v1 forecast that tripped the gate
            final_fc = st.forecasts.get(rid)
            final_noise = final_fc.predicted_weekly_alerts if final_fc else None
            v1_txt = f"{v1_observed:.1f}/wk observed" if v1_observed is not None else "n/a"
            if v1_forecast is not None:
                v1_txt += f" (forecast {v1_forecast:.1f})"
            fin_txt = f"{final_noise:.1f}/wk forecast" if final_noise is not None else "n/a"
            print(f"     weekly noise:    v1 {v1_txt} -> v{rule.version} {fin_txt} "
                  f"(budget {st.fp_budget_weekly:g}/wk)")

            bt = st.backtests.get(rid)
            if bt is not None:
                print(f"     recall:          {bt.recall:.0%} "
                      f"({bt.true_positives}/{bt.labeled_attack_events} labeled "
                      f"attack events; precision {bt.precision:.0%})")
            dec = st.decisions.get(rid)
            if dec is not None:
                print(f"     governance:      {dec.decision.value} "
                      f"(by {dec.approver})")
                if dec.evidence_pack_path:
                    print(f"     evidence pack:   {dec.evidence_pack_path}")
            dep = st.deployments.get(rid)
            if dep is not None:
                rb = " [ROLLED BACK]" if dep.rolled_back else ""
                print(f"     deployment:      {dep.mode} mode as "
                      f"'{dep.saved_search_name}'{rb}")
            ver = st.verifications.get(rid)
            if ver is not None:
                print(f"     verification:    {ver.action} "
                      f"(observed {ver.observed_weekly_alerts:.1f}/wk vs forecast "
                      f"{ver.forecast_weekly_alerts:.1f}/wk, drift "
                      f"{ver.drift_ratio:.2f})")

        print(f"\n flight recorder:   {self.flight_recorder_path}")
        print(f" state file:        {self.state_path}")
        if st.errors:
            print(paint(f" errors:            {len(st.errors)}", "red"))
            for err in st.errors:
                print(paint(f"   - {err}", "red"))
        else:
            print(" errors:            0")
        print(paint(line, "bold"))

    # ---- episodic memory ----

    def _append_memory_summary(self) -> None:
        """Append the run's key numbers to cross-run episodic memory."""
        st = self.state
        rules_summary: list[dict[str, Any]] = []
        for rid, rule in st.rules.items():
            fh = self._forecast_history.get(rid, {})
            fc = st.forecasts.get(rid)
            bt = st.backtests.get(rid)
            dec = st.decisions.get(rid)
            dep = st.deployments.get(rid)
            ver = st.verifications.get(rid)
            rules_summary.append({
                "rule_id": rid,
                "name": rule.name,
                "final_version": rule.version,
                "v1_weekly_forecast": fh.get(1),
                "final_weekly_forecast": fc.predicted_weekly_alerts if fc else None,
                "recall": bt.recall if bt else None,
                "decision": dec.decision.value if dec else None,
                "deploy_mode": dep.mode if dep else None,
                "verification": ver.action if ver else None,
            })
        summary: dict[str, Any] = {
            "run_id": st.run_id,
            "finished_at": iso_now(),
            "stage": st.stage.value,
            "mode": self.cfg.mode,
            "gaps_found": len(st.gaps),
            "rules_drafted": len(st.rules),
            "total_rule_versions": sum(
                len(self._version_chain(rid)) or 1 for rid in st.rules),
            "fp_budget_weekly": st.fp_budget_weekly,
            "errors": len(st.errors),
            "rules": rules_summary,
        }
        try:
            self.ctx.memory.append_run_summary(summary)
        except Exception as exc:  # noqa: BLE001 - memory is advisory, never fatal
            print(paint(f" note: episodic memory write failed ({exc})", "yellow"))


def run_pipeline(cfg: Optional[AppConfig] = None) -> PipelineState:
    """Convenience entry point: build config from env (if absent) and run."""
    return Orchestrator(cfg or AppConfig.from_env()).run()
