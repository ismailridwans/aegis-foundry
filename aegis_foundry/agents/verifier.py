"""Verifier agent: did reality match the forecast?

After deployment the loop is not closed until the rule's real alert volume is
checked against the Noise Forecaster's prediction. The Verifier re-runs each
deployed rule's SPL over the most recent 7 days through the Splunk MCP
search plane, compares the observed weekly alert count with the forecast's
90% confidence band, and takes one of three actions:

- ``ok``       — observed volume sits inside the (slightly padded) band, or
  below it (a quiet rule is not a noise risk). Rule becomes ``VERIFIED``.
- ``retune``   — observed volume exceeds the band's upper bound: the rule is
  noisier than predicted, so it is flagged ``RETUNE_REQUIRED`` for the
  Tuning Optimizer to revisit on the orchestrator's next loop.
- ``rollback`` — observed volume exceeds 10x the weekly false-positive
  budget: a runaway rule. The Verifier immediately undoes the deployment via
  the rollback token recorded by the Deployer and marks the rule
  ``ROLLED_BACK``.

The forecast band is padded by +/- 1.0 alert in absolute terms so a rule
predicted at 1.9/week that fires twice does not flap between verdicts on a
knife-edge boundary.
"""

from __future__ import annotations

from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import DeployError
from aegis_foundry.state import (
    DeploymentRecord,
    DetectionRule,
    PipelineStage,
    PipelineState,
    RuleStatus,
    VerificationResult,
)

#: Absolute padding (alerts/week) applied to both ends of the forecast band
#: to avoid knife-edge verdict flapping.
_BAND_PAD = 1.0

#: Drift ratio reported when the forecast predicted zero but alerts fired.
_INF_DRIFT = 999.0


class Verifier(Agent):
    """Compare post-deploy alert volume against the forecast and react."""

    name: str = "verifier"

    def run(self, state: PipelineState) -> PipelineState:
        """Verify every deployed rule, then advance to DONE.

        The orchestrator may loop rules flagged ``RETUNE_REQUIRED`` back
        through the tuning stage; runaway rules are rolled back here and now.
        """
        deployed_statuses = (RuleStatus.DEPLOYED_ACTIVE, RuleStatus.DEPLOYED_SHADOW)
        for rule_id, rule in list(state.rules.items()):
            if rule.status not in deployed_statuses:
                continue
            deployment = state.deployments.get(rule_id)
            if deployment is None:
                self.fail(state, f"rule {rule_id} marked deployed but has no deployment record")
                continue
            forecast = state.forecasts.get(rule_id)
            if forecast is None:
                self.fail(state, f"rule {rule_id} deployed without a forecast; cannot verify")
                continue

            observed = self.ctx.mcp.run_search(rule.spl, earliest="-7d", max_results=10000)
            if not observed.ok:
                self.fail(state, f"verification search failed for rule {rule_id}: {observed.error}")
                continue
            observed_weekly = float(len(observed.results))

            predicted = forecast.predicted_weekly_alerts
            if predicted == 0:
                drift_ratio = 1.0 if observed_weekly == 0 else _INF_DRIFT
            else:
                drift_ratio = observed_weekly / predicted

            lower = forecast.lower_bound_weekly - _BAND_PAD
            upper = forecast.upper_bound_weekly + _BAND_PAD
            within_band = lower <= observed_weekly <= upper

            band_text = (
                f"forecast {predicted:.1f} "
                f"[{forecast.lower_bound_weekly:.1f}, {forecast.upper_bound_weekly:.1f}]"
            )
            runaway_threshold = 10.0 * state.fp_budget_weekly

            if observed_weekly > runaway_threshold:
                action = "rollback"
                detail = (
                    f"Observed {observed_weekly:.1f} alerts in first post-deploy week vs "
                    f"{band_text} - exceeds 10x the weekly false-positive budget "
                    f"({runaway_threshold:.1f}); runaway rule rolled back."
                )
                self._rollback(state, rule, deployment)
            elif within_band:
                action = "ok"
                if observed_weekly < forecast.lower_bound_weekly:
                    detail = (
                        f"Observed {observed_weekly:.1f} alerts in first post-deploy week vs "
                        f"{band_text} - quieter than forecast but within the padded "
                        f"{forecast.conf_interval}% band."
                    )
                else:
                    detail = (
                        f"Observed {observed_weekly:.1f} alerts in first post-deploy week vs "
                        f"{band_text} - within the {forecast.conf_interval}% band."
                    )
                rule.status = RuleStatus.VERIFIED
            elif observed_weekly > upper:
                action = "retune"
                detail = (
                    f"Observed {observed_weekly:.1f} alerts in first post-deploy week vs "
                    f"{band_text} - above the {forecast.conf_interval}% band; rule is "
                    "noisier than forecast and needs retuning."
                )
                rule.status = RuleStatus.RETUNE_REQUIRED
            else:
                # Below the padded lower bound: under-firing, not a noise risk.
                action = "ok"
                detail = (
                    f"Observed {observed_weekly:.1f} alerts in first post-deploy week vs "
                    f"{band_text} - below the {forecast.conf_interval}% band; rule is "
                    "quieter than forecast, no noise risk, monitoring continues."
                )
                rule.status = RuleStatus.VERIFIED

            result = VerificationResult(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                observed_weekly_alerts=observed_weekly,
                forecast_weekly_alerts=predicted,
                drift_ratio=drift_ratio,
                within_forecast_band=within_band,
                action=action,
                detail=detail,
            )
            state.verifications[rule.rule_id] = result

            self.emit(
                state,
                "verification",
                {
                    "rule_id": rule.rule_id,
                    "rule_version": rule.version,
                    "observed_weekly_alerts": observed_weekly,
                    "forecast_weekly_alerts": predicted,
                    "lower_bound_weekly": forecast.lower_bound_weekly,
                    "upper_bound_weekly": forecast.upper_bound_weekly,
                    "band_pad": _BAND_PAD,
                    "drift_ratio": drift_ratio,
                    "within_forecast_band": within_band,
                    "fp_budget_weekly": state.fp_budget_weekly,
                    "runaway_threshold": runaway_threshold,
                    "action": action,
                },
            )

        state.stage = PipelineStage.DONE
        return state

    # ------------------------------------------------------------------

    def _rollback(
        self, state: PipelineState, rule: DetectionRule, deployment: DeploymentRecord
    ) -> None:
        """Undo a runaway deployment via its rollback token."""
        try:
            ok = self.ctx.admin.rollback(deployment.rollback_token)
        except DeployError as exc:
            self.fail(
                state,
                f"rollback failed for rule {rule.rule_id} "
                f"(token {deployment.rollback_token}): {exc}",
            )
            ok = False
        if ok:
            deployment.rolled_back = True
            rule.status = RuleStatus.ROLLED_BACK
        else:
            # Rollback could not be confirmed; keep the rule flagged for
            # human-driven retuning rather than pretending it is gone.
            rule.status = RuleStatus.RETUNE_REQUIRED
