"""ROI ledger: economic impact derived from measured pipeline numbers."""

from __future__ import annotations

from aegis_foundry.core.roi import compute_roi, v1_weekly_for_rule
from aegis_foundry.state import (
    DeploymentRecord,
    DetectionRule,
    ForecastResult,
    PipelineState,
    RoiModel,
    RuleStatus,
)


def _deployed_state() -> PipelineState:
    state = PipelineState(fp_budget_weekly=25.0)
    rule = DetectionRule(
        rule_id="rule-roi",
        name="r",
        description="d" * 30,
        spl="index=botsv3 process_name=powershell.exe",
        mitre_techniques=["T1059.001"],
        severity="high",
        status=RuleStatus.DEPLOYED_ACTIVE,
        version=2,
    )
    state.upsert_rule(rule)
    state.forecasts["rule-roi"] = ForecastResult(
        rule_id="rule-roi", rule_version=2, model="fallback-ewma", horizon_days=14,
        predicted_weekly_alerts=2.7, lower_bound_weekly=0.5, upper_bound_weekly=9.0,
        within_budget=True, fp_budget_weekly=25.0,
    )
    state.deployments["rule-roi"] = DeploymentRecord(
        rule_id="rule-roi", rule_version=2, saved_search_name="Aegis - r",
        mode="active", rollback_token="savedsearch::Aegis - r",
    )
    # the v1 (untuned) backtest is the honest noise baseline, from the audit trail
    state.add_audit("backtest-engineer", "backtest_completed",
                    {"rule_id": "rule-roi", "version": 1, "weekly_rate": 452.5})
    return state


def test_v1_weekly_from_audit():
    state = _deployed_state()
    assert v1_weekly_for_rule(state, "rule-roi") == 452.5


def test_roi_from_measured_numbers():
    state = _deployed_state()
    roi = compute_roi(state)
    assert roi.alerts_avoided_weekly == 449.8  # 452.5 - 2.7
    assert roi.detections_shipped == 1
    assert roi.engineering_dollars_saved == 3000.0  # 1 x 5 days x $600
    assert roi.annualized_dollars_saved > 0
    assert roi.total_annual_value == roi.annualized_dollars_saved + roi.engineering_dollars_saved
    assert roi.mttd_days_saved == 5.0


def test_roi_respects_custom_model():
    state = _deployed_state()
    cheap = compute_roi(state, RoiModel(analyst_hourly_cost=1.0, triage_minutes_per_alert=1.0))
    rich = compute_roi(state, RoiModel(analyst_hourly_cost=200.0, triage_minutes_per_alert=15.0))
    assert rich.annualized_dollars_saved > cheap.annualized_dollars_saved


def test_roi_ignores_rolled_back_deployments():
    state = _deployed_state()
    state.deployments["rule-roi"].rolled_back = True
    roi = compute_roi(state)
    assert roi.detections_shipped == 0
    assert roi.alerts_avoided_weekly == 0.0
