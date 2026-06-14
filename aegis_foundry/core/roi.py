"""ROI model for Aegis Foundry.

Converts a run's *measured* pipeline numbers into an auditable economic impact:
analyst-hours and dollars saved by the noise reduction, engineering cost avoided
by autonomous authoring, and the lead-time (MTTD) compression of covering a gap
in minutes instead of days. Every input is a real value the agents produced —
v1 backtest noise, the final within-budget forecast, the count of deployed
detections — so the headline number is defensible, not invented.

The function is pure over :class:`~aegis_foundry.state.PipelineState`, so it is
trivially testable and identical in mock and live runs.
"""

from __future__ import annotations

from typing import Optional

from aegis_foundry.state import PipelineState, RoiModel, RoiResult

__all__ = ["compute_roi", "v1_weekly_for_rule"]


def v1_weekly_for_rule(state: PipelineState, rule_id: str) -> Optional[float]:
    """Weekly hit rate of a rule's *version 1* backtest, from the audit trail.

    The Backtest Engineer records ``weekly_rate`` per version in its
    ``backtest_completed`` events; ``state.backtests`` only keeps the latest
    version, so the audit trail is the honest source for the original (untuned)
    noise. Falls back to the latest backtest's weekly rate when no v1 event
    exists (a rule deployed without tuning).
    """
    for evt in state.audit:
        if evt.action != "backtest_completed":
            continue
        detail = evt.detail or {}
        if detail.get("version") != 1:
            continue
        if detail.get("rule_id") not in (None, rule_id):
            continue
        rate = detail.get("weekly_rate")
        if isinstance(rate, (int, float)):
            return float(rate)
    bt = state.backtests.get(rule_id)
    if bt is not None and bt.window_days > 0:
        return bt.total_hits / bt.window_days * 7.0
    return None


def compute_roi(state: PipelineState, model: Optional[RoiModel] = None) -> RoiResult:
    """Quantify the run's economic impact from its measured numbers."""
    model = model or RoiModel()

    deployed_ids = [
        rid for rid, dep in state.deployments.items() if not dep.rolled_back
    ]

    alerts_avoided_weekly = 0.0
    for rid in deployed_ids:
        v1 = v1_weekly_for_rule(state, rid)
        forecast = state.forecasts.get(rid)
        final = forecast.predicted_weekly_alerts if forecast is not None else None
        if v1 is not None and final is not None:
            alerts_avoided_weekly += max(0.0, v1 - final)

    analyst_hours_saved_weekly = alerts_avoided_weekly * model.triage_minutes_per_alert / 60.0
    analyst_hours_saved_annual = analyst_hours_saved_weekly * model.weeks_per_year
    annualized_dollars_saved = analyst_hours_saved_annual * model.analyst_hourly_cost

    detections_shipped = len(deployed_ids)
    engineering_days_saved = detections_shipped * model.manual_engineering_days_per_detection
    engineering_dollars_saved = engineering_days_saved * model.engineer_daily_cost

    # Coverage that used to take days of manual work is now live in minutes:
    # the per-detection authoring lead-time is the dwell-window compression.
    mttd_days_saved = (
        model.manual_engineering_days_per_detection if detections_shipped else 0.0
    )

    total_annual_value = annualized_dollars_saved + engineering_dollars_saved

    return RoiResult(
        alerts_avoided_weekly=round(alerts_avoided_weekly, 1),
        analyst_hours_saved_weekly=round(analyst_hours_saved_weekly, 1),
        analyst_hours_saved_annual=round(analyst_hours_saved_annual, 0),
        annualized_dollars_saved=round(annualized_dollars_saved, 0),
        detections_shipped=detections_shipped,
        engineering_days_saved=round(engineering_days_saved, 1),
        engineering_dollars_saved=round(engineering_dollars_saved, 0),
        mttd_days_saved=round(mttd_days_saved, 1),
        total_annual_value=round(total_annual_value, 0),
        model=model,
    )
