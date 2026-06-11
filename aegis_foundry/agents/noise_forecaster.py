"""Noise Forecaster agent.

Turns each rule's backtest hit timeline into a forward-looking alert-volume
forecast and judges it against the run's weekly false-positive budget. In
live mode it prefers the in-Splunk path — the Cisco Deep Time Series Model
applied directly to the rule's SPL via ``| apply CDTSM`` — and otherwise
feeds the daily series to the configured ForecastClient (the deterministic,
honestly-labeled fallback forecaster in mock mode).

The budget verdict computed here is what drives the orchestrator's
backtest -> forecast -> tune loop: a rule only graduates toward governance
once its predicted weekly alert volume (and the upper confidence bound)
fits the budget.
"""

from __future__ import annotations

from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import ForecastSeries
from aegis_foundry.state import (
    ForecastResult,
    PipelineStage,
    PipelineState,
)

#: Forecast horizon, in days (and future points at daily resolution).
HORIZON_DAYS: int = 14

#: Confidence interval requested from the forecaster, in percent.
CONF_INTERVAL: int = 90


class NoiseForecaster(Agent):
    """Forecasts future alert noise for every freshly backtested rule."""

    name = "noise-forecaster"

    def run(self, state: PipelineState) -> PipelineState:
        """Forecast each rule with a fresh backtest, then advance to TUNE.

        A rule is eligible when a backtest exists for its *current* version
        (clean, no error) and no forecast has been stored for that version
        yet — the version guards keep the orchestrator's measure/tune loop
        from re-forecasting finished work.
        """
        budget = state.fp_budget_weekly

        for rule in list(state.rules.values()):
            backtest = state.backtests.get(rule.rule_id)
            if (
                backtest is None
                or backtest.rule_version != rule.version
                or not backtest.syntax_valid
                or backtest.error is not None
            ):
                continue  # no fresh, clean measurement to forecast from
            forecast = state.forecasts.get(rule.rule_id)
            if forecast is not None and forecast.rule_version == rule.version:
                continue  # this version is already forecast

            series: list[tuple[str, float]] = [
                (str(bucket.get("_time", "")), float(bucket.get("count", 0)))
                for bucket in backtest.hit_timeline
            ]

            try:
                series_result = self._forecast(rule.spl, series)
            except Exception as exc:  # tool-plane failures must not kill the run
                self.fail(
                    state,
                    f"forecast failed for {rule.rule_id} v{rule.version}: {exc}",
                )
                continue
            if not series_result.ok:
                self.fail(
                    state,
                    f"forecast failed for {rule.rule_id} v{rule.version}: "
                    f"{series_result.error or 'empty forecast'}",
                )
                continue

            first_week = series_result.points[:7]
            predicted_weekly = float(sum(p.predicted for p in first_week))
            lower_weekly = float(sum(p.lower for p in first_week))
            upper_weekly = float(sum(p.upper for p in first_week))
            within_budget = predicted_weekly <= budget and upper_weekly <= budget * 1.5

            state.forecasts[rule.rule_id] = ForecastResult(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                model=series_result.model,
                horizon_days=HORIZON_DAYS,
                predicted_weekly_alerts=predicted_weekly,
                lower_bound_weekly=lower_weekly,
                upper_bound_weekly=upper_weekly,
                conf_interval=CONF_INTERVAL,
                points=[
                    {
                        "_time": p.time,
                        "predicted": p.predicted,
                        "lower90": p.lower,
                        "upper90": p.upper,
                    }
                    for p in series_result.points
                ],
                within_budget=within_budget,
                fp_budget_weekly=budget,
            )

            self.emit(
                state,
                "noise_forecast",
                {
                    "rule_id": rule.rule_id,
                    "model": series_result.model,
                    "predicted_weekly": round(predicted_weekly, 1),
                    "band": [round(lower_weekly, 1), round(upper_weekly, 1)],
                    "within_budget": within_budget,
                },
            )

        state.stage = PipelineStage.TUNE
        return state

    # ---- internals ----

    def _forecast(self, spl: str, series: list[tuple[str, float]]) -> ForecastSeries:
        """Run the forecast, preferring the live in-Splunk CDTSM path.

        When the configured forecaster exposes ``forecast_from_spl`` and the
        app is in live mode, the rule's SPL is forecast directly inside
        Splunk (``| apply CDTSM``) so the data never leaves the platform.
        Otherwise the daily hit series from the backtest is forecast through
        the standard ForecastClient protocol.
        """
        forecaster = self.ctx.forecaster
        if hasattr(forecaster, "forecast_from_spl") and not self.ctx.config.is_mock:
            return forecaster.forecast_from_spl(spl, forecast_k=HORIZON_DAYS)
        return forecaster.forecast(
            series, forecast_k=HORIZON_DAYS, conf_interval=CONF_INTERVAL
        )
