"""FallbackForecaster: deterministic, sane, honestly labeled."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aegis_foundry.core.hosted_models import FallbackForecaster


def _daily_series(values: list[float]) -> list[tuple[str, float]]:
    start = datetime(2026, 3, 16, tzinfo=timezone.utc)
    return [((start + timedelta(days=i)).isoformat(), v) for i, v in enumerate(values)]


def test_deterministic():
    series = _daily_series([2.0, 3.0, 1.0, 4.0, 2.0, 0.0, 5.0] * 8)
    f = FallbackForecaster()
    a = f.forecast(series, forecast_k=14, conf_interval=90)
    b = f.forecast(series, forecast_k=14, conf_interval=90)
    assert a.model == "fallback-ewma"
    assert [(p.time, p.predicted, p.lower, p.upper) for p in a.points] == [
        (p.time, p.predicted, p.lower, p.upper) for p in b.points
    ]


def test_flat_series_weekly_sum_close_to_truth():
    series = _daily_series([2.0] * 60)
    fc = FallbackForecaster().forecast(series, forecast_k=14, conf_interval=90)
    assert fc.ok
    assert len(fc.points) == 14
    weekly = sum(p.predicted for p in fc.points[:7])
    assert 14.0 * 0.8 <= weekly <= 14.0 * 1.2


def test_bounds_non_negative_and_ordered():
    series = _daily_series([0.0, 1.0, 0.0, 2.0, 0.0, 0.0, 1.0] * 10)
    fc = FallbackForecaster().forecast(series, forecast_k=14, conf_interval=90)
    for p in fc.points:
        assert p.lower >= 0.0
        assert p.lower <= p.predicted <= p.upper
