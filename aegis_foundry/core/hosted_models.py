"""Forecasting clients for the Noise Forecaster agent.

Two interchangeable :class:`~aegis_foundry.core.interfaces.ForecastClient`
implementations:

- :class:`CDTSMForecastClient` — the live path. Reconstructs the alert-count
  series inside Splunk with ``| makeresults`` (or runs a ``| timechart``
  directly over a base search) and applies the hosted **Cisco Deep Time
  Series Model** via the AI Toolkit's ``| apply CDTSM`` command through the
  Splunk MCP search plane.

- :class:`FallbackForecaster` — a deterministic, dependency-free EWMA +
  day-of-week seasonal forecaster used in mock mode or whenever CDTSM is
  unavailable. Results are always labeled honestly (``model="fallback-ewma"``
  vs ``model="CDTSM"``) so the evidence pack never overstates provenance.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from aegis_foundry.core.interfaces import (
    ForecastClient,
    ForecastPoint,
    ForecastSeries,
    MCPClient,
    MCPError,
)

logger = logging.getLogger(__name__)

#: Honest model label for the deterministic local forecaster.
FALLBACK_MODEL = "fallback-ewma"

#: EWMA smoothing factor for the fallback level estimate.
_EWMA_ALPHA = 0.3

#: Two-sided normal critical values for the supported confidence intervals.
_Z_TABLE: dict[int, float] = {
    20: 0.253,
    40: 0.524,
    50: 0.674,
    60: 0.842,
    80: 1.282,
    90: 1.645,
    98: 2.326,
}

_SPAN_RE = re.compile(r"^(\d+)([smhd])$")
_SPAN_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp (tolerating a trailing ``Z``) to a datetime."""
    dt = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _z_for(conf_interval: int) -> float:
    """Critical value for ``conf_interval``; nearest supported CI when unlisted."""
    if conf_interval in _Z_TABLE:
        return _Z_TABLE[conf_interval]
    nearest = min(_Z_TABLE, key=lambda ci: (abs(ci - conf_interval), ci))
    return _Z_TABLE[nearest]


class FallbackForecaster(ForecastClient):
    """Deterministic EWMA + day-of-week seasonal forecaster (stdlib only).

    Algorithm (exactly reproducible for a given input):

    1. Day-of-week seasonal offsets: mean per weekday minus the global mean.
    2. Level: EWMA (``alpha = 0.3``) over the deseasonalized history.
    3. Forecast for each future day ``t``: ``max(0, level + seasonal[t])``.
    4. Uncertainty: the standard deviation of one-step-ahead errors over the
       history, widened by the normal critical value for the requested
       confidence interval; the lower band is clamped at 0.

    Never raises: malformed input is reported via ``ForecastSeries.error``.
    """

    def forecast(
        self,
        series: list[tuple[str, float]],
        *,
        forecast_k: int = 14,
        conf_interval: int = 90,
    ) -> ForecastSeries:
        """Forecast ``forecast_k`` future daily counts from a daily-count series."""
        if not series:
            return ForecastSeries(model=FALLBACK_MODEL, error="cannot forecast an empty series")
        try:
            parsed = sorted(
                ((_parse_iso(ts), float(value)) for ts, value in series),
                key=lambda pair: pair[0],
            )
        except (TypeError, ValueError) as exc:
            return ForecastSeries(model=FALLBACK_MODEL, error=f"unparseable series point: {exc}")

        times = [t for t, _ in parsed]
        values = [v for _, v in parsed]
        n = len(values)
        global_mean = sum(values) / n

        by_weekday: dict[int, list[float]] = {}
        for when, value in parsed:
            by_weekday.setdefault(when.weekday(), []).append(value)
        seasonal = {wd: (sum(vs) / len(vs)) - global_mean for wd, vs in by_weekday.items()}

        deseasonalized = [v - seasonal.get(t.weekday(), 0.0) for t, v in parsed]
        level = deseasonalized[0]
        errors: list[float] = []
        for i in range(1, n):
            one_step = level + seasonal.get(times[i].weekday(), 0.0)
            errors.append(values[i] - one_step)
            level = _EWMA_ALPHA * deseasonalized[i] + (1.0 - _EWMA_ALPHA) * level

        if len(errors) >= 2:
            err_mean = sum(errors) / len(errors)
            residual_std = (sum((e - err_mean) ** 2 for e in errors) / len(errors)) ** 0.5
        else:
            residual_std = 0.0

        half_width = _z_for(conf_interval) * residual_std
        last = times[-1]
        points: list[ForecastPoint] = []
        for step in range(1, max(0, int(forecast_k)) + 1):
            when = last + timedelta(days=step)
            predicted = max(0.0, level + seasonal.get(when.weekday(), 0.0))
            points.append(
                ForecastPoint(
                    time=when.isoformat(),
                    predicted=round(predicted, 6),
                    lower=round(max(0.0, predicted - half_width), 6),
                    upper=round(predicted + half_width, 6),
                )
            )
        return ForecastSeries(model=FALLBACK_MODEL, points=points)


class CDTSMForecastClient(ForecastClient):
    """Hosted Cisco Deep Time Series Model via ``| apply CDTSM`` over MCP.

    The series is reconstructed in-Splunk with ``| makeresults format=csv``
    (or produced directly by ``| timechart`` in :meth:`forecast_from_spl`,
    the preferred live path) and forecast by the hosted CDTSM. On any error,
    the client logs the degradation and — when a fallback forecaster was
    provided — returns the fallback's forecast under the fallback's **own**
    model label, never masquerading as CDTSM. Without a fallback, failures
    raise :class:`MCPError`.
    """

    def __init__(self, mcp: MCPClient, fallback: Optional[ForecastClient] = None) -> None:
        self._mcp = mcp
        self._fallback = fallback

    # ---- SPL construction & parsing ----

    @staticmethod
    def _apply_clause(forecast_k: int, conf_interval: int) -> str:
        return (
            f"| apply CDTSM count forecast_k={int(forecast_k)} "
            f"conf_interval={int(conf_interval)} time_field=_time show_input=false"
        )

    @staticmethod
    def _build_makeresults_spl(
        series: list[tuple[str, float]], forecast_k: int, conf_interval: int
    ) -> str:
        """SPL that rebuilds the series in-Splunk and applies the hosted CDTSM."""
        rows = ["_time,count"]
        for ts, value in series:
            stamp = _parse_iso(ts).strftime("%Y-%m-%dT%H:%M:%S")
            rows.append(f"{stamp},{float(value):g}")
        csv_blob = "\n".join(rows)
        return (
            f'| makeresults format=csv data="{csv_blob}" '
            '| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%S") '
            f"{CDTSMForecastClient._apply_clause(forecast_k, conf_interval)}"
        )

    @staticmethod
    def _coerce_time(raw: Any) -> str:
        """Normalize a row ``_time`` (epoch seconds or ISO string) to ISO-8601."""
        text = str(raw).strip()
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError, OverflowError):
            return text

    @staticmethod
    def _pick(row: dict[str, Any], exact: str, prefix: str) -> Optional[float]:
        """Read a numeric field by exact name, else by name prefix (e.g. ``lower``)."""
        keys = [exact] + sorted(k for k in row if k != exact and k.startswith(prefix))
        for key in keys:
            if key in row and row[key] not in (None, ""):
                try:
                    return float(row[key])
                except (TypeError, ValueError):
                    continue
        return None

    @classmethod
    def _parse_forecast_rows(
        cls, rows: list[dict[str, Any]], conf_interval: int
    ) -> list[ForecastPoint]:
        """Map ``predicted``/``lower{ci}``/``upper{ci}`` columns to ForecastPoints."""
        points: list[ForecastPoint] = []
        for row in rows:
            predicted = cls._pick(row, "predicted", "predicted")
            if predicted is None:
                continue  # historical/input row or non-forecast artifact
            lower = cls._pick(row, f"lower{conf_interval}", "lower")
            upper = cls._pick(row, f"upper{conf_interval}", "upper")
            points.append(
                ForecastPoint(
                    time=cls._coerce_time(row.get("_time", "")),
                    predicted=predicted,
                    lower=max(0.0, lower if lower is not None else predicted),
                    upper=upper if upper is not None else predicted,
                )
            )
        return points

    # ---- degradation ----

    def _degrade(
        self,
        reason: str,
        series: list[tuple[str, float]],
        forecast_k: int,
        conf_interval: int,
    ) -> ForecastSeries:
        """Fall back honestly (fallback's own label) or raise when impossible."""
        if self._fallback is None:
            raise MCPError(f"CDTSM forecast failed and no fallback is configured: {reason}")
        logger.warning("CDTSM unavailable (%s); degrading to local fallback forecaster", reason)
        return self._fallback.forecast(series, forecast_k=forecast_k, conf_interval=conf_interval)

    # ---- ForecastClient protocol ----

    def forecast(
        self,
        series: list[tuple[str, float]],
        *,
        forecast_k: int = 14,
        conf_interval: int = 90,
    ) -> ForecastSeries:
        """Forecast a daily-count series with the hosted CDTSM (fallback on error)."""
        try:
            if not series:
                raise MCPError("cannot forecast an empty series")
            spl = self._build_makeresults_spl(series, forecast_k, conf_interval)
            result = self._mcp.run_search(
                spl,
                earliest="-1d",
                latest="now",
                max_results=len(series) + int(forecast_k) + 16,
            )
            if not result.ok:
                raise MCPError(result.error or "CDTSM search failed")
            points = self._parse_forecast_rows(result.results, conf_interval)
            if not points:
                raise MCPError("CDTSM returned no forecast rows")
            return ForecastSeries(model="CDTSM", points=points)
        except Exception as exc:  # noqa: BLE001 — every failure degrades honestly
            return self._degrade(str(exc), series, forecast_k, conf_interval)

    # ---- preferred live path ----

    @staticmethod
    def _as_search(base_spl: str) -> str:
        stripped = base_spl.strip()
        if stripped.startswith("|"):
            return stripped
        first = re.split(r"\s+", stripped, maxsplit=1)[0].lower()
        return stripped if first == "search" else f"search {stripped}"

    @staticmethod
    def _span_seconds(span: str) -> int:
        match = _SPAN_RE.match(span.strip().lower())
        if not match:
            return 86400  # default to daily buckets
        return int(match.group(1)) * _SPAN_UNIT_SECONDS[match.group(2)]

    @classmethod
    def _rows_to_series(
        cls, rows: list[dict[str, Any]], span: str
    ) -> list[tuple[str, float]]:
        """Turn timechart rows — or raw events — into a [(iso, count)] series."""
        counted: list[tuple[str, float]] = []
        for row in rows:
            if "_time" not in row:
                continue
            value: Any = row.get("count")
            if value is None:
                for key in sorted(row):
                    if key.startswith("count") and key != "_time":
                        value = row[key]
                        break
            if value in (None, ""):
                continue
            try:
                counted.append((cls._coerce_time(row["_time"]), float(value)))
            except (TypeError, ValueError):
                continue
        if counted:
            return sorted(counted)
        # Raw events (e.g. a mock plane that does not evaluate pipes): bucket them.
        seconds = cls._span_seconds(span)
        buckets: dict[int, int] = {}
        for row in rows:
            raw = row.get("_time")
            if raw is None:
                continue
            try:
                epoch = _parse_iso(str(raw)).timestamp()
            except ValueError:
                try:
                    epoch = float(str(raw))
                except (TypeError, ValueError):
                    continue
            start = int(epoch // seconds) * seconds
            buckets[start] = buckets.get(start, 0) + 1
        return [
            (datetime.fromtimestamp(start, tz=timezone.utc).isoformat(), float(count))
            for start, count in sorted(buckets.items())
        ]

    def forecast_from_spl(
        self,
        base_spl: str,
        *,
        span: str = "1d",
        forecast_k: int = 14,
        conf_interval: int = 90,
    ) -> ForecastSeries:
        """Forecast a rule's alert volume straight from its SPL (preferred live path).

        Runs ``search <base_spl> | timechart span=<span> count | apply CDTSM ...``
        so the history never leaves Splunk. On any error the client rebuilds the
        series from a plain timechart (bucketing raw events when the search plane
        does not evaluate pipes) and hands it to the fallback forecaster.
        """
        timechart_spl = f"{self._as_search(base_spl)} | timechart span={span} count"
        apply_spl = f"{timechart_spl} {self._apply_clause(forecast_k, conf_interval)}"
        try:
            result = self._mcp.run_search(
                apply_spl, earliest="-90d", latest="now", max_results=100000
            )
            if not result.ok:
                raise MCPError(result.error or "CDTSM search failed")
            points = self._parse_forecast_rows(result.results, conf_interval)
            if not points:
                raise MCPError("CDTSM returned no forecast rows")
            return ForecastSeries(model="CDTSM", points=points)
        except Exception as exc:  # noqa: BLE001 — every failure degrades honestly
            reason = str(exc)
            if self._fallback is None:
                raise MCPError(
                    f"CDTSM forecast failed and no fallback is configured: {reason}"
                ) from exc
            history = self._mcp.run_search(
                timechart_spl, earliest="-90d", latest="now", max_results=100000
            )
            if not history.ok:
                raise MCPError(
                    f"CDTSM failed ({reason}) and history search also failed: {history.error}"
                ) from exc
            series = self._rows_to_series(history.results, span)
            if not series:
                raise MCPError(
                    f"CDTSM failed ({reason}) and the base search returned no history"
                ) from exc
            return self._degrade(reason, series, forecast_k, conf_interval)
