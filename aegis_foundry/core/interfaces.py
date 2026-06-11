"""Protocol contracts for Aegis Foundry's tool plane.

Agents never talk to Splunk or models directly: they receive client objects
that satisfy these protocols via AgentContext. Each protocol has a real
implementation (live Splunk / live models) and a deterministic mock backed by
demo/fixtures, so the same agent code runs in both modes unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass
class SearchResult:
    """Result of an SPL search executed through the Splunk MCP Server."""

    spl: str
    results: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    job_sid: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class SPLValidation:
    valid: bool
    error: Optional[str] = None


@dataclass
class ForecastPoint:
    time: str  # ISO-8601
    predicted: float
    lower: float
    upper: float


@dataclass
class ForecastSeries:
    model: str  # "CDTSM" | "fallback-ewma"
    points: list[ForecastPoint] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.points)


@runtime_checkable
class LLMClient(Protocol):
    """Text-completion interface. Implementations: OpenAICompatibleLLM (Ollama/
    vLLM/any OpenAI-compatible endpoint), SplunkAICommandLLM (routes through
    the AI Toolkit ``| ai`` command so data never leaves Splunk), MockLLM."""

    def complete(self, prompt: str, *, system: Optional[str] = None, model: Optional[str] = None,
                 max_tokens: int = 1024) -> str:
        """Return the model's text response. Raises LLMError on failure."""
        ...


@runtime_checkable
class MCPClient(Protocol):
    """Splunk MCP Server interface — the agents' hands on Splunk data.

    Real implementation speaks MCP streamable HTTP with bearer-token auth and
    calls the ``splunk_*`` / ``saia_*`` tools; the mock replays fixtures.
    """

    def list_tools(self) -> list[str]:
        """Names of tools exposed by the MCP server."""
        ...

    def run_search(self, spl: str, *, earliest: str = "-90d", latest: str = "now",
                   max_results: int = 1000) -> SearchResult:
        """Execute an SPL search and return rows as dicts."""
        ...

    def validate_spl(self, spl: str) -> SPLValidation:
        """Syntax-check SPL without materializing results (parse-only run)."""
        ...

    def list_saved_searches(self) -> list[dict[str, Any]]:
        """Inventory of existing detections: [{name, search, description, ...}]."""
        ...

    def generate_spl(self, natural_language: str) -> str:
        """NL -> SPL via the saia_generate_spl tool (AI Assistant), if available."""
        ...


@runtime_checkable
class SplunkAdminClient(Protocol):
    """Management-plane operations (deploys) via Splunk REST / Python SDK.

    Kept separate from MCPClient because deployment is a privileged write
    path that the Governor gates; the MCP search plane stays read-only.
    """

    def create_saved_search(self, name: str, spl: str, *, description: str = "",
                            cron_schedule: str = "*/10 * * * *", disabled: bool = False,
                            extra: Optional[dict[str, Any]] = None) -> str:
        """Create/update a saved search. Returns a rollback token."""
        ...

    def delete_saved_search(self, name: str) -> bool:
        ...

    def rollback(self, rollback_token: str) -> bool:
        """Undo a deployment identified by its rollback token."""
        ...


@runtime_checkable
class ForecastClient(Protocol):
    """Time-series forecasting. Real implementation runs ``| apply CDTSM``
    through the search plane (Splunk Cloud + AI Toolkit 5.7+); the fallback
    is a dependency-free EWMA + seasonal-naive forecaster used in mock mode
    or when CDTSM is unavailable — always labeled honestly in results."""

    def forecast(self, series: list[tuple[str, float]], *, forecast_k: int = 168,
                 conf_interval: int = 90) -> ForecastSeries:
        """series: [(iso_time, value)] at fixed resolution (hourly).
        forecast_k: number of future points. Returns labeled ForecastSeries."""
        ...


class LLMError(RuntimeError):
    pass


class MCPError(RuntimeError):
    pass


class DeployError(RuntimeError):
    pass
