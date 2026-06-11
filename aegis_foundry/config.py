"""Runtime configuration for Aegis Foundry.

Two operating modes, selected by ``AEGIS_MODE``:

- ``mock`` (default): fully offline. The Splunk MCP client, hosted models, and
  LLM are backed by deterministic local fixtures so the entire agentic
  pipeline runs end-to-end on a laptop with zero credentials. This is the
  mode judges can run from the README in under a minute.

- ``live``: talks to a real Splunk deployment. Searches and knowledge-object
  discovery go through the Splunk MCP Server (token auth, streamable HTTP);
  forecasting uses ``| apply CDTSM`` (Splunk Cloud + AI Toolkit 5.7+);
  security reasoning uses Foundation-Sec-1.1-8B and gpt-oss via the AI
  Toolkit ``| ai`` command or any OpenAI-compatible endpoint (e.g. a local
  Ollama/vLLM serving the open-weight models).

All settings come from environment variables so no secrets ever live in the
repo. See .env.example for the full list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


@dataclass
class SplunkConfig:
    """Connection settings for the Splunk MCP Server and management REST API."""

    mcp_url: str = ""            # e.g. https://<host>:8089/services/mcp  (streamable HTTP)
    mcp_token: str = ""          # bearer token (OAuth is not yet GA for the MCP server)
    rest_url: str = ""           # e.g. https://<host>:8089  (management port, for deploys)
    rest_token: str = ""         # Splunk authentication token for REST deploys
    verify_tls: bool = True
    backtest_index: str = "botsv3"   # historical/labeled attack data index
    audit_index: str = "aegis_audit"  # flight-recorder destination
    app_namespace: str = "aegis_foundry"


@dataclass
class ModelConfig:
    """Which models power which agent capability."""

    # Security reasoning (Coverage Cartographer, evidence narratives)
    security_model: str = "foundation-sec-1.1-8b-instruct"
    # General authoring/synthesis (Detection Author, Tuning Optimizer)
    general_model: str = "gpt-oss-20b"
    # Forecasting (Noise Forecaster)
    forecast_model: str = "CDTSM"
    # OpenAI-compatible endpoint used in live mode when not routing via | ai
    llm_base_url: str = "http://localhost:11434/v1"  # Ollama default
    llm_api_key: str = "ollama"
    temperature: float = 0.1
    max_tokens: int = 1024


@dataclass
class AppConfig:
    mode: str = "mock"  # "mock" | "live"
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    models: ModelConfig = field(default_factory=ModelConfig)
    # Governance
    fp_budget_weekly: float = 25.0
    max_tuning_iterations: int = 3
    auto_approve: bool = False
    shadow_first: bool = True  # new rules deploy in shadow mode unless explicitly approved active
    # Paths
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    runs_dir: Path = field(default_factory=lambda: Path("runs"))
    fixtures_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "demo" / "fixtures"
    )

    @property
    def is_mock(self) -> bool:
        return self.mode == "mock"

    @classmethod
    def from_env(cls) -> "AppConfig":
        cfg = cls()
        cfg.mode = _env("AEGIS_MODE", "mock").lower()
        cfg.fp_budget_weekly = _env_float("AEGIS_FP_BUDGET_WEEKLY", 25.0)
        cfg.max_tuning_iterations = int(_env_float("AEGIS_MAX_TUNING_ITERATIONS", 3))
        cfg.auto_approve = _env("AEGIS_AUTO_APPROVE", "false").lower() in ("1", "true", "yes")
        cfg.shadow_first = _env("AEGIS_SHADOW_FIRST", "true").lower() in ("1", "true", "yes")

        cfg.splunk.mcp_url = _env("SPLUNK_MCP_URL")
        cfg.splunk.mcp_token = _env("SPLUNK_MCP_TOKEN")
        cfg.splunk.rest_url = _env("SPLUNK_REST_URL")
        cfg.splunk.rest_token = _env("SPLUNK_REST_TOKEN")
        cfg.splunk.verify_tls = _env("SPLUNK_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
        cfg.splunk.backtest_index = _env("AEGIS_BACKTEST_INDEX", "botsv3")
        cfg.splunk.audit_index = _env("AEGIS_AUDIT_INDEX", "aegis_audit")

        cfg.models.security_model = _env("AEGIS_SECURITY_MODEL", cfg.models.security_model)
        cfg.models.general_model = _env("AEGIS_GENERAL_MODEL", cfg.models.general_model)
        cfg.models.forecast_model = _env("AEGIS_FORECAST_MODEL", cfg.models.forecast_model)
        cfg.models.llm_base_url = _env("AEGIS_LLM_BASE_URL", cfg.models.llm_base_url)
        cfg.models.llm_api_key = _env("AEGIS_LLM_API_KEY", cfg.models.llm_api_key)
        return cfg
