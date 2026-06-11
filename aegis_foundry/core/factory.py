"""Builds the AgentContext for a given mode.

This file pins the construction contract between the orchestrator and the
client implementations. In mock mode everything is deterministic and offline;
in live mode the same agents drive a real Splunk deployment through the MCP
Server, the management REST API, and CDTSM/Foundation-Sec/gpt-oss.
"""

from __future__ import annotations

from pathlib import Path

from aegis_foundry.agents.base import AgentContext
from aegis_foundry.config import AppConfig
from aegis_foundry.core.audit import AuditLog
from aegis_foundry.core.hosted_models import CDTSMForecastClient, FallbackForecaster
from aegis_foundry.core.llm import MockLLM, OpenAICompatibleLLM
from aegis_foundry.core.mcp_client import (
    MockMCPClient,
    MockSplunkAdmin,
    SplunkMCPClient,
    SplunkRESTAdmin,
)
from aegis_foundry.core.memory import EpisodicMemory


def build_context(cfg: AppConfig, run_id: str) -> AgentContext:
    run_dir = Path(cfg.runs_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    audit = AuditLog(run_dir / "flight_recorder.jsonl")
    memory = EpisodicMemory(Path(cfg.runs_dir) / "episodic_memory.json")

    if cfg.is_mock:
        mcp = MockMCPClient(cfg.fixtures_dir)
        admin = MockSplunkAdmin(run_dir / "deployed_savedsearches.conf")
        llm = MockLLM()
        forecaster = FallbackForecaster()
    else:
        mcp = SplunkMCPClient(
            cfg.splunk.mcp_url,
            cfg.splunk.mcp_token,
            verify_tls=cfg.splunk.verify_tls,
        )
        admin = SplunkRESTAdmin(
            cfg.splunk.rest_url,
            cfg.splunk.rest_token,
            verify_tls=cfg.splunk.verify_tls,
            app=cfg.splunk.app_namespace,
        )
        llm = OpenAICompatibleLLM(
            base_url=cfg.models.llm_base_url,
            api_key=cfg.models.llm_api_key,
            default_model=cfg.models.general_model,
            temperature=cfg.models.temperature,
        )
        # CDTSM runs through the search plane; it degrades to the labeled
        # fallback forecaster automatically if `| apply CDTSM` is unavailable.
        forecaster = CDTSMForecastClient(mcp, fallback=FallbackForecaster())

    return AgentContext(
        config=cfg,
        llm=llm,
        mcp=mcp,
        admin=admin,
        forecaster=forecaster,
        audit=audit,
        memory=memory,
    )
