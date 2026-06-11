"""Shared fixtures: an offline mock-mode config and a built AgentContext."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis_foundry.config import AppConfig
from aegis_foundry.core.factory import build_context

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "demo" / "fixtures"

V1_SPL = (
    'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 '
    'process_name="powershell.exe"'
)
V2_SPL = (
    'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 '
    'process_name="powershell.exe" CommandLine="*-EncodedCommand*" NOT user="svc_deploy"'
)


@pytest.fixture
def mock_config(tmp_path: Path) -> AppConfig:
    cfg = AppConfig()
    cfg.mode = "mock"
    cfg.auto_approve = True
    cfg.fixtures_dir = FIXTURES_DIR
    cfg.runs_dir = tmp_path / "runs"
    return cfg


@pytest.fixture
def ctx(mock_config: AppConfig):
    return build_context(mock_config, "run-testfixture")
