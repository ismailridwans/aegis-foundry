"""The first three agents, advancing a fresh state stage by stage."""

from __future__ import annotations

from aegis_foundry.agents.coverage_cartographer import CoverageCartographer
from aegis_foundry.agents.detection_author import DetectionAuthor
from aegis_foundry.agents.intel_scout import IntelScout
from aegis_foundry.state import PipelineStage, PipelineState, RuleStatus
from tests.conftest import V1_SPL


def test_intel_coverage_author_golden_path(ctx):
    state = PipelineState()
    state.auto_approve = True

    state = IntelScout(ctx).run(state)
    assert len(state.intel) == 1
    assert state.intel[0].source == "advisory:CISA-AA26-117A"
    assert set(state.intel[0].mitre_techniques) == {"T1059.001", "T1003.001"}
    assert state.stage is PipelineStage.COVERAGE

    state = CoverageCartographer(ctx).run(state)
    gap_techniques = {g.technique_id for g in state.gaps}
    assert gap_techniques == {"T1059.001"}, "T1003.001 is covered; only T1059.001 is a gap"
    assert state.gaps[0].tactic == "Execution"
    assert len(state.existing_rules) == 4
    assert state.stage is PipelineStage.AUTHOR

    state = DetectionAuthor(ctx).run(state)
    assert len(state.rules) == 1
    rule = next(iter(state.rules.values()))
    assert rule.spl == V1_SPL
    assert rule.status is RuleStatus.SYNTAX_VALID
    assert rule.mitre_techniques == ["T1059.001"]
    assert rule.version == 1
    assert state.stage is PipelineStage.BACKTEST


def test_intel_scout_is_idempotent(ctx):
    state = PipelineState()
    state = IntelScout(ctx).run(state)
    count = len(state.intel)
    state = IntelScout(ctx).run(state)
    assert len(state.intel) == count
