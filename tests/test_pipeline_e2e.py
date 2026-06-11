"""Full end-to-end run of the nine-agent pipeline in offline mock mode.

This is the executable version of the demo storyline: a coverage gap is
found, a draft detection fires hundreds of times a week, the measurement
loop tunes it under the false-positive budget without losing a single
labeled true positive, governance approves, the rule deploys, and the
post-deploy verification lands inside the forecast band.
"""

from __future__ import annotations

import builtins

import pytest

from aegis_foundry.orchestrator import run_pipeline
from aegis_foundry.state import Decision, PipelineStage, RuleStatus


@pytest.fixture
def final_state(mock_config, monkeypatch):
    def _no_input(*args, **kwargs):  # pragma: no cover - only fires on regression
        raise AssertionError("input() must never be called when auto_approve is set")

    monkeypatch.setattr(builtins, "input", _no_input)
    return run_pipeline(mock_config)


def test_pipeline_reaches_done_without_errors(final_state):
    assert final_state.stage is PipelineStage.DONE
    assert final_state.errors == []


def test_exactly_one_rule_tuned_to_version_two(final_state):
    assert len(final_state.rules) == 1
    rule = next(iter(final_state.rules.values()))
    assert rule.version == 2
    assert rule.parent_version == 1
    assert rule.tuning_notes, "tuning rationale must be recorded"
    versions = {r.version for r in final_state.rule_history[rule.rule_id]}
    assert versions == {1, 2}


def test_storyline_numbers(final_state):
    rule_id = next(iter(final_state.rules))
    backtest = final_state.backtests[rule_id]
    forecast = final_state.forecasts[rule_id]
    assert backtest.rule_version == 2
    assert backtest.recall == 1.0
    assert backtest.true_positives == 17
    assert forecast.predicted_weekly_alerts <= 25.0
    assert forecast.within_budget is True
    assert forecast.model in ("CDTSM", "fallback-ewma")


def test_governance_deploy_verify_chain(final_state, mock_config):
    rule_id = next(iter(final_state.rules))
    decision = final_state.decisions[rule_id]
    assert decision.decision is Decision.APPROVE_ACTIVE
    assert len(decision.policy_checks) == 7
    assert all(c.passed for c in decision.policy_checks)
    assert decision.evidence_pack_path

    evidence = open(decision.evidence_pack_path, encoding="utf-8").read()
    assert "Recall" in evidence
    assert final_state.rules[rule_id].spl in evidence

    deployment = final_state.deployments[rule_id]
    assert deployment.mode == "active"
    conf = (mock_config.runs_dir / final_state.run_id / "deployed_savedsearches.conf").read_text(
        encoding="utf-8"
    )
    assert deployment.saved_search_name in conf

    verification = final_state.verifications[rule_id]
    assert verification.action == "ok"
    assert verification.within_forecast_band is True

    assert final_state.rules[rule_id].status is RuleStatus.VERIFIED


def test_flight_recorder_is_complete(final_state, mock_config):
    actions = {a.action for a in final_state.audit}
    for required in (
        "intel_ingested",
        "gap_identified",
        "rule_drafted",
        "backtest_completed",
        "noise_forecast",
        "rule_tuned",
        "governance_decision",
        "rule_deployed",
        "verification",
    ):
        assert required in actions, f"missing audit action {required}"
    assert len(final_state.audit) >= 14

    run_dir = mock_config.runs_dir / final_state.run_id
    assert (run_dir / "state.json").exists()
    assert (run_dir / "flight_recorder.jsonl").exists()
