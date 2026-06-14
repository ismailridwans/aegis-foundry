"""Red-Team gauntlet: SPL predicate matching and adversarial-recall scoring."""

from __future__ import annotations

from aegis_foundry.agents.red_team import RedTeam
from aegis_foundry.core.spl_match import event_matches, parse_predicate
from aegis_foundry.state import (
    DetectionRule,
    ForecastResult,
    PipelineState,
    RuleStatus,
)
from tests.conftest import V2_SPL

_MAL_SEED = {
    "_time": "2026-03-19T03:44:05+00:00",
    "host": "SRV-FILE-03",
    "user": "jsmith",
    "process_name": "powershell.exe",
    "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
    "EventCode": "4688",
    "sourcetype": "WinEventLog:Security",
    "index": "botsv3",
    "label": "malicious",
    "technique": "T1059.001",
}


def test_spl_match_mirrors_dialect():
    pred = parse_predicate(V2_SPL)
    assert pred.error is None
    assert event_matches(pred, _MAL_SEED)  # the real attack fires
    # case folding still fires (matcher is case-insensitive)...
    folded = dict(_MAL_SEED, CommandLine=_MAL_SEED["CommandLine"].upper())
    assert event_matches(pred, folded)
    # ...but the -enc abbreviation evades a literal -EncodedCommand rule.
    aliased = dict(_MAL_SEED, CommandLine="powershell.exe -NoProfile -enc SQBFAFgA")
    assert not event_matches(pred, aliased)
    # the svc_deploy exclusion still suppresses benign automation.
    benign = dict(_MAL_SEED, user="svc_deploy")
    assert not event_matches(pred, benign)


def _ready_state() -> PipelineState:
    state = PipelineState()
    rule = DetectionRule(
        rule_id="rule-rt",
        name="Suspicious Encoded PowerShell Execution",
        description="x" * 40,
        spl=V2_SPL,
        mitre_techniques=["T1059.001"],
        severity="high",
        status=RuleStatus.BACKTESTED,
        version=2,
    )
    state.upsert_rule(rule)
    state.forecasts["rule-rt"] = ForecastResult(
        rule_id="rule-rt",
        rule_version=2,
        model="fallback-ewma",
        horizon_days=14,
        predicted_weekly_alerts=2.7,
        lower_bound_weekly=0.5,
        upper_bound_weekly=9.0,
        within_budget=True,
        fp_budget_weekly=25.0,
    )
    return state


def test_gauntlet_scores_v2_rule(ctx):
    state = _ready_state()
    state = RedTeam(ctx).run(state)
    result = state.robustness["rule-rt"]
    # 3 seeds x 8 mutations = 24 variants; only the -enc alias evades, once per seed.
    assert result.variants_total == 24
    assert result.variants_caught == 21
    assert result.adversarial_recall == 0.875
    assert result.missed_mutations == ["-enc abbreviation instead of -EncodedCommand"]
    assert result.adversarial_recall >= RedTeam.THRESHOLD
    # a robustness audit event was emitted
    assert any(e.action == "robustness_evaluated" for e in state.audit)
