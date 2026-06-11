"""PipelineState serialization round-trips and version-history semantics."""

from __future__ import annotations

from aegis_foundry.state import (
    BacktestResult,
    Decision,
    DeploymentRecord,
    DetectionRule,
    ForecastResult,
    GovernanceDecision,
    PipelineStage,
    PipelineState,
    PolicyCheck,
    RuleStatus,
    ThreatIntel,
    VerificationResult,
)


def _populated_state() -> PipelineState:
    st = PipelineState()
    st.stage = PipelineStage.GOVERN
    st.intel.append(
        ThreatIntel(
            intel_id="intel-1",
            title="t",
            description="d",
            source="advisory:X",
            mitre_techniques=["T1059.001"],
            severity="critical",
        )
    )
    rule = DetectionRule(
        rule_id="rule-1",
        name="r",
        description="desc longer than twenty chars",
        spl="index=botsv3 EventCode=4688",
        mitre_techniques=["T1059.001"],
        status=RuleStatus.BACKTESTED,
    )
    st.upsert_rule(rule)
    st.backtests["rule-1"] = BacktestResult(
        rule_id="rule-1", rule_version=1, window_days=90, syntax_valid=True,
        total_hits=42, true_positives=17, false_positives=25,
        precision=0.405, recall=1.0, labeled_attack_events=17,
    )
    st.forecasts["rule-1"] = ForecastResult(
        rule_id="rule-1", rule_version=1, model="fallback-ewma", horizon_days=14,
        predicted_weekly_alerts=2.7, lower_bound_weekly=0.0, upper_bound_weekly=9.1,
        within_budget=True, fp_budget_weekly=25.0,
    )
    st.decisions["rule-1"] = GovernanceDecision(
        rule_id="rule-1", rule_version=1, decision=Decision.APPROVE_ACTIVE,
        approver="human:operator",
        policy_checks=[PolicyCheck(name="syntax-valid", passed=True, detail="ok")],
    )
    st.deployments["rule-1"] = DeploymentRecord(
        rule_id="rule-1", rule_version=1, saved_search_name="Aegis - r",
        mode="active", rollback_token="savedsearch::Aegis - r",
    )
    st.verifications["rule-1"] = VerificationResult(
        rule_id="rule-1", rule_version=1, observed_weekly_alerts=3.0,
        forecast_weekly_alerts=2.7, drift_ratio=1.11,
        within_forecast_band=True, action="ok",
    )
    st.add_audit("test-agent", "test_action", {"k": "v"})
    return st


def test_round_trip_preserves_everything():
    st = _populated_state()
    clone = PipelineState.from_dict(st.to_dict())
    assert clone.to_dict() == st.to_dict()
    assert clone.stage is PipelineStage.GOVERN
    assert clone.rules["rule-1"].status is RuleStatus.BACKTESTED
    assert clone.decisions["rule-1"].decision is Decision.APPROVE_ACTIVE
    assert clone.decisions["rule-1"].policy_checks[0].passed is True
    assert clone.audit[0].agent == "test-agent"


def test_save_load(tmp_path):
    st = _populated_state()
    path = tmp_path / "state.json"
    st.save(str(path))
    loaded = PipelineState.load(str(path))
    assert loaded.to_dict() == st.to_dict()


def test_upsert_rule_keeps_history():
    st = PipelineState()
    r1 = DetectionRule(rule_id="rule-1", name="r", description="d" * 30, spl="a=1")
    st.upsert_rule(r1)
    r2 = DetectionRule(
        rule_id="rule-1", name="r", description="d" * 30, spl="a=1 b=2",
        version=2, parent_version=1,
    )
    st.upsert_rule(r2)
    assert st.rules["rule-1"].version == 2
    assert [r.version for r in st.rule_history["rule-1"]] == [1, 2]


def test_audit_sequence_increments():
    st = PipelineState()
    e1 = st.add_audit("a", "x")
    e2 = st.add_audit("b", "y")
    assert (e1.seq, e2.seq) == (1, 2)
    assert e2.run_id == st.run_id
