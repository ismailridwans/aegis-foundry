"""Compliance attestation: ATT&CK -> NIST 800-53 / CIS Controls crosswalk."""

from __future__ import annotations

from aegis_foundry.core.compliance import build_attestations, controls_for_technique
from aegis_foundry.state import (
    CoverageGap,
    DeploymentRecord,
    DetectionRule,
    PipelineState,
    RuleStatus,
)


def test_controls_for_known_technique():
    controls = controls_for_technique("T1059.001")
    frameworks = {c.framework for c in controls}
    assert "NIST 800-53" in frameworks
    assert "CIS Controls v8" in frameworks
    assert any(c.control_id == "SI-4" for c in controls)


def test_controls_fall_back_to_parent_then_baseline():
    # unknown sub-technique falls back to parent T1059
    assert controls_for_technique("T1059.999")
    # entirely unknown technique still attests a monitoring baseline
    baseline = controls_for_technique("T9999")
    assert any(c.control_id == "SI-4" for c in baseline)


def test_build_attestations_for_deployed_rule():
    state = PipelineState()
    state.gaps.append(CoverageGap(
        gap_id="gap-1", technique_id="T1059.001",
        technique_name="PowerShell", tactic="Execution",
    ))
    state.upsert_rule(DetectionRule(
        rule_id="rule-c", name="r", description="d" * 30,
        spl="index=botsv3 process_name=powershell.exe",
        mitre_techniques=["T1059.001"], severity="high",
        status=RuleStatus.DEPLOYED_ACTIVE, version=2,
    ))
    state.deployments["rule-c"] = DeploymentRecord(
        rule_id="rule-c", rule_version=2, saved_search_name="Aegis - r",
        mode="active", rollback_token="savedsearch::Aegis - r",
    )
    attestations = build_attestations(state)
    assert len(attestations) == 1
    att = attestations[0]
    assert att.technique_id == "T1059.001"
    assert att.technique_name == "PowerShell"
    assert att.saved_search_name == "Aegis - r"
    assert any(c.framework == "NIST 800-53" for c in att.controls)


def test_rolled_back_deployments_are_not_attested():
    state = PipelineState()
    state.upsert_rule(DetectionRule(
        rule_id="rule-c", name="r", description="d" * 30, spl="index=botsv3 x=1",
        mitre_techniques=["T1059.001"], severity="high",
        status=RuleStatus.ROLLED_BACK, version=2,
    ))
    state.deployments["rule-c"] = DeploymentRecord(
        rule_id="rule-c", rule_version=2, saved_search_name="Aegis - r",
        mode="active", rollback_token="savedsearch::Aegis - r", rolled_back=True,
    )
    assert build_attestations(state) == []
