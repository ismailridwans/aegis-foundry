"""ATT&CK -> control-framework crosswalk for Aegis Foundry.

Bridges detection engineering to the language auditors and executives use: each
deployed detection's MITRE technique is mapped to the NIST SP 800-53 and CIS
Controls v8 safeguards it helps satisfy, producing a per-run compliance
attestation. The crosswalk is a small, curated, in-repo table — fully offline
and deterministic — with a sensible monitoring-baseline fallback so every
deployed detection attests to at least one control.
"""

from __future__ import annotations

from aegis_foundry.state import (
    ComplianceAttestation,
    ComplianceControl,
    PipelineState,
)

__all__ = ["build_attestations", "controls_for_technique", "CROSSWALK"]

#: technique_id -> list of (framework, control_id, control_name)
CROSSWALK: dict[str, list[tuple[str, str, str]]] = {
    "T1059.001": [
        ("NIST 800-53", "SI-4", "System Monitoring"),
        ("NIST 800-53", "SI-3", "Malicious Code Protection"),
        ("CIS Controls v8", "8.11", "Conduct Audit Log Reviews"),
        ("CIS Controls v8", "10", "Malware Defenses"),
    ],
    "T1059": [
        ("NIST 800-53", "SI-4", "System Monitoring"),
        ("CIS Controls v8", "8.11", "Conduct Audit Log Reviews"),
    ],
    "T1003.001": [
        ("NIST 800-53", "AC-6", "Least Privilege"),
        ("NIST 800-53", "SI-4", "System Monitoring"),
        ("CIS Controls v8", "6", "Access Control Management"),
    ],
    "T1003": [
        ("NIST 800-53", "AC-6", "Least Privilege"),
        ("CIS Controls v8", "6", "Access Control Management"),
    ],
    "T1110": [
        ("NIST 800-53", "AC-7", "Unsuccessful Logon Attempts"),
        ("NIST 800-53", "IA-5", "Authenticator Management"),
        ("CIS Controls v8", "6", "Access Control Management"),
    ],
    "T1071.001": [
        ("NIST 800-53", "SC-7", "Boundary Protection"),
        ("NIST 800-53", "SI-4", "System Monitoring"),
        ("CIS Controls v8", "13", "Network Monitoring and Defense"),
    ],
    "T1136.001": [
        ("NIST 800-53", "AC-2", "Account Management"),
        ("CIS Controls v8", "5", "Account Management"),
    ],
    "T1078": [
        ("NIST 800-53", "AC-2", "Account Management"),
        ("NIST 800-53", "AC-6", "Least Privilege"),
        ("CIS Controls v8", "6", "Access Control Management"),
    ],
    "T1047": [
        ("NIST 800-53", "SI-4", "System Monitoring"),
        ("CIS Controls v8", "8.11", "Conduct Audit Log Reviews"),
    ],
    "T1053.005": [
        ("NIST 800-53", "CM-7", "Least Functionality"),
        ("NIST 800-53", "SI-4", "System Monitoring"),
        ("CIS Controls v8", "8.11", "Conduct Audit Log Reviews"),
    ],
    "T1566.001": [
        ("NIST 800-53", "SI-8", "Spam Protection"),
        ("CIS Controls v8", "9", "Email and Web Browser Protections"),
    ],
}

#: Applied when a technique has no specific mapping: detection still provides
#: monitoring/logging coverage at minimum.
_FALLBACK: list[tuple[str, str, str]] = [
    ("NIST 800-53", "SI-4", "System Monitoring"),
    ("CIS Controls v8", "8.11", "Conduct Audit Log Reviews"),
]


def controls_for_technique(technique_id: str) -> list[ComplianceControl]:
    """Controls a detection for ``technique_id`` helps satisfy.

    Tries the exact sub-technique, then its parent technique, then the
    monitoring-baseline fallback.
    """
    rows = CROSSWALK.get(technique_id)
    if rows is None:
        parent = technique_id.split(".")[0]
        rows = CROSSWALK.get(parent)
    if rows is None:
        rows = _FALLBACK
    return [ComplianceControl(framework=f, control_id=c, control_name=n) for f, c, n in rows]


def build_attestations(state: PipelineState) -> list[ComplianceAttestation]:
    """One attestation per (deployed, non-rolled-back) detection in the run."""
    names = {g.technique_id: g.technique_name for g in state.gaps}
    attestations: list[ComplianceAttestation] = []
    for rid, dep in state.deployments.items():
        if dep.rolled_back:
            continue
        rule = state.rules.get(rid)
        if rule is None:
            continue
        seen: set[tuple[str, str]] = set()
        controls: list[ComplianceControl] = []
        primary_tid = rule.mitre_techniques[0] if rule.mitre_techniques else ""
        for tid in rule.mitre_techniques:
            for ctrl in controls_for_technique(tid):
                key = (ctrl.framework, ctrl.control_id)
                if key not in seen:
                    seen.add(key)
                    controls.append(ctrl)
        attestations.append(
            ComplianceAttestation(
                technique_id=primary_tid,
                technique_name=names.get(primary_tid, ""),
                rule_id=rid,
                saved_search_name=dep.saved_search_name,
                controls=controls,
            )
        )
    return attestations
