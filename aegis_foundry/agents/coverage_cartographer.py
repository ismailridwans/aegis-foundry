"""Coverage Cartographer — agent 2 of 9: maps intel to detection coverage.

Pulls the live saved-search inventory through the Splunk MCP Server, works out
which MITRE ATT&CK techniques each existing detection covers (from rule
metadata when present, otherwise by asking the security-reasoning model to
read the SPL), and diffs that coverage against the techniques referenced by
inbound intelligence. Every uncovered technique becomes a scored
:class:`~aegis_foundry.state.CoverageGap` with an analyst-grade rationale, and
a full coverage-matrix snapshot is written to the audit trail so dashboards
can replay the before/after picture.
"""

from __future__ import annotations

from typing import Any

from aegis_foundry.agents._json_utils import (
    extract_technique_ids,
    parse_llm_json,
    technique_info,
)
from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import LLMError, MCPError
from aegis_foundry.state import CoverageGap, PipelineStage, PipelineState, new_id

_MAPPING_SYSTEM = (
    "You are a senior detection engineer. You map Splunk saved searches to the "
    "MITRE ATT&CK techniques they detect and respond with strict JSON only."
)

_RATIONALE_SYSTEM = (
    "You are a SOC analyst writing concise risk rationales for a "
    "detection-engineering evidence pack. Respond with plain prose only."
)

#: Severities that mark a related advisory as elevating gap risk.
_HIGH_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})


class CoverageCartographer(Agent):
    """Diffs ATT&CK techniques in intel against existing saved-search coverage."""

    name = "coverage-cartographer"

    def run(self, state: PipelineState) -> PipelineState:
        """Inventory existing rules, identify coverage gaps, advance to AUTHOR.

        Idempotent: if gaps were already identified for this run, the agent
        passes through without re-querying Splunk or duplicating audit events.
        """
        if state.gaps:
            if state.stage == PipelineStage.COVERAGE:
                state.stage = PipelineStage.AUTHOR
            return state

        try:
            inventory = self.ctx.mcp.list_saved_searches()
        except MCPError as exc:
            self.fail(state, f"could not list saved searches via MCP: {exc}")
            return state
        state.existing_rules = inventory

        # technique_id -> names of rules that cover it
        covered: dict[str, list[str]] = {}
        for rule in inventory:
            if not isinstance(rule, dict):
                continue
            rule_name = str(rule.get("name", "")).strip()
            techniques = extract_technique_ids(rule.get("mitre_techniques") or [])
            if not techniques:
                techniques = self._map_rule_to_techniques(
                    rule_name, str(rule.get("search") or rule.get("spl") or "")
                )
            for tid in techniques:
                names = covered.setdefault(tid, [])
                if rule_name and rule_name not in names:
                    names.append(rule_name)

        intel_techniques: list[str] = []
        for intel in state.intel:
            for tid in intel.mitre_techniques:
                if tid not in intel_techniques:
                    intel_techniques.append(tid)

        gap_techniques = [tid for tid in intel_techniques if tid not in covered]
        matrix = {
            tid: ("covered" if tid in covered else "gap") for tid in intel_techniques
        }
        self.emit(
            state,
            "coverage_mapped",
            {
                "existing_rule_count": len(inventory),
                "covered_techniques": sorted(covered),
                "gap_techniques": gap_techniques,
                "matrix": matrix,
            },
        )

        for tid in gap_techniques:
            gap = self._build_gap(state, tid, covered)
            state.gaps.append(gap)
            self.emit(
                state,
                "gap_identified",
                {
                    "gap_id": gap.gap_id,
                    "technique_id": gap.technique_id,
                    "technique_name": gap.technique_name,
                    "tactic": gap.tactic,
                    "risk_score": gap.risk_score,
                    "related_intel_ids": list(gap.related_intel_ids),
                    "existing_rule_names": list(gap.existing_rule_names),
                    "rationale": gap.rationale,
                },
            )

        state.stage = PipelineStage.AUTHOR
        return state

    # ---- internals ----

    def _map_rule_to_techniques(self, rule_name: str, spl: str) -> list[str]:
        """Ask the security model which ATT&CK techniques a saved search detects.

        Tolerates an empty list (an honest "cannot determine") and treats any
        model or parsing failure as no coverage, which only errs toward
        flagging extra gaps — the safe direction.
        """
        prompt = (
            "Map this Splunk saved search to the MITRE ATT&CK techniques it "
            "detects.\n\n"
            f"Saved search name: {rule_name}\n"
            f"SPL: {spl}\n\n"
            "Respond with strict JSON only: a list of technique id strings, "
            'e.g. ["T1003.001"]. Return [] if no technique can be determined. '
            "No prose, no markdown."
        )
        try:
            response = self.ctx.llm.complete(
                prompt,
                system=_MAPPING_SYSTEM,
                model=self.ctx.config.models.security_model,
            )
            return extract_technique_ids(parse_llm_json(response))
        except (LLMError, ValueError):
            return []

    def _build_gap(
        self, state: PipelineState, technique_id: str, covered: dict[str, list[str]]
    ) -> CoverageGap:
        """Assemble a scored, explained CoverageGap for an uncovered technique."""
        technique_name, tactic = technique_info(technique_id)
        related = [
            intel for intel in state.intel if technique_id in intel.mitre_techniques
        ]
        related_ids = [intel.intel_id for intel in related]
        risk_score = (
            8.5
            if any(intel.severity.lower() in _HIGH_SEVERITIES for intel in related)
            else 6.0
        )
        partial = self._partial_matches(technique_id, covered)
        rationale = self._rationale(technique_id, technique_name, tactic, related, partial)
        return CoverageGap(
            gap_id=new_id("gap"),
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            related_intel_ids=related_ids,
            existing_rule_names=partial,
            risk_score=risk_score,
            rationale=rationale,
        )

    @staticmethod
    def _partial_matches(technique_id: str, covered: dict[str, list[str]]) -> list[str]:
        """Names of rules that cover the parent technique or a sibling sub-technique.

        For a gap on ``T1059.001``, a rule covering ``T1059`` or ``T1059.003``
        counts as partial coverage worth surfacing to the Detection Author.
        """
        parent = technique_id.split(".")[0]
        names: list[str] = []
        for covered_tid, rule_names in covered.items():
            if covered_tid == technique_id:
                continue
            if covered_tid == parent or covered_tid.split(".")[0] == parent:
                for name in rule_names:
                    if name and name not in names:
                        names.append(name)
        return names

    def _rationale(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        related: list[Any],
        partial: list[str],
    ) -> str:
        """Analyst prose explaining why this gap matters; deterministic fallback."""
        intel_summary = (
            "; ".join(f"{intel.title}: {intel.description}" for intel in related)
            or "no linked advisories"
        )
        prompt = (
            "Write the analyst rationale for a detection coverage gap, in two to "
            "three sentences of plain prose (no JSON, no markdown).\n\n"
            f"Uncovered MITRE ATT&CK technique: {technique_id} "
            f"({technique_name}, {tactic} tactic)\n"
            f"Related threat intelligence: {intel_summary}\n"
            f"Partial coverage from existing rules: {', '.join(partial) or 'none'}\n\n"
            "Explain why the missing detection is a risk and what an attacker "
            "could do undetected."
        )
        try:
            rationale = self.ctx.llm.complete(
                prompt,
                system=_RATIONALE_SYSTEM,
                model=self.ctx.config.models.security_model,
            ).strip()
            if rationale:
                return rationale
        except LLMError:
            pass
        related_ids = ", ".join(intel.intel_id for intel in related) or "active intel"
        return (
            f"Technique {technique_id} ({technique_name}) is referenced by "
            f"{related_ids} but no existing saved search covers it, leaving the "
            f"{tactic} tactic unmonitored against an active campaign."
        )
