"""Intel Scout — agent 1 of 9: ingests and normalizes threat intelligence.

In live mode this agent is fed by a Splunk modular input (see ``splunk_app/``)
built on the splunk-sdk-python ``ai_modinput_app`` pattern: the modular input
polls advisory feeds (CISA alerts, vendor PSIRTs, closed-incident exports) and
indexes normalized ThreatIntel events that the orchestrator drains into
``PipelineState.intel``. In mock mode the same normalized advisories are read
from ``demo/fixtures/advisories.json`` so the whole pipeline runs offline and
deterministically.

For advisories that arrive without MITRE ATT&CK mappings, the scout asks the
security-reasoning model to extract technique ids from the advisory prose, so
downstream coverage analysis always operates on technique ids — never on free
text.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from aegis_foundry.agents._json_utils import extract_technique_ids, parse_llm_json
from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import LLMError
from aegis_foundry.state import PipelineStage, PipelineState, ThreatIntel, new_id

#: Field names accepted from raw advisory dicts (anything else is dropped so a
#: slightly-richer fixture or feed payload never crashes ingestion).
_INTEL_FIELDS: frozenset[str] = frozenset(f.name for f in dataclasses.fields(ThreatIntel))

_EXTRACTION_SYSTEM = (
    "You are a MITRE ATT&CK analyst. You extract ATT&CK technique ids from "
    "threat intelligence and respond with strict JSON only."
)


class IntelScout(Agent):
    """Ingests advisories into the pipeline and guarantees technique mappings."""

    name = "intel-scout"

    def run(self, state: PipelineState) -> PipelineState:
        """Load advisories, fill in missing ATT&CK mappings, advance to COVERAGE.

        Idempotent: if ``state.intel`` is already populated (e.g. seeded by the
        orchestrator or a resumed run), the scout passes through without
        re-ingesting or duplicating audit events.
        """
        if state.intel:
            if state.stage == PipelineStage.INTEL:
                state.stage = PipelineStage.COVERAGE
            return state

        fixture_path = Path(self.ctx.config.fixtures_dir) / "advisories.json"
        raw_entries = self._load_advisories(state, fixture_path)
        if raw_entries is None:
            return state

        advisories: list[ThreatIntel] = []
        for entry in raw_entries:
            intel = self._normalize(entry)
            if not intel.mitre_techniques:
                intel.mitre_techniques = self._extract_techniques(state, intel)
            advisories.append(intel)
            self.emit(
                state,
                "advisory_received",
                {
                    "intel_id": intel.intel_id,
                    "title": intel.title,
                    "source": intel.source,
                    "severity": intel.severity,
                    "techniques": list(intel.mitre_techniques),
                },
            )

        state.intel = advisories

        technique_union: list[str] = []
        for intel in advisories:
            for tid in intel.mitre_techniques:
                if tid not in technique_union:
                    technique_union.append(tid)
        self.emit(
            state,
            "intel_ingested",
            {
                "advisory_count": len(advisories),
                "technique_count": len(technique_union),
                "techniques": technique_union,
                "source_file": str(fixture_path),
            },
        )

        state.stage = PipelineStage.COVERAGE
        return state

    # ---- internals ----

    def _load_advisories(
        self, state: PipelineState, fixture_path: Path
    ) -> list[dict[str, Any]] | None:
        """Read and decode the advisory fixture; record a non-fatal error on failure."""
        if not fixture_path.is_file():
            self.fail(state, f"advisory fixture not found: {fixture_path}")
            return None
        try:
            payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.fail(state, f"could not read advisory fixture {fixture_path}: {exc}")
            return None
        if isinstance(payload, dict):  # tolerate {"advisories": [...]} wrappers
            payload = payload.get("advisories", [])
        if not isinstance(payload, list):
            self.fail(state, f"advisory fixture {fixture_path} is not a JSON list")
            return None
        return [e for e in payload if isinstance(e, dict)]

    @staticmethod
    def _normalize(entry: dict[str, Any]) -> ThreatIntel:
        """Build a ThreatIntel from a raw advisory dict, tolerating extra keys."""
        payload = {k: v for k, v in entry.items() if k in _INTEL_FIELDS}
        payload.setdefault("intel_id", new_id("intel"))
        payload.setdefault("title", "")
        payload.setdefault("description", "")
        payload.setdefault("source", "advisory:unknown")
        return ThreatIntel.from_dict(payload)

    def _extract_techniques(self, state: PipelineState, intel: ThreatIntel) -> list[str]:
        """Ask the security model to extract ATT&CK technique ids from advisory prose."""
        prompt = (
            "Extract the MITRE ATT&CK technique ids referenced by this threat "
            "advisory.\n\n"
            f"Advisory title: {intel.title}\n"
            f"Advisory description: {intel.description}\n\n"
            "Respond with strict JSON only: a list of objects, each shaped "
            '{"technique_id": "T1234.001", "technique_name": "...", "tactic": "..."}. '
            "Return [] if no techniques are identifiable. No prose, no markdown."
        )
        try:
            response = self.ctx.llm.complete(
                prompt,
                system=_EXTRACTION_SYSTEM,
                model=self.ctx.config.models.security_model,
            )
            return extract_technique_ids(parse_llm_json(response))
        except (LLMError, ValueError) as exc:
            self.fail(
                state,
                f"technique extraction failed for advisory {intel.intel_id}: {exc}",
            )
            return []
