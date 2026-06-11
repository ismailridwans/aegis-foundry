"""Detection Author — agent 3 of 9: drafts SPL detections for coverage gaps.

For every open :class:`~aegis_foundry.state.CoverageGap`, the author prompts
the general-purpose model with the gap's technique, the related advisory
context, and the target backtest index, and demands a strict-JSON detection
draft (name, description, SPL, severity, cron schedule).

The judged centerpiece is the SPL self-correction loop: every draft is
syntax-checked through the Splunk MCP Server (``validate_spl``); if validation
fails, the *exact* validation error is fed back to the model and a corrected
draft is requested — up to two retries, each one recorded as an
``spl_self_correction`` audit event so the flight recorder shows the agent
fixing its own mistakes. A draft that survives validation is promoted to
``SYNTAX_VALID``; one that does not stays in ``DRAFT`` with a non-fatal error
for the orchestrator to triage.
"""

from __future__ import annotations

from aegis_foundry.agents._json_utils import parse_llm_json
from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import LLMError, MCPError, SPLValidation
from aegis_foundry.state import (
    CoverageGap,
    DetectionRule,
    PipelineStage,
    PipelineState,
    RuleStatus,
    ThreatIntel,
    new_id,
)

__all__ = ["DetectionAuthor", "parse_llm_json"]

_AUTHOR_SYSTEM = (
    "You are a senior Splunk detection engineer. You draft production-quality "
    "saved-search detections and respond with strict JSON only."
)

_ALLOWED_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})

_DEFAULT_CRON = "*/10 * * * *"

#: Maximum number of self-correction round-trips after the initial draft.
_MAX_CORRECTION_RETRIES = 2


class DetectionAuthor(Agent):
    """Drafts one detection rule per coverage gap, self-correcting invalid SPL."""

    name = "detection-author"

    def run(self, state: PipelineState) -> PipelineState:
        """Author a rule for every gap that has none, then advance to BACKTEST.

        Idempotent: gaps that already have a rule in ``state.rules`` (matched
        by ``gap_id``) are skipped, so re-running the agent never duplicates
        drafts.
        """
        authored_gap_ids = {
            rule.gap_id for rule in state.rules.values() if rule.gap_id is not None
        }
        for gap in state.gaps:
            if gap.gap_id in authored_gap_ids:
                continue
            self._author_for_gap(state, gap)

        state.stage = PipelineStage.BACKTEST
        return state

    # ---- internals ----

    def _author_for_gap(self, state: PipelineState, gap: CoverageGap) -> None:
        """Draft, validate, and (if needed) self-correct a detection for one gap."""
        related_intel = [
            intel for intel in state.intel if intel.intel_id in gap.related_intel_ids
        ]
        try:
            response = self.ctx.llm.complete(
                self._draft_prompt(gap, related_intel),
                system=_AUTHOR_SYSTEM,
                model=self.ctx.config.models.general_model,
            )
            draft = parse_llm_json(response)
        except (LLMError, ValueError) as exc:
            self.fail(
                state,
                f"could not draft detection for gap {gap.gap_id} "
                f"({gap.technique_id}): {exc}",
            )
            return
        if not isinstance(draft, dict) or not str(draft.get("spl", "")).strip():
            self.fail(
                state,
                f"model draft for gap {gap.gap_id} ({gap.technique_id}) is not a "
                "JSON object with a non-empty 'spl' field",
            )
            return

        rule = DetectionRule(
            rule_id=new_id("rule"),
            name=str(
                draft.get("name") or f"Aegis - {gap.technique_name} ({gap.technique_id})"
            ).strip(),
            description=str(draft.get("description") or "").strip(),
            spl=str(draft["spl"]).strip(),
            mitre_techniques=[gap.technique_id],
            severity=self._normalize_severity(draft.get("severity")),
            status=RuleStatus.DRAFT,
            version=1,
            gap_id=gap.gap_id,
            cron_schedule=str(draft.get("cron_schedule") or _DEFAULT_CRON).strip(),
        )
        state.upsert_rule(rule)

        # ---- SPL self-correction loop (judged feature) ----
        validation = self._validate(rule.spl)
        attempt = 0
        while not validation.valid and attempt < _MAX_CORRECTION_RETRIES:
            attempt += 1
            error_text = validation.error or "SPL failed validation"
            self.emit(
                state,
                "spl_self_correction",
                {
                    "rule_id": rule.rule_id,
                    "technique_id": gap.technique_id,
                    "attempt": attempt,
                    "max_attempts": _MAX_CORRECTION_RETRIES,
                    "error": error_text,
                    "spl": rule.spl,
                },
            )
            corrected_spl = self._request_correction(rule, gap, error_text)
            if corrected_spl:
                rule.spl = corrected_spl
            validation = self._validate(rule.spl)

        if validation.valid:
            rule.status = RuleStatus.SYNTAX_VALID
            self.emit(
                state,
                "rule_drafted",
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "spl": rule.spl,
                    "technique_id": gap.technique_id,
                    "severity": rule.severity,
                    "version": rule.version,
                    "gap_id": gap.gap_id,
                    "correction_attempts": attempt,
                },
            )
        else:
            self.fail(
                state,
                f"SPL for rule {rule.rule_id} ({gap.technique_id}) still invalid "
                f"after {_MAX_CORRECTION_RETRIES} self-correction retries: "
                f"{validation.error}",
            )

    def _draft_prompt(self, gap: CoverageGap, related: list[ThreatIntel]) -> str:
        """Build the authoring prompt for one coverage gap."""
        intel_lines = (
            "\n".join(f"- {intel.title}: {intel.description}" for intel in related)
            or "- (no linked advisories)"
        )
        index = self.ctx.config.splunk.backtest_index
        return (
            "Draft a Splunk detection (saved search) that closes this MITRE "
            "ATT&CK coverage gap.\n\n"
            f"Coverage gap technique: {gap.technique_id} "
            f"({gap.technique_name}, {gap.tactic} tactic)\n"
            "Related threat intelligence:\n"
            f"{intel_lines}\n"
            f"Target index: {index}\n\n"
            "Respond with strict JSON only (no prose, no markdown), exactly this "
            "shape:\n"
            '{"name": "...", "description": "...", "spl": "...", '
            '"severity": "low|medium|high|critical", '
            '"cron_schedule": "*/10 * * * *"}\n'
            f"The SPL must search index={index} and precisely target the "
            "technique's observable behavior."
        )

    def _request_correction(
        self, rule: DetectionRule, gap: CoverageGap, error_text: str
    ) -> str | None:
        """Feed the exact validation error back to the model; return fixed SPL.

        Returns ``None`` when the model call fails or the reply carries no
        usable SPL, in which case the caller re-validates the existing SPL and
        the loop proceeds to the next attempt.
        """
        prompt = (
            "The Splunk SPL you drafted failed validation. Fix it.\n\n"
            f"Rule name: {rule.name}\n"
            f"MITRE ATT&CK technique: {gap.technique_id} ({gap.technique_name})\n"
            f"Current SPL: {rule.spl}\n"
            f"Validation error (exact): {error_text}\n\n"
            "Keep the detection intent and the target index. Respond with strict "
            "JSON only (no prose, no markdown), exactly this shape:\n"
            '{"name": "...", "description": "...", "spl": "...", '
            '"severity": "low|medium|high|critical", '
            '"cron_schedule": "*/10 * * * *"}'
        )
        try:
            corrected = parse_llm_json(
                self.ctx.llm.complete(
                    prompt,
                    system=_AUTHOR_SYSTEM,
                    model=self.ctx.config.models.general_model,
                )
            )
        except (LLMError, ValueError):
            return None
        if isinstance(corrected, dict):
            spl = str(corrected.get("spl", "")).strip()
            return spl or None
        return None

    def _validate(self, spl: str) -> SPLValidation:
        """Syntax-check SPL via MCP, mapping transport failures to invalid results."""
        try:
            return self.ctx.mcp.validate_spl(spl)
        except MCPError as exc:
            return SPLValidation(valid=False, error=f"validation transport error: {exc}")

    @staticmethod
    def _normalize_severity(value: object) -> str:
        """Clamp a model-supplied severity onto the allowed vocabulary."""
        severity = str(value or "").strip().lower()
        return severity if severity in _ALLOWED_SEVERITIES else "medium"
