"""Red-Team agent (agent of the HARDEN stage): adversarial robustness gauntlet.

Backtest recall only measures the past — it proves a rule caught the attacks
that already happened, in the exact form they happened. The Red-Team agent
measures the *future*: it takes the labeled attacks a within-budget rule
catches, mutates each into MITRE-faithful evasion variants (case folding, flag
aliasing, whitespace and argument-order tricks, payload swaps), and replays
every variant against the rule's own SPL predicate. ``adversarial_recall`` is
the fraction the rule still fires on — a direct, evidence-backed measure of how
well the detection resists an adversary who knows it exists.

The evaluation is a pure logic test (does this SPL match this synthetic event?),
so it is deterministic and runs identically against the mock corpus and a live
Splunk deployment. Results land in ``state.robustness`` and feed an
``adversarial-robustness`` policy check in the Governor's evidence pack.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import MCPError, SearchResult
from aegis_foundry.core.spl_match import event_matches, parse_predicate
from aegis_foundry.state import (
    EvasionVariant,
    PipelineState,
    RobustnessResult,
    RuleStatus,
    new_id,
)

#: Encoded-command flag the pinned PowerShell attack uses; the spine of several mutations.
_ENC_FLAG = "-EncodedCommand"

#: How many distinct true-positive seeds to mutate per rule.
_MAX_SEEDS = 3


def _mut_case_fold_cmdline(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    cmd = e.get("CommandLine")
    if not isinstance(cmd, str) or not cmd:
        return None
    out = dict(e)
    out["CommandLine"] = cmd.upper()
    return out


def _mut_case_fold_process(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    proc = e.get("process_name")
    if not isinstance(proc, str) or not proc:
        return None
    out = dict(e)
    out["process_name"] = proc.upper()
    return out


def _mut_whitespace_pad(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    cmd = e.get("CommandLine")
    if not isinstance(cmd, str) or _ENC_FLAG not in cmd:
        return None
    out = dict(e)
    out["CommandLine"] = cmd.replace(_ENC_FLAG, f"  {_ENC_FLAG}   ")
    return out


def _mut_extra_flags(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    cmd = e.get("CommandLine")
    if not isinstance(cmd, str) or _ENC_FLAG not in cmd:
        return None
    out = dict(e)
    out["CommandLine"] = cmd.replace(
        _ENC_FLAG, f"-WindowStyle Hidden -NonInteractive {_ENC_FLAG}"
    )
    return out


def _mut_reorder_args(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    cmd = e.get("CommandLine")
    if not isinstance(cmd, str) or _ENC_FLAG not in cmd:
        return None
    # Pull the encoded payload to the front of the argument list.
    idx = cmd.find(_ENC_FLAG)
    head, tail = cmd[:idx].strip(), cmd[idx:].strip()
    out = dict(e)
    out["CommandLine"] = f"powershell.exe {tail} {head}".strip()
    return out


def _mut_mixed_case_flag(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    cmd = e.get("CommandLine")
    if not isinstance(cmd, str) or _ENC_FLAG not in cmd:
        return None
    out = dict(e)
    out["CommandLine"] = cmd.replace(_ENC_FLAG, "-EnCoDeDcOmMaNd")
    return out


def _mut_payload_swap(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    cmd = e.get("CommandLine")
    if not isinstance(cmd, str) or _ENC_FLAG not in cmd:
        return None
    idx = cmd.find(_ENC_FLAG) + len(_ENC_FLAG)
    out = dict(e)
    out["CommandLine"] = cmd[:idx] + " QQBlAGcAaQBzAEYAbwB1AG4AZAByAHkAUgBlAGQA"
    return out


def _mut_flag_alias_enc(e: dict[str, Any]) -> Optional[dict[str, Any]]:
    cmd = e.get("CommandLine")
    if not isinstance(cmd, str) or _ENC_FLAG not in cmd:
        return None
    # PowerShell accepts -enc as an unambiguous abbreviation of -EncodedCommand;
    # a detection keyed to the long form alone is blind to it.
    out = dict(e)
    out["CommandLine"] = cmd.replace(_ENC_FLAG, "-enc")
    return out


#: Ordered mutation battery: (short label, analyst description, transform).
_MUTATIONS: list[tuple[str, str, Callable[[dict[str, Any]], Optional[dict[str, Any]]]]] = [
    ("case-fold-cmdline", "command line upper-cased", _mut_case_fold_cmdline),
    ("case-fold-process", "process name upper-cased", _mut_case_fold_process),
    ("whitespace-pad", "extra whitespace around the encoded flag", _mut_whitespace_pad),
    ("extra-flags", "noise flags injected before the encoded flag", _mut_extra_flags),
    ("reorder-args", "argument order shuffled", _mut_reorder_args),
    ("mixed-case-flag", "-EnCoDeDcOmMaNd mixed-case flag", _mut_mixed_case_flag),
    ("payload-swap", "different base64 payload", _mut_payload_swap),
    ("flag-alias-enc", "-enc abbreviation instead of -EncodedCommand", _mut_flag_alias_enc),
]


class RedTeam(Agent):
    """Mutate labeled attacks into evasion variants and measure resilience."""

    name = "red-team"

    #: Minimum adversarial recall the Governor requires to pass the gauntlet.
    THRESHOLD: float = 0.75

    def run(self, state: PipelineState) -> PipelineState:
        """Run the gauntlet on every governance-ready, within-budget rule."""
        for rule in list(state.rules.values()):
            if rule.status != RuleStatus.BACKTESTED:
                continue
            forecast = state.forecasts.get(rule.rule_id)
            if forecast is None or not forecast.within_budget:
                continue  # still owned by the measure/tune loop

            seeds = self._seed_events(rule, state)
            predicate = parse_predicate(rule.spl)
            variants: list[EvasionVariant] = []
            for seed in seeds:
                seed_ref = str(seed.get("host") or seed.get("_time") or "seed")
                for label, description, mutate in _MUTATIONS:
                    mutated = mutate(seed)
                    if mutated is None:
                        continue
                    fired = event_matches(predicate, mutated)
                    variants.append(
                        EvasionVariant(
                            variant_id=new_id("var"),
                            technique_id=str(seed.get("technique", "")),
                            mutation=description,
                            fired=fired,
                            base_event_ref=seed_ref,
                        )
                    )

            total = len(variants)
            caught = sum(1 for v in variants if v.fired)
            adversarial_recall = caught / total if total else 1.0
            missed = sorted({v.mutation for v in variants if not v.fired})

            result = RobustnessResult(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                variants_total=total,
                variants_caught=caught,
                adversarial_recall=round(adversarial_recall, 4),
                missed_mutations=missed,
                variants=variants,
                model="mock-redteam" if total else "skipped-no-seeds",
            )
            state.robustness[rule.rule_id] = result

            self.emit(
                state,
                "robustness_evaluated",
                {
                    "rule_id": rule.rule_id,
                    "rule_version": rule.version,
                    "variants_total": total,
                    "variants_caught": caught,
                    "adversarial_recall": round(adversarial_recall, 4),
                    "missed_mutations": missed,
                    "passed": adversarial_recall >= self.THRESHOLD,
                },
            )
        return state

    # ------------------------------------------------------------------

    def _seed_events(self, rule: Any, state: PipelineState) -> list[dict[str, Any]]:
        """The labeled true-positive events this rule catches, to mutate.

        Re-runs the rule's SPL and keeps events that are both labeled malicious
        and mapped to one of the rule's techniques — the same true-positive
        definition the Backtest Engineer uses. Deterministically ordered and
        capped at :data:`_MAX_SEEDS`.
        """
        techniques = set(rule.mitre_techniques)
        try:
            result = self.ctx.mcp.run_search(rule.spl, earliest="-90d", max_results=10000)
        except MCPError as exc:
            result = SearchResult(spl=rule.spl, error=str(exc))
        if result.error:
            self.fail(state, f"red-team seed search failed for {rule.rule_id}: {result.error}")
            return []
        seeds = [
            e
            for e in result.results
            if e.get("label") == "malicious" and e.get("technique") in techniques
        ]
        seeds.sort(key=lambda e: (str(e.get("_time", "")), str(e.get("host", ""))))
        return seeds[:_MAX_SEEDS]
