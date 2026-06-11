"""Typed pipeline state for Aegis Foundry.

This module is the single source of truth for the data contract shared by all
nine agents and the orchestrator. The state is a plain, JSON-serializable
object graph: working memory for a single pipeline run. Episodic memory
(across runs) lives in aegis_foundry.core.memory; the immutable audit trail
lives in aegis_foundry.core.audit and is mirrored into ``PipelineState.audit``
so a run is self-describing.

Conventions:
- Every dataclass has ``to_dict``/``from_dict`` for lossless JSON round-trips.
- Enums serialize as their ``value`` strings.
- Timestamps are ISO-8601 UTC strings (``iso_now()``).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class PipelineStage(str, Enum):
    """Ordered stages of the detection lifecycle pipeline."""

    INTEL = "intel"
    COVERAGE = "coverage"
    AUTHOR = "author"
    BACKTEST = "backtest"
    FORECAST = "forecast"
    TUNE = "tune"
    GOVERN = "govern"
    DEPLOY = "deploy"
    VERIFY = "verify"
    DONE = "done"
    FAILED = "failed"


class RuleStatus(str, Enum):
    DRAFT = "draft"
    SYNTAX_VALID = "syntax_valid"
    BACKTESTED = "backtested"
    TUNED = "tuned"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEPLOYED_SHADOW = "deployed_shadow"
    DEPLOYED_ACTIVE = "deployed_active"
    VERIFIED = "verified"
    RETUNE_REQUIRED = "retune_required"
    ROLLED_BACK = "rolled_back"


class Decision(str, Enum):
    APPROVE_ACTIVE = "approve_active"
    APPROVE_SHADOW = "approve_shadow"
    REJECT = "reject"
    ESCALATE = "escalate"


@dataclass
class ThreatIntel:
    """A unit of inbound intelligence: advisory, closed incident, or red-team finding."""

    intel_id: str
    title: str
    description: str
    source: str  # e.g. "advisory:CISA-AA26-123", "incident:INC-4711", "redteam"
    mitre_techniques: list[str] = field(default_factory=list)  # e.g. ["T1059.001"]
    severity: str = "medium"  # low | medium | high | critical
    indicators: list[str] = field(default_factory=list)
    received_at: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ThreatIntel":
        return cls(**d)


@dataclass
class CoverageGap:
    """A MITRE technique referenced by intel that no existing detection covers (or covers poorly)."""

    gap_id: str
    technique_id: str  # "T1059.001"
    technique_name: str  # "PowerShell"
    tactic: str  # "Execution"
    related_intel_ids: list[str] = field(default_factory=list)
    existing_rule_names: list[str] = field(default_factory=list)  # partial coverage, if any
    risk_score: float = 0.0  # 0..10, set by Coverage Cartographer
    rationale: str = ""  # model-generated explanation, shown in the evidence pack

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CoverageGap":
        return cls(**d)


@dataclass
class DetectionRule:
    """A candidate or deployed Splunk detection (saved/correlation search)."""

    rule_id: str
    name: str
    description: str
    spl: str
    mitre_techniques: list[str] = field(default_factory=list)
    severity: str = "medium"
    status: RuleStatus = RuleStatus.DRAFT
    version: int = 1
    parent_version: Optional[int] = None  # version this was tuned from
    gap_id: Optional[str] = None
    cron_schedule: str = "*/10 * * * *"
    tuning_notes: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DetectionRule":
        d = dict(d)
        d["status"] = RuleStatus(d.get("status", "draft"))
        return cls(**d)


@dataclass
class BacktestResult:
    """Outcome of replaying a rule's SPL over a historical window (via Splunk MCP Server)."""

    rule_id: str
    rule_version: int
    window_days: int
    syntax_valid: bool
    total_hits: int = 0
    true_positives: int = 0  # hits matching labeled attack windows (ground truth)
    false_positives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    labeled_attack_events: int = 0  # ground-truth events in window
    hit_timeline: list[dict[str, Any]] = field(default_factory=list)  # [{"_time": iso, "count": n}]
    sample_hits: list[dict[str, Any]] = field(default_factory=list)  # up to 5 raw sample events
    error: Optional[str] = None
    executed_at: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BacktestResult":
        return cls(**d)


@dataclass
class ForecastResult:
    """CDTSM (or fallback) forecast of a rule's future alert volume."""

    rule_id: str
    rule_version: int
    model: str  # "CDTSM" | "fallback-ewma"
    horizon_days: int
    predicted_weekly_alerts: float
    lower_bound_weekly: float
    upper_bound_weekly: float
    conf_interval: int = 90
    # [{"_time": iso, "predicted": x, "lower90": y, "upper90": z}]
    points: list[dict[str, Any]] = field(default_factory=list)
    within_budget: bool = False
    fp_budget_weekly: float = 0.0
    executed_at: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ForecastResult":
        return cls(**d)


@dataclass
class PolicyCheck:
    name: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyCheck":
        return cls(**d)


@dataclass
class GovernanceDecision:
    """The Governor's verdict on a tuned rule, with the evidence pack that justified it."""

    rule_id: str
    rule_version: int
    decision: Decision
    approver: str  # "policy:auto-shadow" or "human:<name>"
    policy_checks: list[PolicyCheck] = field(default_factory=list)
    evidence_pack_path: Optional[str] = None
    notes: str = ""
    decided_at: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GovernanceDecision":
        d = dict(d)
        d["decision"] = Decision(d["decision"])
        d["policy_checks"] = [PolicyCheck.from_dict(p) for p in d.get("policy_checks", [])]
        return cls(**d)


@dataclass
class DeploymentRecord:
    rule_id: str
    rule_version: int
    saved_search_name: str
    mode: str  # "shadow" | "active"
    rollback_token: str
    deployed_at: str = field(default_factory=iso_now)
    rolled_back: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DeploymentRecord":
        return cls(**d)


@dataclass
class VerificationResult:
    """Post-deploy check: did reality match the forecast?"""

    rule_id: str
    rule_version: int
    observed_weekly_alerts: float
    forecast_weekly_alerts: float
    drift_ratio: float  # observed / forecast (1.0 == perfect)
    within_forecast_band: bool
    action: str  # "ok" | "retune" | "rollback"
    detail: str = ""
    verified_at: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerificationResult":
        return cls(**d)


@dataclass
class AuditEvent:
    """One immutable entry in the agent flight recorder."""

    ts: str
    agent: str
    action: str
    detail: dict[str, Any] = field(default_factory=dict)
    run_id: str = ""
    seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditEvent":
        return cls(**d)


@dataclass
class PipelineState:
    """Working memory for one end-to-end run of the detection lifecycle."""

    run_id: str = field(default_factory=lambda: new_id("run"))
    created_at: str = field(default_factory=iso_now)
    stage: PipelineStage = PipelineStage.INTEL
    # Inputs
    intel: list[ThreatIntel] = field(default_factory=list)
    # Coverage analysis
    existing_rules: list[dict[str, Any]] = field(default_factory=list)  # raw saved-search inventory
    gaps: list[CoverageGap] = field(default_factory=list)
    # Detection lifecycle (rule_id -> latest object; history preserved via versions list)
    rules: dict[str, DetectionRule] = field(default_factory=dict)
    rule_history: dict[str, list[DetectionRule]] = field(default_factory=dict)
    backtests: dict[str, BacktestResult] = field(default_factory=dict)  # keyed rule_id
    forecasts: dict[str, ForecastResult] = field(default_factory=dict)
    decisions: dict[str, GovernanceDecision] = field(default_factory=dict)
    deployments: dict[str, DeploymentRecord] = field(default_factory=dict)
    verifications: dict[str, VerificationResult] = field(default_factory=dict)
    # Run controls
    fp_budget_weekly: float = 25.0  # max acceptable expected alerts/week per rule
    max_tuning_iterations: int = 3
    auto_approve: bool = False  # demo flag: Governor auto-approves instead of prompting
    # Flight recorder mirror + errors
    audit: list[AuditEvent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ---- helpers used by agents ----

    def upsert_rule(self, rule: DetectionRule) -> None:
        self.rule_history.setdefault(rule.rule_id, []).append(rule)
        self.rules[rule.rule_id] = rule

    def add_audit(self, agent: str, action: str, detail: Optional[dict[str, Any]] = None) -> AuditEvent:
        evt = AuditEvent(
            ts=iso_now(),
            agent=agent,
            action=action,
            detail=detail or {},
            run_id=self.run_id,
            seq=len(self.audit) + 1,
        )
        self.audit.append(evt)
        return evt

    def state_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self.to_dict(), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "stage": self.stage.value,
            "intel": [i.to_dict() for i in self.intel],
            "existing_rules": self.existing_rules,
            "gaps": [g.to_dict() for g in self.gaps],
            "rules": {k: v.to_dict() for k, v in self.rules.items()},
            "rule_history": {k: [r.to_dict() for r in v] for k, v in self.rule_history.items()},
            "backtests": {k: v.to_dict() for k, v in self.backtests.items()},
            "forecasts": {k: v.to_dict() for k, v in self.forecasts.items()},
            "decisions": {k: v.to_dict() for k, v in self.decisions.items()},
            "deployments": {k: v.to_dict() for k, v in self.deployments.items()},
            "verifications": {k: v.to_dict() for k, v in self.verifications.items()},
            "fp_budget_weekly": self.fp_budget_weekly,
            "max_tuning_iterations": self.max_tuning_iterations,
            "auto_approve": self.auto_approve,
            "audit": [a.to_dict() for a in self.audit],
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PipelineState":
        st = cls(
            run_id=d["run_id"],
            created_at=d["created_at"],
            stage=PipelineStage(d["stage"]),
            intel=[ThreatIntel.from_dict(x) for x in d.get("intel", [])],
            existing_rules=d.get("existing_rules", []),
            gaps=[CoverageGap.from_dict(x) for x in d.get("gaps", [])],
            fp_budget_weekly=d.get("fp_budget_weekly", 25.0),
            max_tuning_iterations=d.get("max_tuning_iterations", 3),
            auto_approve=d.get("auto_approve", False),
            errors=d.get("errors", []),
        )
        st.rules = {k: DetectionRule.from_dict(v) for k, v in d.get("rules", {}).items()}
        st.rule_history = {
            k: [DetectionRule.from_dict(r) for r in v] for k, v in d.get("rule_history", {}).items()
        }
        st.backtests = {k: BacktestResult.from_dict(v) for k, v in d.get("backtests", {}).items()}
        st.forecasts = {k: ForecastResult.from_dict(v) for k, v in d.get("forecasts", {}).items()}
        st.decisions = {k: GovernanceDecision.from_dict(v) for k, v in d.get("decisions", {}).items()}
        st.deployments = {k: DeploymentRecord.from_dict(v) for k, v in d.get("deployments", {}).items()}
        st.verifications = {
            k: VerificationResult.from_dict(v) for k, v in d.get("verifications", {}).items()
        }
        st.audit = [AuditEvent.from_dict(a) for a in d.get("audit", [])]
        return st

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str) -> "PipelineState":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))
