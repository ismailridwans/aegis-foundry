"""Agent base class and shared context.

Every Aegis Foundry agent is a small, single-responsibility unit with the
signature ``run(state) -> state``. Agents are pure with respect to their
inputs except for: (a) tool calls through the typed clients in AgentContext,
and (b) audit events, which are appended both to the immutable flight
recorder (core.audit) and mirrored into the state so each run is
self-describing. No agent talks to Splunk or a model except through ctx —
that is what makes the swarm governable and testable.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Optional

from aegis_foundry.config import AppConfig
from aegis_foundry.core.interfaces import (
    ForecastClient,
    LLMClient,
    MCPClient,
    SplunkAdminClient,
)
from aegis_foundry.state import PipelineState


@dataclass
class AgentContext:
    """Dependency container handed to every agent by the orchestrator."""

    config: AppConfig
    llm: LLMClient
    mcp: MCPClient
    admin: SplunkAdminClient
    forecaster: ForecastClient
    audit: Any  # core.audit.AuditLog (Any to avoid import cycle)
    memory: Any  # core.memory.EpisodicMemory


class Agent(abc.ABC):
    """Base class for all nine Aegis Foundry agents."""

    #: Stable agent name used in audit events and dashboards (kebab-case).
    name: str = "agent"

    def __init__(self, ctx: AgentContext) -> None:
        self.ctx = ctx

    @abc.abstractmethod
    def run(self, state: PipelineState) -> PipelineState:
        """Advance the pipeline. Must be idempotent for the same input state."""
        raise NotImplementedError

    # ---- shared helpers ----

    def emit(self, state: PipelineState, action: str,
             detail: Optional[dict[str, Any]] = None) -> None:
        """Record an audit event in both the flight recorder and the state."""
        evt = state.add_audit(self.name, action, detail)
        if self.ctx.audit is not None:
            self.ctx.audit.write(evt)

    def fail(self, state: PipelineState, message: str) -> None:
        """Record a non-fatal error; the orchestrator decides whether to halt."""
        state.errors.append(f"[{self.name}] {message}")
        self.emit(state, "error", {"message": message})
