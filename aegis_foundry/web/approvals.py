"""Approval broker: bridges the pipeline thread and the web console.

When the Aegis Foundry web console is running, the Governor does not prompt
on stdin. Instead it submits an :class:`ApprovalRequest` to the process-wide
broker and blocks until a human resolves it from the browser (or the request
times out, in which case the Governor falls back to its safe default, shadow
deployment). The broker is intentionally tiny and stdlib-only: a lock, a
dict of pending requests, and one ``threading.Event`` per request.

Contract (used by the web server and the frontend):

- ``submit(request, timeout)`` is called by the **Governor** (pipeline thread).
  Returns a :class:`~aegis_foundry.state.Decision` or ``None`` on timeout.
- ``pending()`` is polled by the **web server** (GET /api/pending).
- ``resolve(request_id, decision)`` is called by the **web server**
  (POST /api/approve) with decision strings ``"active" | "shadow" | "reject"``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from aegis_foundry.state import Decision, iso_now, new_id

_DECISION_MAP = {
    "active": Decision.APPROVE_ACTIVE,
    "shadow": Decision.APPROVE_SHADOW,
    "reject": Decision.REJECT,
}


@dataclass
class ApprovalRequest:
    """Everything the browser needs to render an approval card."""

    run_id: str
    rule_id: str
    rule_name: str
    rule_version: int
    technique: str
    weekly_backtest: float
    weekly_forecast: float
    fp_budget_weekly: float
    recall: float
    evidence_pack_path: Optional[str] = None
    request_id: str = field(default_factory=lambda: new_id("appr"))
    created_at: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "run_id": self.run_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_version": self.rule_version,
            "technique": self.technique,
            "weekly_backtest": self.weekly_backtest,
            "weekly_forecast": self.weekly_forecast,
            "fp_budget_weekly": self.fp_budget_weekly,
            "recall": self.recall,
            "evidence_pack_path": self.evidence_pack_path,
            "created_at": self.created_at,
        }


class ApprovalBroker:
    """Thread-safe pending-approval registry with blocking submit."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, ApprovalRequest] = {}
        self._events: dict[str, threading.Event] = {}
        self._decisions: dict[str, Decision] = {}

    def submit(self, request: ApprovalRequest, timeout: float = 600.0) -> Optional[Decision]:
        """Block the calling (pipeline) thread until a human decides.

        Returns ``None`` on timeout so the Governor can apply its safe default.
        """
        event = threading.Event()
        with self._lock:
            self._pending[request.request_id] = request
            self._events[request.request_id] = event
        try:
            if not event.wait(timeout):
                return None
            with self._lock:
                return self._decisions.pop(request.request_id, None)
        finally:
            with self._lock:
                self._pending.pop(request.request_id, None)
                self._events.pop(request.request_id, None)

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            return list(self._pending.values())

    def resolve(self, request_id: str, decision: str) -> bool:
        """Resolve a pending request. ``decision``: active | shadow | reject."""
        mapped = _DECISION_MAP.get(decision.strip().lower())
        if mapped is None:
            return False
        with self._lock:
            event = self._events.get(request_id)
            if event is None:
                return False
            self._decisions[request_id] = mapped
            event.set()
            return True


_broker_lock = threading.Lock()
_broker: Optional[ApprovalBroker] = None


def set_broker(broker: Optional[ApprovalBroker]) -> None:
    """Install (or clear, with None) the process-wide approval broker."""
    global _broker
    with _broker_lock:
        _broker = broker


def get_broker() -> Optional[ApprovalBroker]:
    with _broker_lock:
        return _broker
