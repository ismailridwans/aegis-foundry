"""Immutable agent flight recorder for Aegis Foundry.

Every agent action is appended as one JSON line to a run-scoped
``flight_recorder.jsonl`` file, giving each pipeline run a complete,
replayable audit trail independent of the in-memory state mirror
(:attr:`aegis_foundry.state.PipelineState.audit`). The log is append-only by
construction — there is no update or delete API — and writes are serialized
with a lock so concurrent agents cannot interleave partial lines.

For live deployments the trail is also exportable as Splunk HEC-shaped
events (:meth:`AuditLog.to_splunk_events`) destined for the ``aegis_audit``
index with sourcetype ``aegis:flight_recorder``, so the platform's own
governance activity is searchable alongside the detections it manages.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union

from aegis_foundry.state import AuditEvent


class AuditLog:
    """Append-only JSONL audit trail with thread-safe writes.

    Args:
        path: Destination file for the JSON-lines log. Parent directories
            are created on first write if they do not exist.
    """

    #: Splunk index that receives forwarded flight-recorder events.
    SPLUNK_INDEX: str = "aegis_audit"
    #: Sourcetype applied to forwarded flight-recorder events.
    SPLUNK_SOURCETYPE: str = "aegis:flight_recorder"
    #: Source field applied to forwarded flight-recorder events.
    SPLUNK_SOURCE: str = "aegis_foundry"

    def __init__(self, path: Union[Path, str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, evt: AuditEvent) -> None:
        """Append one audit event as a single JSON line (UTF-8).

        Creates parent directories on demand. Serialized under a lock so
        concurrent writers never interleave partial lines.
        """
        line = json.dumps(evt.to_dict(), sort_keys=True, default=str)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def read_all(self) -> list[AuditEvent]:
        """Return every event in the log, in write order.

        A missing file yields an empty list; blank or unparsable lines are
        skipped so a partially written final line never blocks replay.
        """
        with self._lock:
            if not self.path.exists():
                return []
            with open(self.path, "r", encoding="utf-8") as f:
                raw_lines = f.readlines()
        events: list[AuditEvent] = []
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(AuditEvent.from_dict(json.loads(line)))
            except (ValueError, TypeError, KeyError):
                continue  # tolerate a torn/corrupt line rather than fail replay
        return events

    def to_splunk_events(self) -> list[dict[str, Any]]:
        """Shape the full trail as Splunk HEC event envelopes.

        Each envelope targets the ``aegis_audit`` index with sourcetype
        ``aegis:flight_recorder`` and carries the raw audit event as its
        ``event`` body, ready to POST to ``/services/collector/event``.
        Event time is derived from the audit timestamp (epoch seconds);
        events with unparsable timestamps omit ``time`` so HEC assigns
        ingest time instead.
        """
        envelopes: list[dict[str, Any]] = []
        for evt in self.read_all():
            envelope: dict[str, Any] = {
                "index": self.SPLUNK_INDEX,
                "sourcetype": self.SPLUNK_SOURCETYPE,
                "source": self.SPLUNK_SOURCE,
                "event": evt.to_dict(),
            }
            epoch = self._iso_to_epoch(evt.ts)
            if epoch is not None:
                envelope["time"] = epoch
            envelopes.append(envelope)
        return envelopes

    @staticmethod
    def _iso_to_epoch(ts: str) -> Union[float, None]:
        """Convert an ISO-8601 timestamp to epoch seconds, or None if invalid."""
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
