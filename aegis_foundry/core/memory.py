"""Episodic memory for Aegis Foundry agents.

A small JSON-file-backed key/value store that persists knowledge *across*
pipeline runs: tuning lessons ("svc_deploy is benign automation"), per-rule
outcome summaries, and any facts agents choose to remember. Working memory
for a single run lives in :class:`aegis_foundry.state.PipelineState`; this
module is what survives between runs.

Live-mode mapping: this store maps naturally onto the **Splunk KV Store** —
each top-level key becomes a record in a KV Store collection (one collection
per memory namespace), readable from SPL via ``| inputlookup`` and writable
via ``| outputlookup`` or the REST collections API. Those lookups then serve
as the agents' *semantic memory* inside Splunk itself: detections and
dashboards can join live events against remembered facts (known-benign
service accounts, prior tuning exclusions, historical alert baselines)
without any data leaving the platform. The mock-mode JSON file keeps the
exact same shape so agents are oblivious to which backend is active.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Union


class EpisodicMemory:
    """JSON-file-backed dict store with run-summary history.

    Persists to disk on every mutation so memory survives crashes between
    runs. A missing or corrupt backing file is tolerated: the store simply
    starts fresh rather than failing the pipeline. All access is serialized
    with a lock for thread safety.

    The key ``"runs"`` is reserved for the append-only list maintained by
    :meth:`append_run_summary`.

    Args:
        path: Backing JSON file. Parent directories are created on first
            persist if they do not exist.
    """

    #: Reserved key holding the append-only list of run summaries.
    RUNS_KEY: str = "runs"

    def __init__(self, path: Union[Path, str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = self._load()

    def remember(self, key: str, value: Any) -> None:
        """Store ``value`` under ``key`` and persist immediately.

        Values must be JSON-serializable. The reserved ``"runs"`` key cannot
        be overwritten directly; use :meth:`append_run_summary` instead.

        Raises:
            ValueError: If ``key`` is the reserved ``"runs"`` key.
        """
        if key == self.RUNS_KEY:
            raise ValueError(
                f"'{self.RUNS_KEY}' is reserved; use append_run_summary() instead."
            )
        with self._lock:
            self._data[key] = value
            self._persist()

    def recall(self, key: str, default: Any = None) -> Any:
        """Return the value stored under ``key``, or ``default`` if absent."""
        with self._lock:
            return self._data.get(key, default)

    def append_run_summary(self, summary: dict[str, Any]) -> None:
        """Append a run-outcome summary to the ``"runs"`` list and persist."""
        with self._lock:
            runs = self._data.get(self.RUNS_KEY)
            if not isinstance(runs, list):
                runs = []
            runs.append(summary)
            self._data[self.RUNS_KEY] = runs
            self._persist()

    def run_summaries(self) -> list[dict[str, Any]]:
        """Return a copy of all recorded run summaries (oldest first)."""
        with self._lock:
            runs = self._data.get(self.RUNS_KEY)
            return list(runs) if isinstance(runs, list) else []

    # ---- persistence ---------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        """Read the backing file; start fresh if missing, corrupt, or non-dict."""
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _persist(self) -> None:
        """Write the full store to disk (caller must hold the lock)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, sort_keys=True, default=str)
