"""End-to-end tests for the web console over real HTTP.

A ConsoleServer is bound to an ephemeral port against a tmp runs dir and the
offline mock config, then exercised exactly the way the browser frontend
does: start runs via POST /api/pipeline/start, watch /api/pipeline/status,
and resolve a real governance approval through /api/pending + /api/approve
while the pipeline thread blocks on the broker.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

import pytest

from aegis_foundry.config import AppConfig
from aegis_foundry.web.server import ConsoleServer

_POLL_TIMEOUT = 120.0
_POLL_INTERVAL = 0.1


# --------------------------------------------------------------------------
# Fixtures and HTTP helpers (urllib only)
# --------------------------------------------------------------------------


@pytest.fixture
def console(mock_config: AppConfig):
    """A live ConsoleServer on an ephemeral port, torn down after the test."""
    server = ConsoleServer(mock_config, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=10)


def _base(server: ConsoleServer) -> str:
    host, port = server.httpd.server_address[:2]
    return f"http://{host}:{port}"


def _get_raw(url: str) -> tuple[int, str, str]:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.status, resp.headers.get("Content-Type", ""), resp.read().decode("utf-8")


def _get_json(url: str) -> tuple[int, Any]:
    status, _, body = _get_raw(url)
    return status, json.loads(body)


def _post_json(url: str, payload: dict[str, Any]) -> tuple[int, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


def _poll(predicate: Callable[[], Optional[Any]], what: str) -> Any:
    """Poll until predicate returns a truthy value; fail loudly on timeout."""
    deadline = time.monotonic() + _POLL_TIMEOUT
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"timed out after {_POLL_TIMEOUT:.0f}s waiting for {what}")


def _wait_until_idle(base: str) -> dict[str, Any]:
    """Poll /api/pipeline/status until running is false; return final status."""
    def _check() -> Optional[dict[str, Any]]:
        status_code, payload = _get_json(base + "/api/pipeline/status")
        assert status_code == 200
        return None if payload["running"] else payload

    return _poll(_check, "pipeline run to finish")


# --------------------------------------------------------------------------
# (a) Index page
# --------------------------------------------------------------------------


def test_index_serves_html_mentioning_aegis(console: ConsoleServer):
    status, content_type, body = _get_raw(_base(console) + "/")
    assert status == 200
    assert content_type.startswith("text/html")
    assert "Aegis" in body


# --------------------------------------------------------------------------
# (b) Auto-approved run end to end through the HTTP API
# --------------------------------------------------------------------------


def test_auto_approved_run_via_api(console: ConsoleServer):
    base = _base(console)
    status, payload = _post_json(
        base + "/api/pipeline/start", {"auto_approve": True, "fp_budget_weekly": 25}
    )
    assert status == 202
    assert payload == {"started": True}

    final_status = _wait_until_idle(base)
    assert final_status["error"] is None
    assert final_status["run_id"]
    assert final_status["stage"] == "done"
    assert final_status["last_events"], "status must surface flight events"
    assert len(final_status["last_events"]) <= 12

    status, runs = _get_json(base + "/api/runs")
    assert status == 200
    assert len(runs) == 1
    run = runs[0]
    assert run["run_id"] == final_status["run_id"]
    assert run["stage"] == "done"
    headline = run["headline"]
    assert headline["recall"] == 1.0
    assert headline["gaps"] == 1
    assert headline["rules"] == 1
    assert headline["budget"] == 25.0
    assert headline["v1_weekly"] is not None and headline["v1_weekly"] > 25.0
    assert headline["final_weekly"] is not None and headline["final_weekly"] <= 25.0
    assert headline["decision"] == "approve_active"
    assert headline["deployment_mode"] == "active"
    assert headline["verification"] == "ok"

    # The per-run endpoints serve the same run.
    run_id = run["run_id"]
    status, state = _get_json(f"{base}/api/runs/{run_id}")
    assert status == 200
    assert state["run_id"] == run_id
    status, flight = _get_json(f"{base}/api/runs/{run_id}/flight")
    assert status == 200
    assert [e["seq"] for e in flight] == sorted(e["seq"] for e in flight)
    assert {e["action"] for e in flight} >= {"run_started", "governance_decision"}
    status, evidence = _get_json(f"{base}/api/runs/{run_id}/evidence")
    assert status == 200
    assert evidence and evidence[0]["version"] == 2
    assert "Recall" in evidence[0]["markdown"]


# --------------------------------------------------------------------------
# (c) Full web approval path: pipeline blocks until the browser decides
# --------------------------------------------------------------------------


def test_web_approval_path(console: ConsoleServer, mock_config: AppConfig):
    base = _base(console)
    status, payload = _post_json(
        base + "/api/pipeline/start", {"auto_approve": False, "fp_budget_weekly": 25}
    )
    assert status == 202
    assert payload == {"started": True}

    def _pending() -> Optional[list[dict[str, Any]]]:
        status_code, pending = _get_json(base + "/api/pending")
        assert status_code == 200
        return pending or None

    pending = _poll(_pending, "an approval request to appear")
    assert len(pending) == 1
    request = pending[0]
    assert request["rule_version"] == 2
    assert request["technique"] == "T1059.001"
    assert request["recall"] == 1.0
    assert request["fp_budget_weekly"] == 25.0
    assert request["evidence_markdown"] is not None
    assert "Recall" in request["evidence_markdown"]

    status, resolved = _post_json(
        base + "/api/approve",
        {"request_id": request["request_id"], "decision": "active"},
    )
    assert status == 200
    assert resolved == {"ok": True}

    final_status = _wait_until_idle(base)
    assert final_status["error"] is None
    assert final_status["stage"] == "done"

    run_id = final_status["run_id"]
    state_path = mock_config.runs_dir / run_id / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["stage"] == "done"
    rule_id = next(iter(state["decisions"]))
    decision = state["decisions"][rule_id]
    assert decision["decision"] == "approve_active"
    assert decision["approver"] == "human:operator"
    assert state["deployments"][rule_id]["mode"] == "active"


# --------------------------------------------------------------------------
# (d) Approving a nonexistent request is a 404
# --------------------------------------------------------------------------


def test_approve_unknown_request_returns_404(console: ConsoleServer):
    status, payload = _post_json(
        _base(console) + "/api/approve",
        {"request_id": "appr-doesnotexist", "decision": "active"},
    )
    assert status == 404
    assert "error" in payload
