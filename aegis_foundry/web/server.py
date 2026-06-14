"""Stdlib web console for Aegis Foundry.

:class:`ConsoleServer` exposes the pipeline over plain HTTP so a browser can
watch runs, read evidence packs, and resolve governance approvals. It owns
three things:

- an :class:`~aegis_foundry.web.approvals.ApprovalBroker`, installed
  process-wide while the server runs so the Governor routes interactive
  approvals to the browser instead of stdin;
- a runs-directory reader that turns ``runs/run-*/state.json``,
  ``flight_recorder.jsonl`` and ``evidence/*.md`` into the JSON the frontend
  consumes;
- a single background pipeline runner (one run at a time) driven by
  ``POST /api/pipeline/start``.

API (all JSON responses are ``application/json; charset=utf-8``):

- ``GET  /``                        -> ``static/index.html``
- ``GET  /static/{file}``           -> bundled assets (path-traversal safe)
- ``GET  /api/runs``                -> run summaries, newest first
- ``GET  /api/runs/{id}``           -> the run's raw ``state.json``
- ``GET  /api/runs/{id}/flight``    -> flight-recorder events
- ``GET  /api/runs/{id}/evidence``  -> evidence packs (markdown)
- ``GET  /api/runs/{id}/audit``     -> audit-chain tamper-evidence status
- ``GET  /api/pending``             -> pending approval requests (+ evidence)
- ``POST /api/approve``             -> resolve one approval request
- ``POST /api/pipeline/start``      -> launch a pipeline run in a thread
- ``GET  /api/pipeline/status``     -> live run status + recent flight events
"""

from __future__ import annotations

import copy
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from aegis_foundry.config import AppConfig
from aegis_foundry.orchestrator import run_pipeline
from aegis_foundry.state import PipelineState
from aegis_foundry.web.approvals import ApprovalBroker, set_broker

__all__ = ["ConsoleServer", "RunsReader"]

_STATIC_DIR = Path(__file__).resolve().parent / "static"

_CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

_VALID_DECISIONS = ("active", "shadow", "reject")

_EVIDENCE_FILENAME_RE = re.compile(r"^(?P<rule_id>.+)_v(?P<version>\d+)\.md$")
_RUN_STATE_RE = re.compile(r"^/api/runs/([^/]+)$")
_RUN_FLIGHT_RE = re.compile(r"^/api/runs/([^/]+)/flight$")
_RUN_EVIDENCE_RE = re.compile(r"^/api/runs/([^/]+)/evidence$")
_RUN_AUDIT_RE = re.compile(r"^/api/runs/([^/]+)/audit$")

# Served for GET / when the frontend bundle has not been installed yet, so
# the console degrades to a navigable API directory instead of a 404.
_FALLBACK_INDEX = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Aegis Foundry Console</title>
<style>
body { font-family: system-ui, sans-serif; margin: 3rem auto; max-width: 42rem; color: #1a2733; }
code { background: #eef2f5; padding: 0.1rem 0.35rem; border-radius: 4px; }
li { margin: 0.4rem 0; }
</style>
</head>
<body>
<h1>Aegis Foundry Console</h1>
<p>The web UI bundle (<code>static/index.html</code>) is not installed; the API is fully operational:</p>
<ul>
<li><a href="/api/runs"><code>GET /api/runs</code></a> &mdash; run summaries, newest first</li>
<li><code>GET /api/runs/{run_id}</code> &mdash; full pipeline state</li>
<li><code>GET /api/runs/{run_id}/flight</code> &mdash; agent flight recorder</li>
<li><code>GET /api/runs/{run_id}/evidence</code> &mdash; evidence packs</li>
<li><a href="/api/pending"><code>GET /api/pending</code></a> &mdash; approvals awaiting a human</li>
<li><code>POST /api/approve</code> &mdash; resolve an approval</li>
<li><code>POST /api/pipeline/start</code> &mdash; launch a run</li>
<li><a href="/api/pipeline/status"><code>GET /api/pipeline/status</code></a> &mdash; live run status</li>
</ul>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Runs-directory reader
# --------------------------------------------------------------------------


def _v1_weekly_from_audit(state: dict[str, Any], rule_id: Optional[str]) -> Optional[float]:
    """Weekly hit rate of the first rule's version-1 backtest.

    The Backtest Engineer records ``weekly_rate`` (and ``total_hits``) in its
    ``backtest_completed`` audit events per rule version; the ``backtests``
    map in state only keeps the *latest* version, so the audit trail is the
    one honest source for v1 noise after tuning. Falls back to
    ``total_hits / (window_days / 7)`` when only raw hits were recorded.
    """
    backtests = state.get("backtests") or {}
    for evt in state.get("audit") or []:
        if not isinstance(evt, dict) or evt.get("action") != "backtest_completed":
            continue
        detail = evt.get("detail") or {}
        if not isinstance(detail, dict) or detail.get("version") != 1:
            continue
        evt_rule = detail.get("rule_id")
        if rule_id is not None and evt_rule is not None and evt_rule != rule_id:
            continue
        rate = detail.get("weekly_rate")
        if isinstance(rate, (int, float)):
            return float(rate)
        hits = detail.get("total_hits")
        bt = backtests.get(str(evt_rule or rule_id or "")) or {}
        window = bt.get("window_days") if isinstance(bt, dict) else None
        if isinstance(hits, (int, float)) and isinstance(window, (int, float)) and window > 0:
            return float(hits) / (float(window) / 7.0)
    return None


def _build_headline(state: dict[str, Any]) -> dict[str, Any]:
    """Summarize one run's state.json for the runs list (first rule's story)."""
    rules = state.get("rules") or {}
    first_rid: Optional[str] = next(iter(rules), None)

    final_weekly: Optional[float] = None
    recall: Optional[float] = None
    decision: Optional[str] = None
    deployment_mode: Optional[str] = None
    verification: Optional[str] = None
    if first_rid is not None:
        forecast = (state.get("forecasts") or {}).get(first_rid) or {}
        predicted = forecast.get("predicted_weekly_alerts")
        if isinstance(predicted, (int, float)):
            final_weekly = float(predicted)
        backtest = (state.get("backtests") or {}).get(first_rid) or {}
        bt_recall = backtest.get("recall")
        if isinstance(bt_recall, (int, float)):
            recall = float(bt_recall)
        dec = (state.get("decisions") or {}).get(first_rid) or {}
        if dec.get("decision"):
            decision = str(dec["decision"])
        dep = (state.get("deployments") or {}).get(first_rid) or {}
        if dep.get("mode"):
            deployment_mode = str(dep["mode"])
        ver = (state.get("verifications") or {}).get(first_rid) or {}
        if ver.get("action"):
            verification = str(ver["action"])

    budget = state.get("fp_budget_weekly")

    # Deep-feature headline extras (all tolerant of older runs without them).
    roi = state.get("roi") or {}
    roi_annual = roi.get("total_annual_value") if isinstance(roi, dict) else None
    robustness = state.get("robustness") or {}
    adv_recalls = [
        r.get("adversarial_recall")
        for r in robustness.values()
        if isinstance(r, dict) and isinstance(r.get("adversarial_recall"), (int, float))
        and r.get("variants_total")
    ]
    adversarial_recall = min(adv_recalls) if adv_recalls else None
    compliance = state.get("compliance") or []
    compliance_controls = sum(
        len(a.get("controls") or []) for a in compliance if isinstance(a, dict)
    )

    return {
        "gaps": len(state.get("gaps") or []),
        "rules": len(rules),
        "v1_weekly": _v1_weekly_from_audit(state, first_rid),
        "final_weekly": final_weekly,
        "budget": float(budget) if isinstance(budget, (int, float)) else 0.0,
        "recall": recall,
        "decision": decision,
        "deployment_mode": deployment_mode,
        "verification": verification,
        "roi_annual": float(roi_annual) if isinstance(roi_annual, (int, float)) else None,
        "adversarial_recall": adversarial_recall,
        "compliance_controls": compliance_controls,
    }


class RunsReader:
    """Read-only view over ``runs/run-*`` directories for the console API."""

    def __init__(self, runs_dir: Path) -> None:
        self.runs_dir = Path(runs_dir)

    # -- directory discovery ------------------------------------------------

    def run_dirs(self) -> list[Path]:
        """Every ``run-*`` directory that has a state.json, unsorted."""
        if not self.runs_dir.is_dir():
            return []
        return [
            p for p in self.runs_dir.iterdir()
            if p.is_dir() and p.name.startswith("run-") and (p / "state.json").is_file()
        ]

    def run_dir(self, run_id: str) -> Optional[Path]:
        """Resolve one run directory by id, rejecting path-like ids."""
        if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
            return None
        candidate = self.runs_dir / run_id
        if candidate.is_dir() and candidate.name.startswith("run-"):
            return candidate
        return None

    def latest_run_id(self) -> Optional[str]:
        """Name of the most recently modified run directory, if any."""
        dirs = self.run_dirs()
        if not dirs:
            return None
        return max(dirs, key=lambda p: p.stat().st_mtime).name

    # -- payload builders ----------------------------------------------------

    def load_state(self, run_id: str) -> Optional[dict[str, Any]]:
        """Parsed state.json for a run, or None when absent/unreadable."""
        run_dir = self.run_dir(run_id)
        if run_dir is None:
            return None
        path = run_dir / "state.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def list_runs(self) -> list[dict[str, Any]]:
        """Run summaries for GET /api/runs, newest first."""
        items: list[dict[str, Any]] = []
        for run_dir in self.run_dirs():
            state = self.load_state(run_dir.name)
            if state is None:
                continue
            items.append({
                "run_id": str(state.get("run_id") or run_dir.name),
                "created_at": str(state.get("created_at") or ""),
                "stage": str(state.get("stage") or ""),
                "headline": _build_headline(state),
            })
        items.sort(key=lambda r: r["created_at"], reverse=True)
        return items

    def flight_events(self, run_id: str) -> Optional[list[dict[str, Any]]]:
        """Flight-recorder events as [{seq, ts, agent, action, detail}]."""
        run_dir = self.run_dir(run_id)
        if run_dir is None:
            return None
        path = run_dir / "flight_recorder.jsonl"
        if not path.is_file():
            return []
        events: list[dict[str, Any]] = []
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue  # tolerate a mid-write partial last line
            if not isinstance(raw, dict):
                continue
            events.append({
                "seq": int(raw.get("seq") or 0),
                "ts": str(raw.get("ts") or ""),
                "agent": str(raw.get("agent") or ""),
                "action": str(raw.get("action") or ""),
                "detail": raw.get("detail") if isinstance(raw.get("detail"), dict) else {},
            })
        events.sort(key=lambda e: e["seq"])
        return events

    def audit_status(self, run_id: str) -> Optional[dict[str, Any]]:
        """Tamper-evidence summary: {count, chain_ok, broken_seq} for a run."""
        state = self.load_state(run_id)
        if state is None:
            return None
        try:
            ps = PipelineState.from_dict(state)
        except Exception:  # noqa: BLE001 - malformed state -> report unknown
            return {"count": len(state.get("audit") or []), "chain_ok": None, "broken_seq": None}
        ok, broken = ps.verify_audit_chain()
        return {"count": len(ps.audit), "chain_ok": ok, "broken_seq": broken}

    def evidence(self, run_id: str) -> Optional[list[dict[str, Any]]]:
        """Evidence packs as [{rule_id, version, filename, markdown}]."""
        run_dir = self.run_dir(run_id)
        if run_dir is None:
            return None
        evidence_dir = run_dir / "evidence"
        packs: list[dict[str, Any]] = []
        if not evidence_dir.is_dir():
            return packs
        for path in sorted(evidence_dir.glob("*.md")):
            match = _EVIDENCE_FILENAME_RE.match(path.name)
            if match is None:
                continue
            try:
                markdown = path.read_text(encoding="utf-8")
            except OSError:
                continue
            packs.append({
                "rule_id": match.group("rule_id"),
                "version": int(match.group("version")),
                "filename": path.name,
                "markdown": markdown,
            })
        return packs


# --------------------------------------------------------------------------
# Console server
# --------------------------------------------------------------------------


class _ConsoleHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that carries a back-reference to the ConsoleServer."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type, console: "ConsoleServer") -> None:
        super().__init__(address, handler)
        self.console = console


class ConsoleServer:
    """HTTP console: runs browser, approval bridge, and pipeline launcher."""

    def __init__(self, cfg: AppConfig, *, host: str = "127.0.0.1", port: int = 8787) -> None:
        self.cfg = cfg
        self.host = host
        self.broker = ApprovalBroker()
        self.reader = RunsReader(Path(cfg.runs_dir))
        self._pipeline_lock = threading.Lock()
        # Holder for the single background run: the worker thread writes
        # run_id/error; status reads fall back to a runs-dir watch until the
        # orchestrator has persisted its first state.json.
        self._pipeline: dict[str, Any] = {
            "thread": None,
            "run_id": None,
            "error": None,
            "dirs_before": set(),
        }
        self.httpd = _ConsoleHTTPServer((host, port), _ConsoleRequestHandler, self)
        self.port = int(self.httpd.server_address[1])

    # -- lifecycle ------------------------------------------------------------

    def serve_forever(self) -> None:
        """Install the broker, announce the URL, and serve until shutdown."""
        set_broker(self.broker)
        print(f"Aegis Foundry console -> http://{self.host}:{self.port}")
        print("  runs started from the UI pause at governance until you approve "
              "them in the browser (Ctrl+C to stop)")
        try:
            self.httpd.serve_forever()
        finally:
            set_broker(None)

    def shutdown(self) -> None:
        """Stop the HTTP loop, close the socket, and clear the broker."""
        set_broker(None)
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- background pipeline runner --------------------------------------------

    def start_pipeline(self, auto_approve: bool, fp_budget_weekly: float) -> bool:
        """Launch one pipeline run in a daemon thread; False if one is active."""
        with self._pipeline_lock:
            thread = self._pipeline.get("thread")
            if thread is not None and thread.is_alive():
                return False
            run_cfg = copy.deepcopy(self.cfg)
            run_cfg.auto_approve = bool(auto_approve)
            run_cfg.fp_budget_weekly = float(fp_budget_weekly)
            holder: dict[str, Any] = {
                "thread": None,
                "run_id": None,
                "error": None,
                "dirs_before": {p.name for p in self.reader.run_dirs()},
            }
            worker = threading.Thread(
                target=self._pipeline_worker,
                args=(run_cfg, holder),
                name="aegis-pipeline",
                daemon=True,
            )
            holder["thread"] = worker
            self._pipeline = holder
            worker.start()
            return True

    @staticmethod
    def _pipeline_worker(run_cfg: AppConfig, holder: dict[str, Any]) -> None:
        """Thread body: run the pipeline, record run_id / error in the holder."""
        try:
            state = run_pipeline(run_cfg)
            holder["run_id"] = state.run_id
        except Exception as exc:  # noqa: BLE001 - surfaced via /api/pipeline/status
            holder["error"] = f"{type(exc).__name__}: {exc}"

    def _active_run_id(self) -> Optional[str]:
        """Run id of the in-flight (or just-finished) run, via runs-dir watch.

        The orchestrator mints its own run id, so we record the run-directory
        names that existed before launch and treat the newest directory that
        appeared since as the active run. Once discovered (or once the worker
        finishes and reports the id itself) the value is cached in the holder.
        """
        holder = self._pipeline
        cached = holder.get("run_id")
        if cached:
            return str(cached)
        if holder.get("thread") is None:
            return None
        before: set[str] = holder.get("dirs_before") or set()
        new_dirs = [p for p in self.reader.run_dirs() if p.name not in before]
        if not new_dirs:
            return None
        run_id = max(new_dirs, key=lambda p: p.stat().st_mtime).name
        holder["run_id"] = run_id
        return run_id

    def pipeline_status(self) -> dict[str, Any]:
        """Payload for GET /api/pipeline/status."""
        holder = self._pipeline
        thread = holder.get("thread")
        running = bool(thread is not None and thread.is_alive())
        run_id = self._active_run_id() or self.reader.latest_run_id()
        stage: Optional[str] = None
        last_events: list[dict[str, Any]] = []
        if run_id is not None:
            state = self.reader.load_state(run_id)
            if state is not None:
                stage = str(state.get("stage") or "") or None
            last_events = (self.reader.flight_events(run_id) or [])[-12:]
        error = holder.get("error")
        return {
            "running": running,
            "run_id": run_id,
            "stage": stage,
            "last_events": last_events,
            "error": str(error) if error else None,
        }

    # -- approvals ----------------------------------------------------------------

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Pending approval requests, each extended with evidence markdown."""
        payload: list[dict[str, Any]] = []
        for request in self.broker.pending():
            item = request.to_dict()
            item["evidence_markdown"] = self._read_evidence_pack(request.evidence_pack_path)
            payload.append(item)
        return payload

    def _read_evidence_pack(self, path_str: Optional[str]) -> Optional[str]:
        """Load an evidence pack by stored path (absolute, cwd- or root-relative)."""
        if not path_str:
            return None
        path = Path(path_str)
        candidates = [path] if path.is_absolute() else [path, Path(self.cfg.project_root) / path]
        for candidate in candidates:
            try:
                if candidate.is_file():
                    return candidate.read_text(encoding="utf-8")
            except OSError:
                continue
        return None


# --------------------------------------------------------------------------
# HTTP request handler
# --------------------------------------------------------------------------


class _ConsoleRequestHandler(BaseHTTPRequestHandler):
    """Routes the pinned console API onto a ConsoleServer instance."""

    server: _ConsoleHTTPServer  # narrowed type for self.server
    server_version = "AegisFoundryConsole/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def console(self) -> ConsoleServer:
        return self.server.console

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence per-request stderr noise; the pipeline narrates enough."""

    # -- GET routing -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?", 1)[0]
        try:
            if path == "/":
                self._serve_page("index.html")
            elif path in ("/console", "/console/"):
                self._serve_page("console.html")
            elif path.startswith("/static/"):
                self._serve_static(path[len("/static/"):])
            elif path == "/api/runs":
                self._send_json(self.console.reader.list_runs())
            elif path == "/api/pending":
                self._send_json(self.console.pending_approvals())
            elif path == "/api/pipeline/status":
                self._send_json(self.console.pipeline_status())
            elif (match := _RUN_FLIGHT_RE.match(path)) is not None:
                self._serve_run_payload(match.group(1), self.console.reader.flight_events)
            elif (match := _RUN_EVIDENCE_RE.match(path)) is not None:
                self._serve_run_payload(match.group(1), self.console.reader.evidence)
            elif (match := _RUN_AUDIT_RE.match(path)) is not None:
                self._serve_run_payload(match.group(1), self.console.reader.audit_status)
            elif (match := _RUN_STATE_RE.match(path)) is not None:
                self._serve_run_payload(match.group(1), self.console.reader.load_state)
            else:
                self._send_json({"error": f"no such resource: {path}"}, status=404)
        except Exception as exc:  # noqa: BLE001 - a handler crash must not kill the server
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _serve_run_payload(self, run_id: str, loader: Any) -> None:
        payload = loader(run_id)
        if payload is None:
            self._send_json({"error": f"run '{run_id}' not found"}, status=404)
        else:
            self._send_json(payload)

    # -- POST routing -------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?", 1)[0]
        try:
            if path == "/api/approve":
                self._handle_approve()
            elif path == "/api/pipeline/start":
                self._handle_pipeline_start()
            else:
                self._send_json({"error": f"no such resource: {path}"}, status=404)
        except Exception as exc:  # noqa: BLE001 - a handler crash must not kill the server
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _handle_approve(self) -> None:
        body = self._read_json_body()
        if body is None:
            self._send_json({"error": "request body must be a JSON object"}, status=400)
            return
        request_id = str(body.get("request_id") or "")
        decision = str(body.get("decision") or "").strip().lower()
        if decision not in _VALID_DECISIONS:
            self._send_json(
                {"error": "decision must be one of: " + ", ".join(_VALID_DECISIONS)},
                status=400,
            )
            return
        if self.console.broker.resolve(request_id, decision):
            self._send_json({"ok": True})
        else:
            self._send_json(
                {"error": f"no pending approval with request_id '{request_id}'"},
                status=404,
            )

    def _handle_pipeline_start(self) -> None:
        body = self._read_json_body()
        if body is None:
            self._send_json({"error": "request body must be a JSON object"}, status=400)
            return
        auto_approve = bool(body.get("auto_approve", False))
        try:
            fp_budget_weekly = float(body.get("fp_budget_weekly", 25))
        except (TypeError, ValueError):
            self._send_json({"error": "fp_budget_weekly must be a number"}, status=400)
            return
        if self.console.start_pipeline(auto_approve, fp_budget_weekly):
            self._send_json({"started": True}, status=202)
        else:
            self._send_json({"error": "a run is already in progress"}, status=409)

    # -- static assets -------------------------------------------------------------

    def _serve_page(self, filename: str) -> None:
        """Serve a top-level HTML page: ``/`` -> the landing experience,
        ``/console`` -> the operational dashboard."""
        page = _STATIC_DIR / filename
        if page.is_file():
            self._send_bytes(page.read_bytes(), _CONTENT_TYPES[".html"])
        else:
            self._send_bytes(_FALLBACK_INDEX.encode("utf-8"), _CONTENT_TYPES[".html"])

    def _serve_static(self, rel_path: str) -> None:
        if not rel_path:
            self._send_json({"error": "no such resource: /static/"}, status=404)
            return
        static_root = _STATIC_DIR.resolve()
        try:
            target = (static_root / rel_path).resolve()
        except (OSError, ValueError):
            self._send_json({"error": "invalid static path"}, status=404)
            return
        if not target.is_relative_to(static_root) or not target.is_file():
            self._send_json({"error": f"no such asset: {rel_path}"}, status=404)
            return
        content_type = _CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream")
        self._send_bytes(target.read_bytes(), content_type)

    # -- response / body plumbing ---------------------------------------------------

    def _read_json_body(self) -> Optional[dict[str, Any]]:
        """Parse the POST body as a JSON object; {} when empty, None when invalid."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status=status)

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionError, BrokenPipeError, OSError):
            pass  # client went away mid-response; nothing to recover
