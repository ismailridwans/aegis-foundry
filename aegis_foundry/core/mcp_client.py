"""Splunk tool-plane clients for Aegis Foundry.

This module implements both sides of the agents' "hands on Splunk":

- The **search plane** (read-only) via the Model Context Protocol:
  :class:`SplunkMCPClient` speaks MCP streamable-HTTP JSON-RPC 2.0 against a
  real Splunk MCP Server, and :class:`MockMCPClient` deterministically replays
  the demo fixtures so the whole pipeline runs offline.

- The **deploy plane** (privileged writes, gated by the Governor):
  :class:`SplunkRESTAdmin` manages saved searches through the Splunk
  management REST API, and :class:`MockSplunkAdmin` keeps an in-memory
  registry while writing a real ``savedsearches.conf``-formatted artifact to
  disk for the demo.

The mock SPL dialect (what :class:`MockMCPClient` evaluates) is intentionally
tiny and pinned: space-separated ``field=value`` filters whose values may be
double-quoted and may contain ``*`` wildcards (matched case-insensitively,
``fnmatch`` style), ``NOT field=value`` negation, and bare keyword tokens
(case-insensitive full-text match). ``index=...`` / ``sourcetype=...`` are
ordinary field filters against the event corpus. Pipes are never evaluated by
the mock — agents fetch raw matching events and compute metrics in Python.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shlex
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import quote

import requests

from aegis_foundry.core.interfaces import (
    DeployError,
    MCPClient,
    MCPError,
    SearchResult,
    SplunkAdminClient,
    SPLValidation,
)

logger = logging.getLogger(__name__)

#: SPL commands that can start a pipeline without an implicit ``search`` prefix.
_GENERATING_COMMANDS = frozenset(
    {
        "search",
        "from",
        "tstats",
        "mstats",
        "mcatalog",
        "makeresults",
        "inputlookup",
        "inputcsv",
        "metadata",
        "metasearch",
        "rest",
        "datamodel",
        "eventcount",
        "loadjob",
        "union",
        "dbinspect",
        "pivot",
    }
)

#: Field names accepted by the mock SPL dialect (Splunk-style identifiers).
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

#: Relative time modifiers understood by the mock, e.g. ``-90d`` / ``-7d``.
_REL_TIME_RE = re.compile(r"^-(\d+)([smhdw])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

#: Pinned demo draft — the Detection Author's v1 SPL (exact string).
PINNED_V1_SPL = (
    'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 '
    'process_name="powershell.exe"'
)


def _needs_search_prefix(spl: str) -> bool:
    """Return True when ``spl`` must be prefixed with ``search `` to be valid."""
    stripped = spl.lstrip()
    if not stripped or stripped.startswith("|"):
        return False
    first = re.split(r"\s+", stripped, maxsplit=1)[0].lower()
    return first not in _GENERATING_COMMANDS


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp (tolerating a trailing ``Z``) to a datetime."""
    dt = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Live MCP client (streamable HTTP, JSON-RPC 2.0)
# ---------------------------------------------------------------------------


class SplunkMCPClient(MCPClient):
    """Splunk MCP Server client over MCP streamable HTTP (JSON-RPC 2.0).

    Performs the ``initialize`` handshake lazily on first use, then exposes
    ``tools/list`` / ``tools/call`` plus the high-level :class:`MCPClient`
    protocol methods. Tool names are discovered at runtime so the client works
    across Splunk MCP Server releases with slightly different namespacing.
    All transport/protocol failures are mapped to :class:`MCPError`; raw
    ``requests`` exceptions never escape.
    """

    PROTOCOL_VERSION = "2025-03-26"
    CLIENT_INFO = {"name": "aegis-foundry", "version": "1.0.0"}

    _SEARCH_TOOL_CANDIDATES = (
        "splunk_run_search",
        "run_search",
        "splunk_search",
        "run_splunk_search",
        "run_oneshot_search",
    )
    _SAVED_SEARCH_TOOL_CANDIDATES = (
        "splunk_list_saved_searches",
        "list_saved_searches",
        "splunk_get_saved_searches",
    )
    _GENERATE_SPL_TOOL = "saia_generate_spl"

    def __init__(self, mcp_url: str, token: str, *, verify_tls: bool = True) -> None:
        self._url = mcp_url
        self._verify = verify_tls
        self._timeout = 120
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
        )
        self._initialized = False
        self._mcp_session_id: Optional[str] = None
        self._next_id = 0
        self._tools_cache: Optional[list[str]] = None
        if not verify_tls:
            try:  # pragma: no cover - cosmetic only
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    # ---- JSON-RPC transport ----

    def _post(self, payload: dict[str, Any]) -> requests.Response:
        headers: dict[str, str] = {}
        if self._mcp_session_id:
            headers["Mcp-Session-Id"] = self._mcp_session_id
        try:
            resp = self._session.post(
                self._url, json=payload, headers=headers, verify=self._verify, timeout=self._timeout
            )
        except requests.RequestException as exc:
            raise MCPError(f"MCP transport error calling {payload.get('method')}: {exc}") from exc
        session_id = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
        if session_id:
            self._mcp_session_id = session_id
        return resp

    @staticmethod
    def _parse_sse(text: str, request_id: Optional[int]) -> dict[str, Any]:
        """Extract the matching JSON-RPC message from an SSE-formatted body."""
        messages: list[dict[str, Any]] = []
        data_lines: list[str] = []

        def flush() -> None:
            if not data_lines:
                return
            try:
                parsed = json.loads("\n".join(data_lines))
                if isinstance(parsed, dict):
                    messages.append(parsed)
            except ValueError:
                pass
            data_lines.clear()

        for line in text.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif not line.strip():
                flush()
        flush()

        for msg in messages:
            if msg.get("id") == request_id and ("result" in msg or "error" in msg):
                return msg
        for msg in reversed(messages):
            if "result" in msg or "error" in msg:
                return msg
        raise MCPError("no JSON-RPC response found in MCP event stream")

    def _parse_message(self, resp: requests.Response, request_id: Optional[int]) -> dict[str, Any]:
        ctype = resp.headers.get("Content-Type", "")
        body = resp.text
        if "text/event-stream" in ctype or body.lstrip().startswith("event:") or body.lstrip().startswith("data:"):
            return self._parse_sse(body, request_id)
        try:
            msg = resp.json()
        except ValueError as exc:
            raise MCPError(f"non-JSON MCP response: {body[:200]!r}") from exc
        if isinstance(msg, list):  # JSON-RPC batch response
            for item in msg:
                if isinstance(item, dict) and item.get("id") == request_id:
                    return item
            msg = msg[-1] if msg else {}
        if not isinstance(msg, dict):
            raise MCPError(f"unexpected MCP response type: {type(msg).__name__}")
        return msg

    def _rpc(
        self,
        method: str,
        params: Optional[dict[str, Any]] = None,
        *,
        notification: bool = False,
        skip_init: bool = False,
    ) -> Any:
        """Send one JSON-RPC 2.0 request (or notification) and return its result."""
        if not skip_init and not self._initialized:
            self._initialize()
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        request_id: Optional[int] = None
        if not notification:
            self._next_id += 1
            request_id = self._next_id
            payload["id"] = request_id
        resp = self._post(payload)
        if resp.status_code >= 400:
            raise MCPError(f"MCP HTTP {resp.status_code} for {method}: {resp.text[:300]}")
        if notification or resp.status_code in (202, 204) or not resp.content:
            return None
        message = self._parse_message(resp, request_id)
        if "error" in message:
            err = message.get("error") or {}
            raise MCPError(f"MCP error {err.get('code')} for {method}: {err.get('message')}")
        return message.get("result")

    def _initialize(self) -> None:
        """Run the MCP initialize handshake followed by notifications/initialized."""
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": self.PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "clientInfo": dict(self.CLIENT_INFO),
            },
            skip_init=True,
        )
        self._initialized = True
        server = (result or {}).get("serverInfo", {}) if isinstance(result, dict) else {}
        logger.debug("MCP initialized against %s %s", server.get("name"), server.get("version"))
        self._rpc("notifications/initialized", {}, notification=True, skip_init=True)

    # ---- MCP primitives ----

    def list_tools(self) -> list[str]:
        """Names of tools exposed by the MCP server (paginated, cached)."""
        if self._tools_cache is not None:
            return list(self._tools_cache)
        names: list[str] = []
        cursor: Optional[str] = None
        while True:
            params: dict[str, Any] = {"cursor": cursor} if cursor else {}
            result = self._rpc("tools/list", params)
            if not isinstance(result, dict):
                break
            for tool in result.get("tools", []) or []:
                name = tool.get("name") if isinstance(tool, dict) else None
                if name:
                    names.append(str(name))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        self._tools_cache = names
        return list(names)

    @staticmethod
    def _content_text(result: dict[str, Any]) -> str:
        parts = [
            str(item.get("text", ""))
            for item in result.get("content", []) or []
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        return "\n".join(p for p in parts if p)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Invoke an MCP tool; return structured content, parsed JSON, or text."""
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        if not isinstance(result, dict):
            return result
        if result.get("isError"):
            raise MCPError(f"MCP tool '{name}' failed: {self._content_text(result)[:300]}")
        structured = result.get("structuredContent")
        if structured is not None:
            return structured
        text = self._content_text(result)
        if text:
            try:
                return json.loads(text)
            except ValueError:
                return text
        return result

    def _find_tool(self, candidates: tuple[str, ...]) -> str:
        """Resolve the first available tool matching the candidate names."""
        tools = self.list_tools()
        lowered = {t.lower(): t for t in tools}
        for cand in candidates:
            if cand.lower() in lowered:
                return lowered[cand.lower()]
        for cand in candidates:
            for tool in tools:
                if cand.lower() in tool.lower():
                    return tool
        raise MCPError(f"no MCP tool found matching any of {list(candidates)} (server exposes {tools})")

    # ---- row/result coercion ----

    @staticmethod
    def _extract_rows(payload: Any) -> list[dict[str, Any]]:
        """Best-effort coercion of a tool payload into a list of row dicts."""
        if isinstance(payload, list):
            return [r if isinstance(r, dict) else {"_raw": r} for r in payload]
        if isinstance(payload, dict):
            for key in ("results", "rows", "events", "data", "entries", "saved_searches", "entry"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [r if isinstance(r, dict) else {"_raw": r} for r in value]
            return [payload] if payload else []
        if isinstance(payload, str) and payload.strip():
            return [{"_raw": payload}]
        return []

    @staticmethod
    def _extract_sid(payload: Any) -> str:
        if isinstance(payload, dict):
            for key in ("sid", "job_sid", "search_id"):
                value = payload.get(key)
                if value:
                    return str(value)
        return ""

    # ---- MCPClient protocol ----

    def run_search(
        self, spl: str, *, earliest: str = "-90d", latest: str = "now", max_results: int = 1000
    ) -> SearchResult:
        """Execute SPL via the server's search tool; errors land in ``SearchResult.error``."""
        try:
            tool = self._find_tool(self._SEARCH_TOOL_CANDIDATES)
            query = f"search {spl.strip()}" if _needs_search_prefix(spl) else spl.strip()
            payload = self.call_tool(
                tool,
                {"query": query, "earliest_time": earliest, "latest_time": latest},
            )
            rows = self._extract_rows(payload)[: max(0, int(max_results))]
            return SearchResult(
                spl=spl, results=rows, count=len(rows), job_sid=self._extract_sid(payload)
            )
        except MCPError as exc:
            logger.warning("run_search failed: %s", exc)
            return SearchResult(spl=spl, error=str(exc))

    def validate_spl(self, spl: str) -> SPLValidation:
        """Parse-only syntax check: run the SPL with ``| head 0`` appended."""
        probe = f"{spl.strip()} | head 0"
        result = self.run_search(probe, earliest="-1m", latest="now", max_results=1)
        return SPLValidation(valid=result.ok, error=result.error)

    def list_saved_searches(self) -> list[dict[str, Any]]:
        """Inventory of existing saved searches via the server's discovery tool."""
        tool = self._find_tool(self._SAVED_SEARCH_TOOL_CANDIDATES)
        payload = self.call_tool(tool, {})
        return self._extract_rows(payload)

    def generate_spl(self, natural_language: str) -> str:
        """NL -> SPL via the Splunk AI Assistant tool, when the server exposes it."""
        if self._GENERATE_SPL_TOOL not in self.list_tools():
            raise MCPError("Splunk AI Assistant tools not available")
        payload = self.call_tool(self._GENERATE_SPL_TOOL, {"prompt": natural_language})
        if isinstance(payload, str) and payload.strip():
            return payload.strip()
        if isinstance(payload, dict):
            for key in ("spl", "search", "query", "result", "text"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        raise MCPError(f"could not parse SPL from {self._GENERATE_SPL_TOOL} response")


# ---------------------------------------------------------------------------
# Deterministic mock MCP client (offline demo mode)
# ---------------------------------------------------------------------------


class MockMCPClient(MCPClient):
    """Fixture-backed Splunk MCP client for fully offline, deterministic runs.

    Loads ``attack_events.json`` and ``existing_saved_searches.json`` from the
    fixtures directory lazily (at first use, never at import/construction
    time) and evaluates the pinned mock SPL dialect against the event corpus.
    Relative time bounds such as ``-90d`` are resolved against the **maximum
    ``_time`` in the corpus**, so the demo replays identically forever.
    """

    _TOOLS = [
        "splunk_run_search",
        "splunk_get_search_results",
        "splunk_list_saved_searches",
        "splunk_list_indexes",
        "splunk_list_sourcetypes",
        "splunk_get_index_info",
        "saia_generate_spl",
        "saia_summarize_events",
    ]

    def __init__(self, fixtures_dir: Union[Path, str]) -> None:
        self._fixtures_dir = Path(fixtures_dir)
        self._events_cache: Optional[list[dict[str, Any]]] = None
        self._saved_cache: Optional[list[dict[str, Any]]] = None
        self._anchor_cache: Optional[datetime] = None

    # ---- lazy fixture loading ----

    def _load_json(self, filename: str) -> Any:
        path = self._fixtures_dir / filename
        if not path.exists():
            raise MCPError(f"fixture not found: {path}")
        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError) as exc:
            raise MCPError(f"failed to load fixture {path}: {exc}") from exc

    def _events(self) -> list[dict[str, Any]]:
        if self._events_cache is None:
            raw = self._load_json("attack_events.json")
            events = raw.get("events", raw) if isinstance(raw, dict) else raw
            if not isinstance(events, list):
                raise MCPError("attack_events.json must contain a list of events")
            self._events_cache = [e for e in events if isinstance(e, dict)]
        return self._events_cache

    def _anchor(self) -> datetime:
        """Max ``_time`` across the corpus — the mock's notion of 'now'."""
        if self._anchor_cache is None:
            times = []
            for event in self._events():
                try:
                    times.append(_parse_iso(event["_time"]))
                except (KeyError, ValueError):
                    continue
            if not times:
                raise MCPError("attack_events.json contains no parseable _time values")
            self._anchor_cache = max(times)
        return self._anchor_cache

    # ---- mock SPL dialect ----

    @staticmethod
    def _split_field_value(token: str) -> Optional[tuple[str, str]]:
        """Return (field, pattern) when ``token`` is a valid field=value filter."""
        if "=" not in token:
            return None
        field, _, value = token.partition("=")
        if not _FIELD_RE.match(field) or value == "":
            return None
        return field, value

    def _compile(
        self, spl: str
    ) -> tuple[list[tuple[str, str, bool]], list[str], Optional[str]]:
        """Tokenize the first pipe segment into (filters, keywords, error).

        filters: list of ``(field, pattern, negate)``; keywords: bare full-text
        tokens. ``error`` names the offending token when the grammar is violated.
        Everything after the first ``|`` is ignored — the mock never evaluates
        pipes (agents compute metrics over raw events in Python instead).
        """
        segment = spl.split("|", 1)[0].strip()
        try:
            tokens = shlex.split(segment)
        except ValueError as exc:
            return [], [], f"unparseable SPL (check quoting): {exc}"
        if tokens and tokens[0].lower() == "search":
            tokens = tokens[1:]
        filters: list[tuple[str, str, bool]] = []
        keywords: list[str] = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == "NOT":
                if i + 1 >= len(tokens):
                    return [], [], "invalid token 'NOT': must be followed by field=value"
                pair = self._split_field_value(tokens[i + 1])
                if pair is None:
                    return [], [], f"invalid token after NOT: '{tokens[i + 1]}' (expected field=value)"
                filters.append((pair[0], pair[1], True))
                i += 2
                continue
            if "=" in token:
                pair = self._split_field_value(token)
                if pair is None:
                    return [], [], f"invalid token: '{token}' (expected field=value)"
                filters.append((pair[0], pair[1], False))
            else:
                keywords.append(token)
            i += 1
        return filters, keywords, None

    @staticmethod
    def _field_matches(event: dict[str, Any], field: str, pattern: str) -> bool:
        value = event.get(field)
        text = "" if value is None else str(value)
        return fnmatchcase(text.lower(), pattern.lower())

    @staticmethod
    def _keyword_matches(event: dict[str, Any], keyword: str) -> bool:
        needle = keyword.lower()
        for value in event.values():
            text = "" if value is None else str(value).lower()
            if ("*" in needle or "?" in needle) and fnmatchcase(text, needle):
                return True
            if needle in text:
                return True
        return False

    def _resolve_time(self, spec: str) -> Optional[datetime]:
        """Resolve ``now`` / ``-Nd``-style modifiers against the corpus anchor."""
        spec = (spec or "").strip().lower().split("@", 1)[0]
        if spec in ("", "now", "rt", "0", "all", "alltime"):
            return None if spec in ("0", "all", "alltime") else self._anchor()
        match = _REL_TIME_RE.match(spec)
        if match:
            amount, unit = int(match.group(1)), match.group(2)
            return self._anchor() - timedelta(seconds=amount * _UNIT_SECONDS[unit])
        try:
            return _parse_iso(spec)
        except ValueError:
            return None  # unparseable -> treat as unbounded

    # ---- MCPClient protocol ----

    def list_tools(self) -> list[str]:
        """Realistic, deterministic tool inventory mirroring the live server."""
        return list(self._TOOLS)

    def run_search(
        self, spl: str, *, earliest: str = "-90d", latest: str = "now", max_results: int = 1000
    ) -> SearchResult:
        """Evaluate the pinned mock SPL dialect against the fixture corpus."""
        try:
            filters, keywords, error = self._compile(spl)
            if error:
                return SearchResult(spl=spl, error=error)
            lower = self._resolve_time(earliest)
            upper = self._resolve_time(latest)
            hits: list[tuple[datetime, dict[str, Any]]] = []
            for event in self._events():
                try:
                    when = _parse_iso(event["_time"])
                except (KeyError, ValueError):
                    continue
                if lower is not None and when < lower:
                    continue
                if upper is not None and when > upper:
                    continue
                matched = all(
                    self._field_matches(event, field, pattern) != negate
                    for field, pattern, negate in filters
                ) and all(self._keyword_matches(event, kw) for kw in keywords)
                if matched:
                    hits.append((when, event))
            hits.sort(key=lambda pair: (pair[0], pair[1].get("host", ""), pair[1].get("user", "")))
            rows = [dict(event) for _, event in hits[: max(0, int(max_results))]]
            sid = "mock-sid-" + hashlib.sha1(
                f"{spl}|{earliest}|{latest}".encode("utf-8")
            ).hexdigest()[:10]
            return SearchResult(spl=spl, results=rows, count=len(rows), job_sid=sid)
        except MCPError as exc:
            return SearchResult(spl=spl, error=str(exc))

    #: SPL commands the mock validator recognizes in pipe segments. Mirrors
    #: Splunk's own "Unknown search command" rejection for anything else.
    _KNOWN_COMMANDS = frozenset(
        {
            "ai", "append", "apply", "bin", "chart", "collect", "convert", "dedup",
            "eval", "eventstats", "fields", "fillnull", "head", "inputlookup",
            "join", "lookup", "makeresults", "outputlookup", "rare", "regex",
            "rename", "rex", "search", "sendemail", "sort", "stats", "streamstats",
            "table", "tail", "timechart", "top", "transaction", "tstats", "where",
        }
    )

    def validate_spl(self, spl: str) -> SPLValidation:
        """Valid iff the first segment matches the mock grammar and every pipe
        segment starts with a recognized SPL command (as real Splunk enforces)."""
        if not spl or not spl.strip():
            return SPLValidation(valid=False, error="empty SPL")
        _, _, error = self._compile(spl)
        if error is not None:
            return SPLValidation(valid=False, error=error)
        for segment in spl.split("|")[1:]:
            words = segment.strip().split()
            if not words:
                return SPLValidation(valid=False, error="empty pipe segment ('||')")
            command = words[0].lower()
            if command not in self._KNOWN_COMMANDS:
                return SPLValidation(
                    valid=False, error=f"Unknown search command '{command}'"
                )
        return SPLValidation(valid=True)

    def list_saved_searches(self) -> list[dict[str, Any]]:
        """Existing detection inventory from ``existing_saved_searches.json``."""
        if self._saved_cache is None:
            raw = self._load_json("existing_saved_searches.json")
            searches = raw.get("saved_searches", raw) if isinstance(raw, dict) else raw
            if not isinstance(searches, list):
                raise MCPError("existing_saved_searches.json must contain a list")
            self._saved_cache = [s for s in searches if isinstance(s, dict)]
        return [dict(s) for s in self._saved_cache]

    def generate_spl(self, natural_language: str) -> str:
        """Deterministic NL->SPL: pinned v1 draft for the demo storyline."""
        lowered = natural_language.lower()
        if "powershell" in lowered or "encoded" in lowered:
            return PINNED_V1_SPL
        words = re.findall(r"[A-Za-z0-9_.\-]+", natural_language)
        terms = " ".join(words[:6])
        return f"index=botsv3 {terms}".strip()


# ---------------------------------------------------------------------------
# Live deploy plane (Splunk management REST API)
# ---------------------------------------------------------------------------


class SplunkRESTAdmin(SplunkAdminClient):
    """Saved-search deployment via the Splunk management REST API.

    Creates (or, on HTTP 409, updates) saved searches under
    ``servicesNS/nobody/{app}/saved/searches`` using bearer-token auth.
    Every successful deploy returns a rollback token of the form
    ``savedsearch::{name}`` which :meth:`rollback` can later undo.
    """

    def __init__(
        self, rest_url: str, token: str, *, verify_tls: bool = True, app: str = "aegis_foundry"
    ) -> None:
        self._base = rest_url.rstrip("/")
        self._app = app
        self._verify = verify_tls
        self._timeout = 30
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {token}"})
        if not verify_tls:
            try:  # pragma: no cover - cosmetic only
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    @property
    def _collection_url(self) -> str:
        return f"{self._base}/servicesNS/nobody/{self._app}/saved/searches"

    def _entity_url(self, name: str) -> str:
        return f"{self._collection_url}/{quote(name, safe='')}"

    def create_saved_search(
        self,
        name: str,
        spl: str,
        *,
        description: str = "",
        cron_schedule: str = "*/10 * * * *",
        disabled: bool = False,
        extra: Optional[dict[str, Any]] = None,
    ) -> str:
        """Create or update a scheduled saved search; return its rollback token."""
        data: dict[str, str] = {
            "search": spl,
            "description": description,
            "cron_schedule": cron_schedule,
            "is_scheduled": "1",
            "disabled": "1" if disabled else "0",
        }
        if extra:
            data.update({str(k): str(v) for k, v in extra.items()})
        try:
            resp = self._session.post(
                self._collection_url,
                params={"output_mode": "json"},
                data={**data, "name": name},
                verify=self._verify,
                timeout=self._timeout,
            )
            if resp.status_code == 409:  # already exists -> update in place
                resp = self._session.post(
                    self._entity_url(name),
                    params={"output_mode": "json"},
                    data=data,
                    verify=self._verify,
                    timeout=self._timeout,
                )
        except requests.RequestException as exc:
            raise DeployError(f"saved-search deploy transport error for '{name}': {exc}") from exc
        if resp.status_code >= 400:
            raise DeployError(
                f"saved-search deploy failed for '{name}' (HTTP {resp.status_code}): {resp.text[:300]}"
            )
        return f"savedsearch::{name}"

    def delete_saved_search(self, name: str) -> bool:
        """Delete a saved search; True when removed, False when it did not exist."""
        try:
            resp = self._session.delete(
                self._entity_url(name),
                params={"output_mode": "json"},
                verify=self._verify,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise DeployError(f"saved-search delete transport error for '{name}': {exc}") from exc
        if resp.status_code == 404:
            return False
        if resp.status_code >= 400:
            raise DeployError(
                f"saved-search delete failed for '{name}' (HTTP {resp.status_code}): {resp.text[:300]}"
            )
        return True

    def rollback(self, rollback_token: str) -> bool:
        """Undo a deployment identified by its ``savedsearch::{name}`` token."""
        prefix = "savedsearch::"
        if not rollback_token.startswith(prefix) or not rollback_token[len(prefix):]:
            raise DeployError(f"malformed rollback token: {rollback_token!r}")
        return self.delete_saved_search(rollback_token[len(prefix):])


# ---------------------------------------------------------------------------
# Mock deploy plane (in-memory + real savedsearches.conf artifact)
# ---------------------------------------------------------------------------


class MockSplunkAdmin(SplunkAdminClient):
    """Offline deploy plane: in-memory registry plus a real conf artifact.

    Every create/update/delete rewrites ``conf_path`` in genuine
    ``savedsearches.conf`` stanza format so the demo can open the produced
    knowledge-object file. Token and rollback semantics mirror
    :class:`SplunkRESTAdmin` exactly.
    """

    def __init__(self, conf_path: Union[Path, str]) -> None:
        self._conf_path = Path(conf_path)
        self._searches: dict[str, dict[str, Any]] = {}

    def _flush(self) -> None:
        """Rewrite the savedsearches.conf artifact from the in-memory registry."""
        lines = [
            "# savedsearches.conf — generated by Aegis Foundry (mock deploy plane)",
            "# Every stanza below was deployed by the governed agent pipeline.",
            "",
        ]
        for name in sorted(self._searches):
            record = self._searches[name]
            lines.append(f"[{name}]")
            lines.append(f"search = {record['search']}")
            lines.append(f"description = {record['description']}")
            lines.append(f"cron_schedule = {record['cron_schedule']}")
            lines.append("enableSched = 1")
            lines.append(f"disabled = {1 if record['disabled'] else 0}")
            for key in sorted(record.get("extra", {})):
                lines.append(f"{key} = {record['extra'][key]}")
            lines.append("")
        self._conf_path.parent.mkdir(parents=True, exist_ok=True)
        self._conf_path.write_text("\n".join(lines), encoding="utf-8")

    def create_saved_search(
        self,
        name: str,
        spl: str,
        *,
        description: str = "",
        cron_schedule: str = "*/10 * * * *",
        disabled: bool = False,
        extra: Optional[dict[str, Any]] = None,
    ) -> str:
        """Register the saved search and persist the conf artifact."""
        if not name.strip():
            raise DeployError("saved search name must not be empty")
        self._searches[name] = {
            "search": spl,
            "description": description,
            "cron_schedule": cron_schedule,
            "disabled": disabled,
            "extra": {str(k): str(v) for k, v in (extra or {}).items()},
        }
        self._flush()
        return f"savedsearch::{name}"

    def delete_saved_search(self, name: str) -> bool:
        """Remove a deployed search; True when it existed."""
        existed = self._searches.pop(name, None) is not None
        if existed:
            self._flush()
        return existed

    def rollback(self, rollback_token: str) -> bool:
        """Undo a deployment identified by its ``savedsearch::{name}`` token."""
        prefix = "savedsearch::"
        if not rollback_token.startswith(prefix) or not rollback_token[len(prefix):]:
            raise DeployError(f"malformed rollback token: {rollback_token!r}")
        return self.delete_saved_search(rollback_token[len(prefix):])

    def list_deployed(self) -> list[str]:
        """Names of currently deployed saved searches (demo/introspection aid)."""
        return sorted(self._searches)
