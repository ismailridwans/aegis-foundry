"""LLM client implementations for Aegis Foundry.

Three interchangeable implementations of the ``LLMClient`` protocol
(:mod:`aegis_foundry.core.interfaces`):

- :class:`MockLLM` — fully deterministic, offline. Routes prompts by keyword
  to canned, high-quality responses that reproduce the pinned demo storyline
  (CISA-AA26-117A encoded-PowerShell credential theft). Judges can run the
  entire pipeline with zero credentials.
- :class:`OpenAICompatibleLLM` — talks to any OpenAI-compatible
  ``/chat/completions`` endpoint (Ollama, vLLM, etc.) serving open-weight
  models such as gpt-oss-20b or Foundation-Sec-1.1-8B-Instruct.
- :class:`SplunkAICommandLLM` — routes completions through Splunk's AI
  Toolkit ``| ai`` SPL command via the MCP search plane, so prompts and
  data never leave the Splunk deployment (hosted-models path).

All three raise :class:`~aegis_foundry.core.interfaces.LLMError` on failure
(the mock never fails by design).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

import requests

from aegis_foundry.core.interfaces import LLMError, MCPClient

# ---------------------------------------------------------------------------
# Pinned demo storyline constants (exact strings — do not reformat).
# ---------------------------------------------------------------------------

V1_SPL: str = (
    'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 '
    'process_name="powershell.exe"'
)

V2_SPL: str = (
    'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 '
    'process_name="powershell.exe" CommandLine="*-EncodedCommand*" '
    'NOT user="svc_deploy"'
)

_T1059_001: dict[str, str] = {
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "tactic": "Execution",
}

_T1003_001: dict[str, str] = {
    "technique_id": "T1003.001",
    "technique_name": "LSASS Memory",
    "tactic": "Credential Access",
}

_TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


class MockLLM:
    """Deterministic, offline stand-in for a security-reasoning LLM.

    ``complete`` inspects the prompt (plus optional system message) with
    keyword routing and returns canned responses that drive the pinned demo
    storyline end-to-end: MITRE mapping of the CISA-AA26-117A advisory,
    coverage mapping of existing saved searches, the v1 detection draft for
    T1059.001, the tuned v2 SPL, and analyst-grade rationale prose. The same
    input always produces the same output, and no network IO ever occurs.
    """

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1024,
    ) -> str:
        """Return a deterministic canned response selected by keyword routing.

        Args:
            prompt: The user prompt to route.
            system: Optional system message; included in routing text.
            model: Ignored (kept for protocol compatibility).
            max_tokens: Ignored (kept for protocol compatibility).
        """
        text = f"{system or ''}\n{prompt}".lower()

        if self._is_tuning_request(text):
            return self._tuning_response()
        if self._is_draft_request(text):
            return self._draft_response()
        if self._is_saved_search_mapping(text):
            return self._saved_search_mapping_response(text)
        if self._is_intel_mapping(text):
            return self._intel_mapping_response(text)
        if self._is_rationale_request(text):
            return self._rationale_response(text)
        return self._generic_response(text)

    # ---- routing predicates -------------------------------------------------

    @staticmethod
    def _is_tuning_request(text: str) -> bool:
        return (
            "exceeds the false-positive budget" in text
            or "tighten" in text
            or "reduce false positives" in text
            or ("tune" in text and "spl" in text)
        )

    @staticmethod
    def _is_draft_request(text: str) -> bool:
        draftish = any(
            kw in text
            for kw in ("draft", "write a detection", "create a detection", "author a detection")
        )
        detectionish = any(kw in text for kw in ("detection", "spl", "saved search", "rule"))
        return draftish and detectionish

    @staticmethod
    def _is_saved_search_mapping(text: str) -> bool:
        existingish = any(
            kw in text
            for kw in ("saved search", "savedsearch", "existing search",
                       "existing detection", "existing rule")
        )
        mappingish = any(kw in text for kw in ("map", "technique", "mitre", "att&ck", "cover"))
        return existingish and mappingish

    @staticmethod
    def _is_intel_mapping(text: str) -> bool:
        mappingish = any(kw in text for kw in ("map", "extract", "identify", "classif"))
        mitreish = any(kw in text for kw in ("mitre", "att&ck", "technique"))
        return mappingish and mitreish

    @staticmethod
    def _is_rationale_request(text: str) -> bool:
        return any(
            kw in text
            for kw in ("rationale", "risk score", "risk assessment", "evidence",
                       "narrative", "justif", "explain the risk")
        )

    # ---- canned responses ---------------------------------------------------

    @staticmethod
    def _intel_mapping_response(text: str) -> str:
        """Strict-JSON technique list containing only techniques present in the prompt."""
        techniques: list[dict[str, str]] = []
        if any(kw in text for kw in ("t1059", "powershell", "encoded")):
            techniques.append(dict(_T1059_001))
        if any(kw in text for kw in ("t1003", "lsass", "credential")):
            techniques.append(dict(_T1003_001))
        return json.dumps(techniques)

    @staticmethod
    def _saved_search_mapping_response(text: str) -> str:
        """Strict-JSON mapping for an existing saved search (T1003.001 or nothing)."""
        if "lsass" in text or "t1003" in text:
            return json.dumps([dict(_T1003_001)])
        return json.dumps([])

    @staticmethod
    def _draft_response() -> str:
        """Strict-JSON detection draft (v1) for the T1059.001 coverage gap."""
        return json.dumps(
            {
                "name": "Suspicious Encoded PowerShell Execution",
                "description": (
                    "Detects PowerShell process creation associated with "
                    "encoded-command abuse linked to credential theft campaigns "
                    "(CISA-AA26-117A)."
                ),
                "spl": V1_SPL,
                "severity": "high",
                "cron_schedule": "*/10 * * * *",
            }
        )

    @staticmethod
    def _tuning_response() -> str:
        """Strict-JSON tuned rule (v2) that constrains the over-broad v1 draft."""
        return json.dumps(
            {
                "spl": V2_SPL,
                "tuning_note": (
                    "Constrained to encoded-command invocations (-EncodedCommand) "
                    "and excluded the svc_deploy automation account, which "
                    "generated the bulk of benign matches in backtest."
                ),
            }
        )

    @staticmethod
    def _rationale_response(text: str) -> str:
        """Security-analyst prose tying the technique to the pinned campaign."""
        match = _TECHNIQUE_ID_RE.search(text)
        technique = match.group(0).upper() if match else "T1059.001"
        return (
            f"Technique {technique} is actively exploited in the CISA-AA26-117A "
            "encoded-PowerShell credential theft campaign, where adversaries launch "
            "powershell.exe with -EncodedCommand payloads to evade keyword-based "
            "detections before harvesting credentials. The organization currently "
            "lacks a high-fidelity detection for this execution pattern, leaving a "
            "direct path from initial access to credential access unobserved. "
            "Backtest evidence shows the malicious activity is cleanly separable "
            "from benign administrative automation once encoded-command filtering "
            "and service-account exclusions are applied. Closing this gap delivers "
            "high detection value at a predictable, in-budget alert volume."
        )

    @staticmethod
    def _generic_response(text: str) -> str:
        """Short, sensible analyst prose for any unrecognized prompt."""
        match = _TECHNIQUE_ID_RE.search(text)
        focus = match.group(0).upper() if match else "the activity in question"
        return (
            f"Based on the available evidence, {focus} warrants continued "
            "monitoring under the current detection strategy. The observed "
            "signals are consistent with the documented campaign behavior, and "
            "no contradicting telemetry was identified in the reviewed window. "
            "Recommend proceeding with the pipeline's next governed step."
        )


class OpenAICompatibleLLM:
    """LLM client for any OpenAI-compatible ``/chat/completions`` endpoint.

    Works with local Ollama (``http://localhost:11434/v1``) or vLLM serving
    open-weight models such as gpt-oss-20b or Foundation-Sec-1.1-8B-Instruct,
    as well as any hosted OpenAI-compatible gateway. Transient failures
    (connection errors, timeouts, HTTP 5xx) are retried three times with
    exponential backoff; the final failure raises :class:`LLMError` with an
    actionable message.
    """

    #: Number of attempts before giving up on transient failures.
    MAX_ATTEMPTS: int = 3
    #: Base backoff delay in seconds (doubled per retry: 1s, 2s).
    BACKOFF_BASE_SECONDS: float = 1.0
    #: Per-request timeout in seconds.
    REQUEST_TIMEOUT_SECONDS: float = 120.0

    def __init__(
        self,
        base_url: str,
        api_key: str,
        default_model: str,
        temperature: float = 0.1,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.default_model = default_model
        self.temperature = temperature

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1024,
    ) -> str:
        """POST a chat completion and return the assistant message text.

        Raises:
            LLMError: After exhausting retries on transient failures, or
                immediately on non-retryable HTTP errors / malformed replies.
        """
        url = f"{self.base_url}/chat/completions"
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error: str = "unknown error"
        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            try:
                resp = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.REQUEST_TIMEOUT_SECONDS,
                )
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ChunkedEncodingError) as exc:
                last_error = f"connection failure: {exc}"
            else:
                if resp.status_code >= 500:
                    last_error = (
                        f"server error HTTP {resp.status_code}: {resp.text[:300]}"
                    )
                elif resp.status_code >= 400:
                    raise LLMError(
                        f"LLM endpoint {url} rejected the request "
                        f"(HTTP {resp.status_code}): {resp.text[:300]}. "
                        "Check AEGIS_LLM_API_KEY and that the model "
                        f"'{payload['model']}' is available on the server."
                    )
                else:
                    return self._extract_text(resp, url)
            if attempt < self.MAX_ATTEMPTS:
                time.sleep(self.BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))

        raise LLMError(
            f"LLM request to {url} failed after {self.MAX_ATTEMPTS} attempts "
            f"({last_error}). Verify the endpoint is reachable (e.g. `ollama serve` "
            f"is running and the model '{payload['model']}' has been pulled), or "
            "set AEGIS_MODE=mock to run fully offline."
        )

    @staticmethod
    def _extract_text(resp: requests.Response, url: str) -> str:
        """Pull ``choices[0].message.content`` out of a 2xx response."""
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(
                f"LLM endpoint {url} returned an unexpected payload "
                f"({exc}): {resp.text[:300]}"
            ) from exc
        if not isinstance(content, str):
            raise LLMError(
                f"LLM endpoint {url} returned non-text content of type "
                f"{type(content).__name__}."
            )
        return content


class SplunkAICommandLLM:
    """LLM client that routes completions through Splunk's AI Toolkit.

    Runs the SPL pipeline
    ``| makeresults | eval prompt="..." | ai prompt="..." model="..."``
    through the MCP search plane (:meth:`MCPClient.run_search`) and reads the
    AI response field from the first result row. Because the prompt is
    evaluated inside Splunk, sensitive search context never leaves the
    deployment — this is the hosted-models path for Splunk Cloud with the
    AI Toolkit installed.
    """

    #: Result-row field names that may carry the AI Toolkit's response text.
    _RESPONSE_FIELDS: tuple[str, ...] = (
        "ai", "ai_response", "ai_result", "response", "result",
        "answer", "completion", "output",
    )

    def __init__(self, mcp: MCPClient, default_model: str) -> None:
        self.mcp = mcp
        self.default_model = default_model

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1024,
    ) -> str:
        """Execute ``| ai`` over the MCP search plane and return its text.

        The optional ``system`` message is prepended to the prompt, since the
        ``| ai`` command takes a single prompt string. ``max_tokens`` is
        accepted for protocol compatibility; output length is governed by the
        AI Toolkit's server-side model configuration.

        Raises:
            LLMError: If the search fails, returns no rows, or the response
                field cannot be located in the first row.
        """
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        escaped_prompt = self._escape_spl_string(full_prompt)
        escaped_model = self._escape_spl_string(model or self.default_model)
        spl = (
            f'| makeresults | eval prompt="{escaped_prompt}" '
            f'| ai prompt="{escaped_prompt}" model="{escaped_model}"'
        )

        try:
            result = self.mcp.run_search(spl, earliest="-1m", latest="now", max_results=1)
        except Exception as exc:  # MCPError or transport-level failure
            raise LLMError(
                f"Splunk | ai command failed via MCP search plane: {exc}. "
                "Verify the AI Toolkit (5.7+) is installed and the model "
                f"'{model or self.default_model}' is configured."
            ) from exc

        if result.error is not None:
            raise LLMError(
                f"Splunk | ai search returned an error: {result.error}. "
                "Verify the AI Toolkit (5.7+) is installed and reachable."
            )
        if not result.results:
            raise LLMError(
                "Splunk | ai search returned no rows; the AI Toolkit may be "
                "unavailable or the model name unrecognized."
            )
        return self._extract_response(result.results[0])

    @staticmethod
    def _escape_spl_string(value: str) -> str:
        """Escape a Python string for safe embedding in a double-quoted SPL literal."""
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @classmethod
    def _extract_response(cls, row: dict[str, Any]) -> str:
        """Locate the AI response text in the first result row."""
        for field_name in cls._RESPONSE_FIELDS:
            value = row.get(field_name)
            if isinstance(value, str) and value.strip():
                return value
        # Fall back: a single non-internal, non-echo field must be the answer.
        candidates = {
            k: v for k, v in row.items()
            if not k.startswith("_") and k != "prompt" and isinstance(v, str) and v.strip()
        }
        if len(candidates) == 1:
            return next(iter(candidates.values()))
        raise LLMError(
            "Could not locate the AI response field in the | ai result row; "
            f"available fields: {sorted(row.keys())}"
        )
