"""Shared LLM-output parsing helpers and a minimal MITRE ATT&CK lookup.

LLMs are asked to answer in strict JSON, but real models (and even
deterministic mocks) sometimes wrap their answer in ``` fences or add a line
of prose. ``parse_llm_json`` is the single, well-tested tolerance layer used
by every agent that consumes structured model output, so parsing behavior is
identical across the swarm.

``MITRE_TECHNIQUES`` is a small built-in technique-id -> (name, tactic) table
covering the techniques exercised by the demo storyline; it keeps mock mode
fully offline (no ATT&CK STIX download required).
"""

from __future__ import annotations

import json
import re
from typing import Any

#: Minimal MITRE ATT&CK lookup: technique_id -> (technique_name, tactic).
MITRE_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1059.001": ("PowerShell", "Execution"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
}

#: Pattern for a syntactically valid ATT&CK technique id (e.g. T1059 or T1059.001).
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

#: Matches a ```json ... ``` (or bare ``` ... ```) fenced block.
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def parse_llm_json(text: str) -> Any:
    """Parse the first JSON object or array found in an LLM response.

    Tolerance rules, applied in order:

    1. Any ```json ... ``` (or plain ``` ... ```) fenced blocks are tried first.
    2. Each candidate is parsed as-is with :func:`json.loads`.
    3. If that fails, the candidate is scanned for ``{`` / ``[`` characters and
       :meth:`json.JSONDecoder.raw_decode` is attempted at each, which ignores
       trailing prose after a balanced JSON value.

    Args:
        text: Raw model output.

    Returns:
        The decoded Python object (``dict`` or ``list``, typically).

    Raises:
        ValueError: If no parseable JSON value exists anywhere in ``text``.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty LLM response; expected strict JSON")

    candidates: list[str] = [m.strip() for m in _FENCE_RE.findall(text) if m.strip()]
    candidates.append(text.strip())

    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        for match in re.finditer(r"[\[{]", candidate):
            try:
                obj, _ = decoder.raw_decode(candidate, match.start())
                return obj
            except json.JSONDecodeError:
                continue
    raise ValueError("no JSON object or array found in LLM response")


def extract_technique_ids(payload: Any) -> list[str]:
    """Normalize an LLM JSON payload into a deduplicated technique-id list.

    Accepts the shapes models actually produce: a list of id strings, a list
    of dicts carrying ``technique_id`` (or ``id`` / ``technique``) keys, or a
    dict wrapping either form under ``techniques`` / ``mitre_techniques``.
    Ids that do not look like ATT&CK technique ids are dropped; order of
    first appearance is preserved so results are deterministic.

    Args:
        payload: Decoded JSON from :func:`parse_llm_json` (or raw metadata).

    Returns:
        Unique, validated technique ids such as ``["T1059.001"]``; possibly empty.
    """
    if isinstance(payload, dict):
        payload = payload.get("techniques") or payload.get("mitre_techniques") or []
    ids: list[str] = []
    if isinstance(payload, list):
        for item in payload:
            tid: str | None = None
            if isinstance(item, str):
                tid = item.strip()
            elif isinstance(item, dict):
                raw = item.get("technique_id") or item.get("id") or item.get("technique")
                if isinstance(raw, str):
                    tid = raw.strip()
            if tid and _TECHNIQUE_ID_RE.match(tid) and tid not in ids:
                ids.append(tid)
    return ids


def technique_info(technique_id: str) -> tuple[str, str]:
    """Return ``(technique_name, tactic)`` for a technique id.

    Falls back to ``(technique_id, "Unknown")`` for ids outside the built-in
    table so callers never crash on novel intel.
    """
    return MITRE_TECHNIQUES.get(technique_id, (technique_id, "Unknown"))
