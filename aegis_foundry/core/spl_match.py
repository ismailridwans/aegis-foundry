"""Standalone evaluator for the pinned mock SPL dialect against a single event.

The Red-Team Gauntlet needs to ask "would this detection fire on *this* synthetic
event?" — a pure logic test, identical in mock and live, because the event is one
we generate, not one we fetch. This module re-implements exactly the grammar
:class:`~aegis_foundry.core.mcp_client.MockMCPClient` evaluates (space-separated
``field=value`` filters with ``fnmatch`` wildcards and case-insensitive matching,
``NOT field=value`` negation, and bare full-text keywords; pipes ignored), so an
adversarial variant is judged by the same rules the real detection uses.
"""

from __future__ import annotations

import re
import shlex
from fnmatch import fnmatchcase
from typing import Any

__all__ = ["parse_predicate", "event_matches", "Predicate"]

_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


class Predicate:
    """A compiled search predicate: field filters + full-text keywords."""

    __slots__ = ("filters", "keywords", "error")

    def __init__(
        self,
        filters: list[tuple[str, str, bool]],
        keywords: list[str],
        error: str | None,
    ) -> None:
        self.filters = filters  # (field, pattern, negate)
        self.keywords = keywords
        self.error = error


def _split_field_value(token: str) -> tuple[str, str] | None:
    if "=" not in token:
        return None
    field, _, value = token.partition("=")
    if not _FIELD_RE.match(field) or value == "":
        return None
    return field, value


def parse_predicate(spl: str) -> Predicate:
    """Compile the first pipe segment of ``spl`` into a :class:`Predicate`."""
    segment = (spl or "").split("|", 1)[0].strip()
    try:
        tokens = shlex.split(segment)
    except ValueError as exc:
        return Predicate([], [], f"unparseable SPL (check quoting): {exc}")
    if tokens and tokens[0].lower() == "search":
        tokens = tokens[1:]
    filters: list[tuple[str, str, bool]] = []
    keywords: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "NOT":
            if i + 1 >= len(tokens):
                return Predicate([], [], "invalid token 'NOT': must be followed by field=value")
            pair = _split_field_value(tokens[i + 1])
            if pair is None:
                return Predicate([], [], f"invalid token after NOT: '{tokens[i + 1]}'")
            filters.append((pair[0], pair[1], True))
            i += 2
            continue
        if "=" in token:
            pair = _split_field_value(token)
            if pair is None:
                return Predicate([], [], f"invalid token: '{token}'")
            filters.append((pair[0], pair[1], False))
        else:
            keywords.append(token)
        i += 1
    return Predicate(filters, keywords, None)


def _field_matches(event: dict[str, Any], field: str, pattern: str) -> bool:
    value = event.get(field)
    text = "" if value is None else str(value)
    return fnmatchcase(text.lower(), pattern.lower())


def _keyword_matches(event: dict[str, Any], keyword: str) -> bool:
    needle = keyword.lower()
    for value in event.values():
        text = "" if value is None else str(value).lower()
        if ("*" in needle or "?" in needle) and fnmatchcase(text, needle):
            return True
        if needle in text:
            return True
    return False


def event_matches(predicate: Predicate, event: dict[str, Any]) -> bool:
    """True when ``event`` satisfies every filter and keyword in ``predicate``."""
    if predicate.error:
        return False
    if not all(
        _field_matches(event, field, pattern) != negate
        for field, pattern, negate in predicate.filters
    ):
        return False
    return all(_keyword_matches(event, kw) for kw in predicate.keywords)
