"""Fencing of untrusted text for prompts. Shared by triage and chat.

Security boundary: prompt construction (CLAUDE.md rule 3). Everything that reaches the
model from a customer system, or from a console user, is placed inside a tagged fence
whose body is JSON in which every `<` and `>` (and look-alike angle brackets, control,
format and separator characters) is written as a `\\uXXXX` escape. The body therefore
cannot contain a tag of any kind, so no casing, spacing, attribute or nesting trick can
close a fence early or open a new one. `fenced()` refuses to build a fence if that
invariant is ever broken, so a future rendering change cannot silently reopen the hole.

Moved here from `ai/prompt.py` (Phase 2) so triage and chat share one implementation
instead of two copies that could drift apart.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from typing import Final, Literal

FENCE_TAG: Final = "untrusted_evidence"
FENCE_OPEN: Final = f"<{FENCE_TAG}>"
FENCE_CLOSE: Final = f"</{FENCE_TAG}>"
TRUNCATION_MARK: Final = "…"

# Server-side refusal fallback (shared/model-migration.md, "refusal stop reason" and
# "Migrating to Claude Opus 5.5 -> Safeguards"). "default" lets Anthropic route by refusal
# category, so there is no pinned fallback model to deprecate. Security content can trip
# the cyber classifier; without this a false positive is an outage of the feature.
FALLBACK_BETA: Final = "server-side-fallback-2026-07-01"
FALLBACK_MODE: Literal["default"] = "default"

# Characters written as \\uXXXX inside a fence. ASCII angle brackets are the structural
# threat; the rest are look-alikes and invisible characters that could make the fence or
# its content read differently from what the bytes say.
_ANGLE_LOOKALIKES: Final = frozenset(
    chr(code)
    for code in (
        0x2039, 0x203A, 0x2329, 0x232A, 0x27E8, 0x27E9, 0x3008, 0x3009, 0x300A, 0x300B,
        0xFE64, 0xFE65, 0xFF1C, 0xFF1E, 0x02C2, 0x02C3, 0x1438, 0x1433, 0x276C, 0x276D,
        0x276E, 0x276F, 0x2770, 0x2771, 0x29FC, 0x29FD,
    )
)  # fmt: skip
_ESCAPED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_BMP_LAST: Final = 0xFFFF
_SAFE_CHARS: Final = re.compile(r"[\x20-\x3b\x3d\x3f-\x7e\n]*")
_TAG_NAME: Final = re.compile(r"^[a-z][a-z_]{0,63}$")


class FenceIntegrityError(RuntimeError):
    """A fence body would contain a tag. Never expected; refuse to send."""


def cap(value: str, limit: int) -> tuple[str, bool]:
    """`value` cut to at most `limit` characters (marked), and whether it was cut."""
    if len(value) <= limit:
        return value, False
    return value[: limit - len(TRUNCATION_MARK)] + TRUNCATION_MARK, True


def cap_evidence_value(
    value: object, *, max_chars: int, max_items: int, max_item_chars: int
) -> tuple[object, bool]:
    """A JSON-safe, size-capped copy of one evidence value, and whether it was cut.

    Accepts anything, not only the connector schema's value types: stored evidence is
    read back from the database, and a value of an unexpected shape is rendered as capped
    text rather than trusted or allowed to fail the whole request.
    """
    if value is None or isinstance(value, bool | int):
        return value, False
    if isinstance(value, float):
        # NaN/Infinity are not valid JSON; render as text rather than fail.
        return (value, False) if math.isfinite(value) else (str(value), False)
    if isinstance(value, str):
        return cap(value, max_chars)
    if isinstance(value, list):
        items: list[object] = list(value)  # pyright: ignore[reportUnknownArgumentType]
        cut = len(items) > max_items
        capped_items: list[str] = []
        for item in items[:max_items]:
            text = item if isinstance(item, str) else _as_text(item)
            capped, item_cut = cap(text, max_item_chars)
            capped_items.append(capped)
            cut = cut or item_cut
        return capped_items, cut
    return cap(_as_text(value), max_chars)


def _as_text(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return repr(value)


def _escape_char(char: str) -> str:
    code = ord(char)
    if code > _BMP_LAST:
        # JSON escapes outside the BMP are written as a UTF-16 surrogate pair.
        code -= 0x10000
        return f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}"
    return f"\\u{code:04x}"


def _needs_escape(char: str) -> bool:
    # A raw newline in json.dumps output is always indentation (newlines inside strings are
    # already written as \n), so it is structural and must stay: escaping it would make
    # the document invalid JSON.
    if char == "\n":
        return False
    return (
        char in "<>"
        or char in _ANGLE_LOOKALIKES
        or unicodedata.category(char) in _ESCAPED_CATEGORIES
    )


def escape_json_text(text: str) -> str:
    """Escape fence-relevant characters in already-serialised JSON.

    Safe on the whole document: none of the escaped characters is structural JSON (which
    is ASCII braces, brackets, colon, comma, quote and whitespace), so they can only occur
    inside strings, where `\\uXXXX` is an exact JSON equivalent.
    """
    if _SAFE_CHARS.fullmatch(text):
        return text
    return "".join(_escape_char(c) if _needs_escape(c) else c for c in text)


def dumps_escaped(document: object) -> str:
    """Deterministic, escaped JSON for a fence body.

    sort_keys: the same input always renders the same bytes (prompt caching and dedupe).
    ensure_ascii=False keeps non-English text readable (and short); dangerous characters
    are escaped after. The newlines from indent are the only raw control characters left.
    """
    return escape_json_text(
        json.dumps(document, sort_keys=True, ensure_ascii=False, allow_nan=False, indent=1)
    )


def check_body(body: str) -> None:
    """The invariant every fence rests on: no angle bracket in the body at all."""
    if "<" in body or ">" in body:
        msg = "fence body contains an angle bracket"
        raise FenceIntegrityError(msg)


def fenced(tag: str, body: str) -> str:
    """`body` (already escaped JSON) inside `<tag>` ... `</tag>`, after checking it."""
    if not _TAG_NAME.fullmatch(tag):  # our own constant; checked so a typo cannot open one
        msg = f"invalid fence tag {tag!r}"
        raise ValueError(msg)
    check_body(body)
    return f"<{tag}>\n{body}\n</{tag}>"
