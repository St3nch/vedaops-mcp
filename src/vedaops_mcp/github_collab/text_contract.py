"""Visible-text contract for the pinned GitHub MCP Server v1.12.2.

Bodies and timeline comments are read back through ``sanitize.Content``,
which removes a fixed set of invisible and bidi characters. Titles are read
back through ``sanitize.PlainText``, which also rewrites HTML. F008 accepts
a title only when that rewrite would leave it unchanged, and compares bodies
and comments after the same invisible-character filter.

Equality here is the pinned provider's visible representation. It is not a
claim of exact native GitHub bytes.
"""

from __future__ import annotations

import re
import unicodedata

TEXT_COMPARISON_LIMITATION = (
    "text comparison uses the pinned provider visible-content representation, "
    "not exact native GitHub bytes"
)

_ENTITY = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);")
_REMOVED = frozenset(
    {
        0x200B,
        0x200C,
        0x200E,
        0x200F,
        0x061C,
        0x00AD,
        0xFEFF,
        0x180E,
        0xE0001,
    }
)


def visible_content(value: str) -> str:
    """Return ``sanitize.Content``: invisible characters removed, markup kept."""
    return _filter_invisible(value)


def title_is_stable(value: str) -> bool:
    """Return whether pinned PlainText would return this title unchanged."""
    if _filter_invisible(value) != value:
        return False
    if "\r" in value or "\x00" in value or "<" in value or ">" in value:
        return False
    if _ENTITY.search(value):
        return False
    return _code_fence(value) == value


def texts_match(kind: str, requested: str, observed: str) -> bool:
    """Compare requested text with the provider's read representation."""
    if kind == "title":
        return requested == observed
    return visible_content(requested) == visible_content(observed)


def _filter_invisible(value: str) -> str:
    if all(character < "\x80" for character in value):
        return value
    output: list[str] = []
    previous = ""
    previous_kept = False
    changed = False
    for character in value:
        keep = True
        if _is_variation_selector(character):
            keep = previous_kept and _valid_variation(previous, character)
        elif _should_remove(character):
            keep = False
        previous, previous_kept = character, keep
        if keep:
            output.append(character)
        else:
            changed = True
    if not changed:
        return value
    return "".join(output)


def _should_remove(character: str) -> bool:
    code = ord(character)
    if code in _REMOVED:
        return True
    if 0xE0020 <= code <= 0xE007F:
        return True
    if 0x202A <= code <= 0x202E:
        return True
    if 0x2066 <= code <= 0x2069:
        return True
    return 0x2060 <= code <= 0x2064


def _is_variation_selector(character: str) -> bool:
    code = ord(character)
    return 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF


def _is_graphic(character: str) -> bool:
    category = unicodedata.category(character)
    return category[:1] in {"L", "M", "N", "P", "S"} or category == "Zs"


def _is_han(character: str) -> bool:
    code = ord(character)
    return (
        0x3400 <= code <= 0x4DBF
        or 0x4E00 <= code <= 0x9FFF
        or 0xF900 <= code <= 0xFAFF
        or 0x20000 <= code <= 0x2A6DF
        or 0x2A700 <= code <= 0x2B73F
        or 0x2B740 <= code <= 0x2B81F
        or 0x2B820 <= code <= 0x2CEAF
        or 0x2F800 <= code <= 0x2FA1F
    )


def _valid_variation(base: str, selector: str) -> bool:
    if not base or _is_variation_selector(base) or not _is_graphic(base) or base.isspace():
        return False
    code = ord(selector)
    if code >= 0xE0100:
        return _is_han(base)
    if ord(base) < 128:
        if base not in {"#", "*"} and not base.isdigit():
            return False
        return code in {0xFE0E, 0xFE0F}
    return True


def _code_fence(value: str) -> str:
    lines = value.split("\n")
    changed = False
    inside = False
    fence_len = 0
    sanitized: list[str] = []
    for line in lines:
        replacement, toggled, fence_len = _fence_line(line, inside, fence_len)
        if toggled:
            inside = not inside
            if not inside:
                fence_len = 0
        if replacement != line:
            changed = True
        sanitized.append(replacement)
    if not changed:
        return value
    return "\n".join(sanitized)


def _fence_line(line: str, inside: bool, expected: int) -> tuple[str, bool, int]:
    index = line.find("```")
    if index < 0 or line[:index].strip():
        return line, False, expected
    fence_end = index
    while fence_end < len(line) and line[fence_end] == "`":
        fence_end += 1
    length = fence_end - index
    if length < 3:
        return line, False, expected
    rest = line[fence_end:]
    if inside:
        if expected and length != expected:
            return line, False, expected
        return line[:fence_end], True, length
    trimmed = rest.strip()
    if trimmed == "":
        return line[:fence_end], True, length
    if any(character.isspace() for character in trimmed) or len(trimmed) > 48:
        return line[:fence_end], True, length
    if any(not (character.isalnum() or character in "+-_#.") for character in trimmed):
        return line[:fence_end], True, length
    if rest == trimmed or (rest.startswith(" ") and rest[1:] == trimmed):
        return line, True, length
    if rest[:1].isspace():
        return line[:fence_end] + " " + trimmed, True, length
    return line[:fence_end] + trimmed, True, length
