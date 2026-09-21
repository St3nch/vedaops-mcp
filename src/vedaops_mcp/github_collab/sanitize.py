"""Redact secret-bearing provider text before it enters results or journals."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MAX_RESULT_STRING = 64 * 1024

_SECRET_KEYS = frozenset(
    {
        "access_token",
        "authorization",
        "client_secret",
        "github_app_private_key",
        "password",
        "pem",
        "private_key",
        "private_key_path",
        "secret",
        "token",
    }
)
_SECRET_TEXT = re.compile(
    r"(?:"
    r"ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|ghs_[A-Za-z0-9]{20,}"
    r"|ghu_[A-Za-z0-9]{20,}"
    r"|github_app_[A-Za-z0-9_]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|Bearer [A-Za-z0-9._\-]{8,}"
    r")"
)


def scrub_text(value: str) -> tuple[str, bool]:
    """Return text with secret-shaped substrings removed."""
    redacted = False
    if len(value) > MAX_RESULT_STRING:
        value = value[:MAX_RESULT_STRING]
        redacted = True
    cleaned, count = _SECRET_TEXT.subn("***", value)
    return cleaned, redacted or count > 0


def scrub_payload(value: Any) -> tuple[Any, bool]:
    """Return a JSON-ready copy with secret fields and secret-shaped text removed."""
    redacted = False
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if name.casefold() in _SECRET_KEYS:
                redacted = True
                continue
            child, child_redacted = scrub_payload(item)
            redacted = redacted or child_redacted
            cleaned[name] = child
        return cleaned, redacted
    if isinstance(value, list):
        items = []
        for item in value:
            child, child_redacted = scrub_payload(item)
            redacted = redacted or child_redacted
            items.append(child)
        return items, redacted
    if isinstance(value, tuple):
        child, child_redacted = scrub_payload(list(value))
        return child, child_redacted
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    text, text_redacted = scrub_text(str(value))
    return text, text_redacted
