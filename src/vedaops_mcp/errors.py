"""Stable-code errors and secret-safe detail scrubbing."""

from __future__ import annotations

import os
import re

MAX_DETAIL_CHARS = 400
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_REGISTERED_SECRETS: set[str] = set()


def register_secret(value: str) -> None:
    """Record a value that must never appear in an error detail or log line."""
    if isinstance(value, str) and len(value) >= 8:
        _REGISTERED_SECRETS.add(value)


def forget_secrets() -> None:
    """Clear registered secrets. Used by tests and process teardown."""
    _REGISTERED_SECRETS.clear()


def scrub(detail: object) -> str:
    """Return a bounded, control-free, secret-free rendering of one detail."""
    text = str(detail)
    for secret in _REGISTERED_SECRETS:
        text = text.replace(secret, "***")
    home = os.environ.get("HOME", "")
    if len(home) > 1:
        text = text.replace(home, "~")
    text = _CONTROL_CHARACTERS.sub(" ", text).strip()
    if len(text) > MAX_DETAIL_CHARS:
        text = text[:MAX_DETAIL_CHARS] + "..."
    return text


class VedaOpsError(ValueError):
    """Base class for every stable-code VedaOps failure."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = scrub(detail)
        super().__init__(f"{code}: {self.detail}")


class PolicyError(VedaOpsError):
    """A path, bounds, or Git policy failure."""


class SettingsError(VedaOpsError):
    """A fail-closed runtime configuration failure."""


class IdentityError(VedaOpsError):
    """A fail-closed caller-identity failure."""


class AuthorityError(VedaOpsError):
    """A registry, manifest, or authorization failure."""
