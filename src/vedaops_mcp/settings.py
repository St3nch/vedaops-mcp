"""Fail-closed runtime settings.

Operator policy is resolved from the environment or from the operator's own
``~/.config/vedaops/mcp`` directory. That path is distinct from the live
legacy controller's ``~/.config/vedaops/projects.toml``.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vedaops_mcp.errors import IdentityError, SettingsError

REGISTRY_ENVIRONMENT_VARIABLE = "VEDAOPS_PROJECTS_REGISTRY"
AGENT_ID_ENVIRONMENT_VARIABLE = "VEDAOPS_AGENT_ID"
RESERVED_IDENTITIES = frozenset(
    {"", "anonymous", "unknown", "vedaops-local-agent", "local-stdio-agent"}
)
AGENT_IDENTITY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def operator_config_dir() -> Path:
    """Return the operator-owned configuration directory for this controller."""
    return Path.home() / ".config" / "vedaops" / "mcp"


def default_registry_path() -> Path:
    """Return the default operator policy path."""
    return operator_config_dir() / "projects.toml"


def default_user_config_path() -> Path:
    """Return the optional operator settings file path."""
    return operator_config_dir() / "config.toml"


@dataclass(frozen=True, slots=True)
class Settings:
    principal_id: str
    registry_path: Path
    default_page_size: int = 50
    maximum_page_size: int = 200
    config_source: tuple[str, ...] = ("code-defaults",)

    @classmethod
    def load(cls) -> Settings:
        """Resolve settings, refusing missing identity or insecure policy files."""
        sources = ["code-defaults"]
        principal_id = _required_principal_id()
        registry_path = default_registry_path()
        default_page_size = 50
        maximum_page_size = 200

        user_config = default_user_config_path()
        if user_config.exists() or user_config.is_symlink():
            config_path = _validate_operator_file(user_config, "the operator settings file")
            loaded = _load_user_config(config_path)
            default_page_size = loaded.get("default_page_size", default_page_size)
            maximum_page_size = loaded.get("maximum_page_size", maximum_page_size)
            sources.append("user-config")

        if value := os.getenv(REGISTRY_ENVIRONMENT_VARIABLE):
            registry_path = Path(value).expanduser()
            sources.append("environment")

        if default_page_size > maximum_page_size:
            raise SettingsError(
                "VEDAOPS_CONFIG_INVALID",
                "default_page_size must not exceed maximum_page_size",
            )

        return cls(
            principal_id=principal_id,
            registry_path=_validated_registry_path(registry_path),
            default_page_size=default_page_size,
            maximum_page_size=maximum_page_size,
            config_source=tuple(dict.fromkeys(sources)),
        )


def validate_principal_id(value: object, *, source: str) -> str:
    """Validate one declared agent identity."""
    if not isinstance(value, str):
        raise IdentityError("VEDAOPS_IDENTITY_INVALID", f"{source} must be a string")
    normalized = value.strip()
    if normalized.casefold() in RESERVED_IDENTITIES:
        raise IdentityError(
            "VEDAOPS_IDENTITY_INVALID",
            f"{source} must name one specific agent, not a generic principal",
        )
    if AGENT_IDENTITY_PATTERN.fullmatch(normalized) is None:
        raise IdentityError(
            "VEDAOPS_IDENTITY_INVALID",
            f"{source} must be a normalized lowercase agent name",
        )
    return normalized


def _required_principal_id() -> str:
    value = os.getenv(AGENT_ID_ENVIRONMENT_VARIABLE)
    if value is None or not str(value).strip():
        raise IdentityError(
            "VEDAOPS_IDENTITY_UNAVAILABLE",
            f"{AGENT_ID_ENVIRONMENT_VARIABLE} must name the authenticated principal",
        )
    return validate_principal_id(value, source=AGENT_ID_ENVIRONMENT_VARIABLE)


def _validate_operator_file(path: Path, label: str) -> Path:
    try:
        expanded = path.expanduser()
        source_info = expanded.lstat()
        if stat.S_ISLNK(source_info.st_mode):
            raise SettingsError(
                "VEDAOPS_CONFIG_INSECURE",
                f"{label} must not be a symbolic link",
            )
        resolved = expanded.resolve(strict=True)
        info = resolved.stat()
    except SettingsError:
        raise
    except OSError as exc:
        raise SettingsError("VEDAOPS_CONFIG_UNAVAILABLE", f"{label} is unavailable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise SettingsError("VEDAOPS_CONFIG_INSECURE", f"{label} must be a regular file")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SettingsError(
            "VEDAOPS_CONFIG_INSECURE",
            f"{label} must not be group- or world-writable",
        )
    if info.st_uid != os.getuid():
        raise SettingsError(
            "VEDAOPS_CONFIG_INSECURE",
            f"{label} must be owned by the service user",
        )
    return resolved


def _validated_registry_path(path: Path) -> Path:
    expanded = path.expanduser()
    try:
        source_info = expanded.lstat()
        if stat.S_ISLNK(source_info.st_mode):
            raise SettingsError(
                "VEDAOPS_REGISTRY_INSECURE",
                "the trusted project registry must not be a symbolic link",
            )
        resolved = expanded.resolve(strict=True)
        info = resolved.stat()
    except SettingsError:
        raise
    except OSError as exc:
        raise SettingsError(
            "VEDAOPS_REGISTRY_NOT_CONFIGURED",
            f"no trusted project registry at {expanded}; "
            f"create it or set {REGISTRY_ENVIRONMENT_VARIABLE}",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise SettingsError(
            "VEDAOPS_REGISTRY_INSECURE",
            "the trusted project registry must be a regular file",
        )
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SettingsError(
            "VEDAOPS_REGISTRY_INSECURE",
            "the trusted project registry must not be group- or world-writable",
        )
    if info.st_uid != os.getuid():
        raise SettingsError(
            "VEDAOPS_REGISTRY_INSECURE",
            "the trusted project registry must be owned by the service user",
        )
    return resolved


def _load_user_config(path: Path) -> dict[str, Any]:
    import tomllib

    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SettingsError("VEDAOPS_CONFIG_INVALID", f"{path.name} is not valid TOML") from exc
    unknown = set(data) - {"limits"}
    if unknown:
        raise SettingsError(
            "VEDAOPS_CONFIG_INVALID",
            f"{path.name}: unknown tables {sorted(unknown)}",
        )
    limits = data.get("limits", {})
    if not isinstance(limits, dict):
        raise SettingsError("VEDAOPS_CONFIG_INVALID", f"{path.name}: [limits] must be a table")
    result: dict[str, Any] = {}
    if "default_page_size" in limits:
        result["default_page_size"] = _valid_page_size(
            limits["default_page_size"],
            "limits.default_page_size",
        )
    if "maximum_page_size" in limits:
        result["maximum_page_size"] = _valid_page_size(
            limits["maximum_page_size"],
            "limits.maximum_page_size",
        )
    return result


def _valid_page_size(value: object, source: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SettingsError("VEDAOPS_CONFIG_INVALID", f"{source} must be an integer")
    if value < 1 or value > 1000:
        raise SettingsError("VEDAOPS_CONFIG_INVALID", f"{source} must be between 1 and 1000")
    return value
