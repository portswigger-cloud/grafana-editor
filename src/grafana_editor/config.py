# SPDX-License-Identifier: MIT
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EntraSettings:
    """Where to validate access tokens against in Microsoft Entra ID.

    ``audience`` is the value Entra stamps into the ``aud`` claim of access
    tokens minted for this server's exposed API. Entra defaults an app
    registration's App ID URI to ``api://<client-id>``, so that is the
    default here too; set it explicitly if the app registration's App ID URI
    was customised.

    ``scope`` is the name of the scope added under "Expose an API" (e.g.
    ``mcp.access``), used to tell MCP clients which scope to request via this
    server's OAuth Protected Resource Metadata.
    """

    tenant_id: str
    client_id: str
    audience: str
    scope: str = "mcp.access"

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> EntraSettings:
        tenant_id = _required_string(data, "tenant-id", context="entra")
        client_id = _required_string(data, "client-id", context="entra")
        audience = _optional_string(data, "audience", context="entra")
        scope = _optional_string(data, "scope", context="entra")
        return cls(
            tenant_id=tenant_id,
            client_id=client_id,
            audience=audience or f"api://{client_id}",
            scope=scope or "mcp.access",
        )


@dataclass(frozen=True)
class Settings:
    listen: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    resource_server_url: str | None = None
    entra: EntraSettings | None = None

    @classmethod
    def from_toml(cls, path: str | Path) -> Settings:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Invalid TOML in {path}: {exc}") from exc

        entra_data = data.get("entra")
        if entra_data is not None and not isinstance(entra_data, dict):
            raise ValueError("entra must be a table")

        return cls(
            listen=_string_or_default(data, "listen", cls.listen),
            port=_int_or_default(data, "port", cls.port),
            log_level=_log_level_or_default(data, "log-level", cls.log_level),
            resource_server_url=_optional_string(
                data, "resource-server-url", context="top-level"
            ),
            entra=EntraSettings.from_mapping(entra_data) if entra_data else None,
        )


def _required_string(data: dict[str, Any], key: str, *, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}.{key} must be a non-empty string")
    return value


def _optional_string(data: dict[str, Any], key: str, *, context: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}.{key} must be a non-empty string")
    return value


def _string_or_default(data: dict[str, Any], key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _int_or_default(data: dict[str, Any], key: str, default: int) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{key} must be an integer")
    return value


def _log_level_or_default(data: dict[str, Any], key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    normalized = value.upper()
    if normalized not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ValueError(
            f"{key} must be one of DEBUG, INFO, WARNING, ERROR, or CRITICAL"
        )
    return normalized
