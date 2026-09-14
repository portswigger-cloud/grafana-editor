# SPDX-License-Identifier: MIT
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RoleConfig:
    """One issuer/audience pair whose access tokens this server accepts.

    A bearer token is accepted if it validates against at least one role: its
    signature must verify against that issuer's JWKS, and its ``iss`` and
    ``aud`` claims must equal the role's ``issuer`` and ``audience``.

    ``jwks_uri`` is normally left unset, in which case it is read from
    ``{issuer}/.well-known/openid-configuration`` the first time a token from
    that issuer needs validating. Discovering it rather than hardcoding a
    provider-specific keys endpoint is what lets a role point at any OIDC
    issuer, sovereign Entra clouds (e.g. Azure Government) included; set it
    explicitly only for an issuer that publishes no discovery document.

    For Entra, ``audience`` is the app registration's Application ID URI
    (``api://<client-id>`` unless it was customised). ``issuer`` is whichever
    issuer the tenant actually stamps into its tokens, which is not
    necessarily the authorization server the client talked to: an app
    registration whose manifest leaves ``requestedAccessTokenVersion`` at its
    default issues v1 tokens, with an issuer of
    ``https://sts.windows.net/{tenant}/``, even for a client that
    authenticated via the v2 endpoints.
    """

    name: str
    audience: str
    issuer: str
    jwks_uri: str | None = None

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> RoleConfig:
        name = _required_string(data, "name", context="role")
        context = f"role '{name}'"
        return cls(
            name=name,
            audience=_required_string(data, "audience", context=context),
            issuer=_required_string(data, "issuer", context=context),
            jwks_uri=_optional_string(data, "jwks-uri", context=context),
        )


@dataclass(frozen=True)
class GrafanaSettings:
    """How to reach the Grafana instance this server edits.

    The token is named by path rather than by value so that it can come from
    a Kubernetes secret mounted into the container, and so that it never
    appears in the config file (which is a ConfigMap in this deployment).
    """

    url: str
    service_account_token_path: str

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> GrafanaSettings:
        url = _required_string(data, "url", context="grafana")
        token_path = _required_string(
            data, "service-account-token-path", context="grafana"
        )
        return cls(url=url.rstrip("/"), service_account_token_path=token_path)


@dataclass(frozen=True)
class Settings:
    """This server's configuration.

    ``resource_server_url``, ``origin`` and ``scopes`` are what this server
    publishes in its OAuth Protected Resource Metadata: where this server is
    reachable, which authorization server clients should authenticate
    against, and which scope they should ask it for. ``roles`` is the
    separate question of which tokens are accepted once a client comes back
    holding one. The two are not interchangeable — a tenant can hand out
    tokens whose issuer is not the authorization server its clients talk to.

    ``grafana`` is unrelated to any of that: it is the Grafana instance whose
    data the tools read, which this server reaches as its own service account
    rather than as the caller.
    """

    listen: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    resource_server_url: str | None = None
    origin: str | None = None
    scopes: tuple[str, ...] = ()
    roles: tuple[RoleConfig, ...] = ()
    grafana: GrafanaSettings | None = None

    @classmethod
    def from_toml(cls, path: str | Path) -> Settings:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Invalid TOML in {path}: {exc}") from exc

        return cls(
            listen=_string_or_default(data, "listen", cls.listen),
            port=_int_or_default(data, "port", cls.port),
            log_level=_log_level_or_default(data, "log-level", cls.log_level),
            resource_server_url=_optional_string(
                data, "resource-server-url", context="top-level"
            ),
            origin=_optional_string(data, "origin", context="top-level"),
            scopes=_scopes(data),
            roles=_roles(data),
            grafana=_grafana(data),
        )


def _grafana(data: dict[str, Any]) -> GrafanaSettings | None:
    raw = data.get("grafana")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise TypeError(f"grafana must be a table, not a {type(raw).__name__}")
    return GrafanaSettings.from_mapping(raw)


def _roles(data: dict[str, Any]) -> tuple[RoleConfig, ...]:
    raw = data.get("role")
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise TypeError("role must be an array of tables ([[role]])")
    roles = tuple(RoleConfig.from_mapping(item) for item in raw)
    seen: set[str] = set()
    for role in roles:
        if role.name in seen:
            raise ValueError(f"duplicate role '{role.name}'")
        seen.add(role.name)
    return roles


def _scopes(data: dict[str, Any]) -> tuple[str, ...]:
    raw = data.get("scopes")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise TypeError("scopes must be an array of strings")
    for scope in raw:
        if not isinstance(scope, str):
            raise TypeError(f"scopes entries must be strings, got {scope!r}")
        if not scope.strip():
            raise ValueError("scopes entries must not be empty")
    return tuple(raw)


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
