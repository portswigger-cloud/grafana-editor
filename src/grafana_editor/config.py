# SPDX-License-Identifier: MIT
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

# The Grafana folder dashboards are written to. Writes go nowhere else, so this
# is the one folder the service account needs edit permission on.
DEFAULT_SANDBOX_FOLDER = "Sandbox"


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

    ``sandbox_folder`` is the title of the folder dashboards are created in,
    matched case-insensitively against the folders Grafana reports.
    """

    url: str
    service_account_token_path: str
    sandbox_folder: str = DEFAULT_SANDBOX_FOLDER

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> GrafanaSettings:
        url = _required_string(data, "url", context="grafana")
        token_path = _required_string(
            data, "service-account-token-path", context="grafana"
        )
        folder = _optional_string(data, "sandbox-folder", context="grafana")
        return cls(
            url=url.rstrip("/"),
            service_account_token_path=token_path,
            sandbox_folder=folder or DEFAULT_SANDBOX_FOLDER,
        )


@dataclass(frozen=True)
class TracesSettings:
    """Where spans are exported, and which requests produce none.

    ``endpoint`` is an OTLP gRPC collector, e.g. ``http://otel-collector:4317``;
    an ``http`` URL is dialled without TLS and an ``https`` one with it.
    ``excluded_paths`` are request paths, matched exactly, that are not traced
    at all — health probes, typically — though they are still logged.
    """

    endpoint: str
    excluded_paths: frozenset[str] = frozenset()

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> TracesSettings:
        endpoint = _required_string(data, "endpoint", context="traces")
        parsed = urlparse(endpoint)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "traces.endpoint must be an http:// or https:// URL with a "
                f"host, such as http://otel-collector:4317, not {endpoint!r}"
            )
        return cls(
            endpoint=endpoint,
            excluded_paths=frozenset(_excluded_paths(data)),
        )


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

    ``traces`` says where to export spans; unset, no spans leave the process.

    ``offline_access`` asks clients to request a refresh token as well; see
    ``advertised_scopes``.

    ``grafana`` is unrelated to any of that: it is the Grafana instance whose
    data the tools read, which this server reaches as its own service account
    rather than as the caller.
    """

    listen: str = "0.0.0.0"
    port: int = 8000
    tls_port: ClassVar[int] = 8443
    tls_cert_path: str | None = None
    tls_key_path: str | None = None
    log_level: str = "INFO"
    traces: TracesSettings | None = None
    resource_server_url: str | None = None
    origin: str | None = None
    scopes: tuple[str, ...] = ()
    offline_access: bool = True
    roles: tuple[RoleConfig, ...] = ()
    grafana: GrafanaSettings | None = None

    @property
    def advertised_scopes(self) -> tuple[str, ...]:
        """What clients are told to ask for, which is more than is required.

        A client takes the ``scope`` of its authorization request from this
        server's ``scopes_supported`` (RFC 9728 metadata is the highest
        priority source it has), so that list is also the only chance this
        server gets to ask for ``offline_access``. Without it Entra returns
        an access token and no refresh token, and the client is locked out
        an hour later when the access token expires, with no way back except
        a fresh interactive authorization.

        ``offline_access`` belongs to the authorization server rather than to
        this resource, so it is advertised but never required: it does not
        appear in the ``scp`` of a token minted for our audience, and a token
        is no less valid for that.
        """
        if not self.offline_access or "offline_access" in self.scopes:
            return self.scopes
        return (*self.scopes, "offline_access")

    @classmethod
    def from_toml(cls, path: str | Path) -> Settings:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Invalid TOML in {path}: {exc}") from exc

        tls_cert_path = _optional_string(data, "tls-cert-path", context="top-level")
        tls_key_path = _optional_string(data, "tls-key-path", context="top-level")
        if (tls_cert_path is None) != (tls_key_path is None):
            raise ValueError(
                "tls-cert-path and tls-key-path must be set together, but "
                f"tls-cert-path is {tls_cert_path!r} and "
                f"tls-key-path is {tls_key_path!r}"
            )

        return cls(
            listen=_string_or_default(data, "listen", cls.listen),
            port=_int_or_default(
                data, "port", cls.tls_port if tls_cert_path else cls.port
            ),
            tls_cert_path=tls_cert_path,
            tls_key_path=tls_key_path,
            log_level=_log_level_or_default(data, "log-level", cls.log_level),
            traces=_traces(data),
            resource_server_url=_optional_string(
                data, "resource-server-url", context="top-level"
            ),
            origin=_optional_string(data, "origin", context="top-level"),
            scopes=_scopes(data),
            offline_access=_bool_or_default(data, "offline-access", cls.offline_access),
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


def _traces(data: dict[str, Any]) -> TracesSettings | None:
    # An earlier version read this top-level key. Ignoring it now would leave
    # a config that still sets it running without the traces it asks for.
    if "traces-endpoint" in data:
        raise ValueError(
            "traces-endpoint is no longer supported; move it into a [traces] "
            f"table as endpoint = {data['traces-endpoint']!r}"
        )
    raw = data.get("traces")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise TypeError(f"traces must be a table, not a {type(raw).__name__}")
    return TracesSettings.from_mapping(raw)


def _excluded_paths(data: dict[str, Any]) -> list[str]:
    raw = data.get("excluded-paths", [])
    if not isinstance(raw, list):
        raise TypeError(
            "traces.excluded-paths must be an array of strings, "
            f"not a {type(raw).__name__}"
        )
    for path in raw:
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError(
                "traces.excluded-paths entries must be strings starting with "
                f"'/', such as '/healthz', not {path!r}"
            )
    return raw


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


def _bool_or_default(data: dict[str, Any], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise TypeError(f"{key} must be a boolean, not a {type(value).__name__}")
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
