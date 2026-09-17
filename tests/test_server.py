# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.auth.middleware.auth_context import (
    AuthenticatedUser,
    auth_context_var,
)
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult
from starlette.testclient import TestClient

from grafana_editor.auth import UserAccessToken, _scopes_from_claims
from grafana_editor.config import GrafanaSettings, RoleConfig, Settings
from grafana_editor.grafana import GrafanaClient
from grafana_editor.server import _build_auth, create_app, create_server

TENANT_ID = "11111111-1111-1111-1111-111111111111"
RESOURCE = "https://grafana-editor.platform-prod.portswigger.io"
ORIGIN = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
SCOPE = f"{RESOURCE}/mcp.access"


def _grafana(tmp_path: Path) -> GrafanaSettings:
    token = tmp_path / "token"
    token.write_text("glsa-test-token")
    return GrafanaSettings(
        url="https://grafana.example.com", service_account_token_path=str(token)
    )


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        resource_server_url=RESOURCE,
        origin=ORIGIN,
        scopes=(SCOPE,),
        roles=(
            RoleConfig(
                name="entra",
                issuer=f"https://sts.windows.net/{TENANT_ID}/",
                audience=RESOURCE,
            ),
        ),
        grafana=_grafana(tmp_path),
    )


def test_health_endpoint(tmp_path: Path) -> None:
    settings = Settings(grafana=_grafana(tmp_path))
    with TestClient(create_app(settings, disable_auth=True)) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_requires_auth_config_unless_auth_disabled() -> None:
    try:
        create_app(Settings())
    except RuntimeError as exc:
        assert "resource-server-url" in str(exc)
        assert "origin" in str(exc)
        assert "[[role]]" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for missing auth config")


def test_requires_grafana_config() -> None:
    with pytest.raises(RuntimeError, match="grafana"):
        create_app(Settings(), disable_auth=True)


def test_protected_resource_metadata_has_no_trailing_slash(tmp_path: Path) -> None:
    with TestClient(create_app(_settings(tmp_path))) as client:
        response = client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    body = response.json()
    # Entra refuses to register an Application ID URI ending in a slash, so
    # this must match settings.resource_server_url exactly, byte for byte.
    # AuthSettings preserves that as long as it is handed the plain string.
    assert body["resource"] == RESOURCE
    # `origin`, not a role's issuer: clients authenticate against the v2
    # endpoint even where the tokens it hands back name sts.windows.net.
    assert body["authorization_servers"] == [ORIGIN]
    # Without this, MCP clients have no way to know which scope to request
    # on this resource and fall back to bare OIDC scopes, which Entra
    # rejects with AADSTS9010010 just the same as a resource/scope mismatch.
    assert body["scopes_supported"] == [SCOPE, "offline_access"]


def test_metadata_asks_for_offline_access_without_requiring_it(
    tmp_path: Path,
) -> None:
    """A client requests the scopes advertised here and nothing more, so
    leaving `offline_access` out of them means Entra hands back no refresh
    token and the client is locked out an hour later. It must not be required
    per request, though: it is the authorization server's scope, so it never
    appears in the `scp` of a token minted for our audience, and requiring it
    would 403 every request with `insufficient_scope`."""
    settings = _settings(tmp_path)

    with TestClient(create_app(settings)) as client:
        advertised = client.get("/.well-known/oauth-protected-resource").json()
    _, auth_settings = _build_auth(settings, False)

    assert "offline_access" in advertised["scopes_supported"]
    assert auth_settings is not None
    assert auth_settings.required_scopes == [SCOPE]


def test_offline_access_can_be_turned_off(tmp_path: Path) -> None:
    settings = replace(_settings(tmp_path), offline_access=False)

    with TestClient(create_app(settings)) as client:
        body = client.get("/.well-known/oauth-protected-resource").json()

    assert body["scopes_supported"] == [SCOPE]


def test_required_scopes_match_the_scopes_the_verifier_reports(
    tmp_path: Path,
) -> None:
    """`scopes` is advertised as `scopes_supported` *and* checked against
    `AccessToken.scopes` by exact string match, so the two sides have to be
    built the same way — otherwise every authenticated request 403s with
    `insufficient_scope`."""
    settings = _settings(tmp_path)

    _, auth_settings = _build_auth(settings, False)

    assert auth_settings is not None
    assert auth_settings.required_scopes == [SCOPE]
    # Entra puts the bare name in `scp`; the verifier qualifies it with the
    # matching role's audience to match.
    assert _scopes_from_claims({"scp": "mcp.access"}, settings.roles[0].audience) == [
        SCOPE
    ]


def _client_against(tmp_path: Path, handler: object) -> GrafanaClient:
    return GrafanaClient(
        _grafana(tmp_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),  # ty: ignore[invalid-argument-type]
    )


@pytest.mark.anyio
async def test_exposes_the_query_and_dashboard_tools(tmp_path: Path) -> None:
    server = create_server(_settings(tmp_path), disable_auth=True)

    names = {tool.name for tool in await server.list_tools()}

    assert names == {
        "whoami",
        "list_datasources",
        "list_metrics",
        "describe_metrics",
        "list_labels",
        "list_label_values",
        "query_instant",
        "query_range",
        "create_dashboard",
        "update_dashboard",
        "get_dashboard",
        "list_dashboards",
    }


@pytest.mark.anyio
async def test_a_tool_call_reaches_grafana_and_comes_back_structured(
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/datasources"
        return httpx.Response(
            200, json=[{"uid": "mimir-uid", "name": "Mimir", "type": "prometheus"}]
        )

    server = create_server(
        _settings(tmp_path),
        disable_auth=True,
        grafana_client=_client_against(tmp_path, handler),
    )

    result = await server.call_tool("list_datasources", {})

    assert isinstance(result, CallToolResult)
    assert result.structured_content is not None
    assert result.structured_content["grafana_url"] == "https://grafana.example.com"
    assert result.structured_content["datasources"][0]["uid"] == "mimir-uid"


@pytest.mark.anyio
async def test_a_grafana_failure_reaches_the_caller_as_a_tool_error(
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Access denied to datasource"})

    server = create_server(
        _settings(tmp_path),
        disable_auth=True,
        grafana_client=_client_against(tmp_path, handler),
    )

    # Not a bare Exception: MCPServer replaces anything else with a generic
    # "internal error", which would hide the reason from the caller.
    with pytest.raises(ToolError, match="Access denied to datasource"):
        await server.call_tool("list_metrics", {"datasource": "Mimir"})


def _signed_in(email: str) -> AuthenticatedUser:
    """An auth context like the one AuthContextMiddleware sets per request."""
    return AuthenticatedUser(
        UserAccessToken(
            token="t",
            client_id="c",
            scopes=[],
            expires_at=None,
            email=email,
            role="entra",
        )
    )


@pytest.mark.anyio
async def test_a_created_dashboard_is_titled_after_the_signed_in_user(
    tmp_path: Path,
) -> None:
    saved: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/search":
            return httpx.Response(
                200, json=[{"uid": "sandbox-uid", "title": "Sandbox"}]
            )
        saved.append(json.loads(request.content))
        return httpx.Response(
            200, json={"uid": "new-uid", "url": "/d/new-uid/x", "version": 1}
        )

    server = create_server(
        _settings(tmp_path),
        disable_auth=True,
        grafana_client=_client_against(tmp_path, handler),
    )

    token = auth_context_var.set(_signed_in("noa.resare@portswigger.net"))
    try:
        result = await server.call_tool(
            "create_dashboard",
            {"title": "Server Temperature", "dashboard": {"panels": []}},
        )
    finally:
        auth_context_var.reset(token)

    assert isinstance(result, CallToolResult)
    assert result.structured_content is not None
    assert result.structured_content["title"] == "noa.resare: Server Temperature"
    assert result.structured_content["url"] == (
        "https://grafana.example.com/d/new-uid/x"
    )
    assert saved[-1]["dashboard"]["title"] == "noa.resare: Server Temperature"
    assert saved[-1]["folderUid"] == "sandbox-uid"


@pytest.mark.anyio
async def test_creating_a_dashboard_needs_a_signed_in_user(tmp_path: Path) -> None:
    server = create_server(_settings(tmp_path), disable_auth=True)

    # No auth context, as when the server runs with --disable-auth: there is no
    # user to name the dashboard after, so this fails rather than inventing one.
    with pytest.raises(ToolError, match="no authenticated user"):
        await server.call_tool(
            "create_dashboard", {"title": "Nameless", "dashboard": {}}
        )
