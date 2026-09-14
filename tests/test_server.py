# SPDX-License-Identifier: MIT
from __future__ import annotations

from starlette.testclient import TestClient

from grafana_editor.auth import _scopes_from_claims
from grafana_editor.config import RoleConfig, Settings
from grafana_editor.server import _build_auth, create_app

TENANT_ID = "11111111-1111-1111-1111-111111111111"
RESOURCE = "https://grafana-editor.platform-prod.portswigger.io"
ORIGIN = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
SCOPE = f"{RESOURCE}/mcp.access"


def _settings() -> Settings:
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
    )


def test_health_endpoint() -> None:
    with TestClient(create_app(Settings(), disable_auth=True)) as client:
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


def test_protected_resource_metadata_has_no_trailing_slash() -> None:
    with TestClient(create_app(_settings())) as client:
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
    assert body["scopes_supported"] == [SCOPE]


def test_required_scopes_match_the_scopes_the_verifier_reports() -> None:
    """`scopes` is advertised as `scopes_supported` *and* checked against
    `AccessToken.scopes` by exact string match, so the two sides have to be
    built the same way — otherwise every authenticated request 403s with
    `insufficient_scope`."""
    settings = _settings()

    _, auth_settings = _build_auth(settings, False)

    assert auth_settings is not None
    assert auth_settings.required_scopes == [SCOPE]
    # Entra puts the bare name in `scp`; the verifier qualifies it with the
    # matching role's audience to match.
    assert _scopes_from_claims({"scp": "mcp.access"}, settings.roles[0].audience) == [
        SCOPE
    ]
