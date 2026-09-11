# SPDX-License-Identifier: MIT
from __future__ import annotations

from starlette.testclient import TestClient

from grafana_editor.auth import _scopes_from_claims
from grafana_editor.config import EntraSettings, Settings
from grafana_editor.server import _build_auth, create_app


def test_health_endpoint() -> None:
    with TestClient(create_app(Settings(), disable_auth=True)) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_requires_entra_config_unless_auth_disabled() -> None:
    try:
        create_app(Settings())
    except RuntimeError as exc:
        assert "entra" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for missing [entra] config")


def _entra_settings() -> EntraSettings:
    return EntraSettings(
        tenant_id="11111111-1111-1111-1111-111111111111",
        client_id="22222222-2222-2222-2222-222222222222",
        audience="https://grafana-editor.platform-prod.portswigger.io",
        scope="mcp.access",
    )


def test_protected_resource_metadata_has_no_trailing_slash() -> None:
    settings = Settings(
        resource_server_url="https://grafana-editor.platform-prod.portswigger.io",
        entra=_entra_settings(),
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    body = response.json()
    # Entra refuses to register an Application ID URI ending in a slash, so
    # this must match settings.resource_server_url exactly, byte for byte.
    # AuthSettings preserves that as long as it is handed the plain string.
    assert body["resource"] == "https://grafana-editor.platform-prod.portswigger.io"
    assert body["authorization_servers"] == [
        "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
    ]
    # Without this, MCP clients have no way to know which scope to request
    # on this resource and fall back to bare OIDC scopes, which Entra
    # rejects with AADSTS9010010 just the same as a resource/scope mismatch.
    assert body["scopes_supported"] == [
        "https://grafana-editor.platform-prod.portswigger.io/mcp.access"
    ]


def test_required_scopes_match_the_scopes_the_verifier_reports() -> None:
    """`required_scopes` is advertised as `scopes_supported` *and* checked
    against `AccessToken.scopes` by exact string match, so the two sides have
    to be built the same way — otherwise every authenticated request 403s
    with `insufficient_scope`."""
    entra = _entra_settings()
    settings = Settings(
        resource_server_url="https://grafana-editor.platform-prod.portswigger.io",
        entra=entra,
    )

    _, auth_settings = _build_auth(settings, False)

    assert auth_settings is not None
    assert auth_settings.required_scopes == [entra.qualified_scope]
    # Entra puts the bare name in `scp`; the verifier qualifies it to match.
    assert _scopes_from_claims({"scp": entra.scope}, entra.audience) == [
        entra.qualified_scope
    ]
