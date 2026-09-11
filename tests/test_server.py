# SPDX-License-Identifier: MIT
from __future__ import annotations

from starlette.testclient import TestClient

from grafana_editor.config import EntraSettings, Settings
from grafana_editor.server import create_app


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
    # this must match settings.resource_server_url exactly, byte for byte —
    # not whatever pydantic's AnyHttpUrl would normalise a bare origin to.
    assert body["resource"] == "https://grafana-editor.platform-prod.portswigger.io"
    assert body["authorization_servers"] == [
        "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
    ]
