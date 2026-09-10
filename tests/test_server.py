# SPDX-License-Identifier: MIT
from __future__ import annotations

from starlette.testclient import TestClient

from grafana_editor.config import Settings
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
