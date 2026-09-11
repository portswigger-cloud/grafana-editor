# SPDX-License-Identifier: MIT
from __future__ import annotations

from pathlib import Path

import pytest

from grafana_editor.config import Settings


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    return path


def test_defaults(tmp_path: Path) -> None:
    settings = Settings.from_toml(_write(tmp_path, ""))

    assert settings.listen == "0.0.0.0"
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert settings.entra is None


def test_entra_section(tmp_path: Path) -> None:
    settings = Settings.from_toml(
        _write(
            tmp_path,
            """
            resource-server-url = "https://mcp.example.com"

            [entra]
            tenant-id = "11111111-1111-1111-1111-111111111111"
            client-id = "22222222-2222-2222-2222-222222222222"
            """,
        )
    )

    assert settings.resource_server_url == "https://mcp.example.com"
    assert settings.entra is not None
    assert settings.entra.audience == "api://22222222-2222-2222-2222-222222222222"
    assert settings.entra.scope == "mcp.access"
    assert settings.entra.issuer == (
        "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
    )


def test_entra_audience_override(tmp_path: Path) -> None:
    settings = Settings.from_toml(
        _write(
            tmp_path,
            """
            [entra]
            tenant-id = "11111111-1111-1111-1111-111111111111"
            client-id = "22222222-2222-2222-2222-222222222222"
            audience = "api://custom-app-id-uri"
            scope = "grafana.edit"
            """,
        )
    )

    assert settings.entra is not None
    assert settings.entra.audience == "api://custom-app-id-uri"
    assert settings.entra.scope == "grafana.edit"
    # Qualified with the App ID URI, which is what Entra resolves a scope
    # against — not with resource-server-url, which need not be equal to it.
    assert settings.entra.qualified_scope == "api://custom-app-id-uri/grafana.edit"


def test_rejects_invalid_log_level(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="log-level"):
        Settings.from_toml(_write(tmp_path, 'log-level = "TRACE"'))
