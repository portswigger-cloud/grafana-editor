# SPDX-License-Identifier: MIT
from __future__ import annotations

from pathlib import Path

import pytest

from grafana_editor.config import Settings

TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    return path


def test_defaults(tmp_path: Path) -> None:
    settings = Settings.from_toml(_write(tmp_path, ""))

    assert settings.listen == "0.0.0.0"
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert settings.origin is None
    assert settings.scopes == ()
    assert settings.offline_access is True
    assert settings.roles == ()


def test_offline_access_is_advertised_alongside_the_required_scopes(
    tmp_path: Path,
) -> None:
    settings = Settings.from_toml(
        _write(tmp_path, 'scopes = ["api://app-id/mcp.access"]\n')
    )

    assert settings.scopes == ("api://app-id/mcp.access",)
    assert settings.advertised_scopes == ("api://app-id/mcp.access", "offline_access")


def test_offline_access_can_be_turned_off(tmp_path: Path) -> None:
    settings = Settings.from_toml(
        _write(
            tmp_path,
            'scopes = ["api://app-id/mcp.access"]\noffline-access = false\n',
        )
    )

    assert settings.advertised_scopes == ("api://app-id/mcp.access",)


def test_offline_access_is_not_advertised_twice(tmp_path: Path) -> None:
    """An issuer that wants it required as well as advertised can list it in
    `scopes`; it should not then appear twice."""
    settings = Settings.from_toml(
        _write(tmp_path, 'scopes = ["api://app-id/mcp.access", "offline_access"]\n')
    )

    assert settings.advertised_scopes == (
        "api://app-id/mcp.access",
        "offline_access",
    )


def test_rejects_a_non_boolean_offline_access(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="offline-access must be a boolean"):
        Settings.from_toml(_write(tmp_path, 'offline-access = "yes"\n'))


def test_reads_metadata_and_roles(tmp_path: Path) -> None:
    settings = Settings.from_toml(
        _write(
            tmp_path,
            f"""
            resource-server-url = "https://mcp.example.com"
            origin = "https://login.microsoftonline.com/{TENANT_ID}/v2.0"
            scopes = ["api://{CLIENT_ID}/mcp.access"]

            [[role]]
            name = "entra"
            issuer = "https://sts.windows.net/{TENANT_ID}/"
            audience = "api://{CLIENT_ID}"
            """,
        )
    )

    assert settings.resource_server_url == "https://mcp.example.com"
    assert settings.origin == f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    assert settings.scopes == (f"api://{CLIENT_ID}/mcp.access",)
    assert len(settings.roles) == 1
    role = settings.roles[0]
    assert role.name == "entra"
    # The issuer a token carries is its own setting, not derived from the
    # authorization server clients authenticate against.
    assert role.issuer == f"https://sts.windows.net/{TENANT_ID}/"
    assert role.audience == f"api://{CLIENT_ID}"
    assert role.jwks_uri is None


def test_reads_several_roles_and_an_explicit_jwks_uri(tmp_path: Path) -> None:
    settings = Settings.from_toml(
        _write(
            tmp_path,
            """
            [[role]]
            name = "entra-v1"
            issuer = "https://sts.windows.net/tenant/"
            audience = "api://app"

            [[role]]
            name = "entra-v2"
            issuer = "https://login.microsoftonline.com/tenant/v2.0"
            audience = "api://app"
            jwks-uri = "https://login.microsoftonline.com/tenant/discovery/v2.0/keys"
            """,
        )
    )

    assert [role.name for role in settings.roles] == ["entra-v1", "entra-v2"]
    assert settings.roles[1].jwks_uri == (
        "https://login.microsoftonline.com/tenant/discovery/v2.0/keys"
    )


def test_rejects_a_role_without_an_audience(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="role 'entra'.audience"):
        Settings.from_toml(
            _write(
                tmp_path,
                """
                [[role]]
                name = "entra"
                issuer = "https://sts.windows.net/tenant/"
                """,
            )
        )


def test_rejects_duplicate_role_names(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="duplicate role 'entra'"):
        Settings.from_toml(
            _write(
                tmp_path,
                """
                [[role]]
                name = "entra"
                issuer = "https://sts.windows.net/tenant/"
                audience = "api://app"

                [[role]]
                name = "entra"
                issuer = "https://login.microsoftonline.com/tenant/v2.0"
                audience = "api://app"
                """,
            )
        )


def test_rejects_role_as_a_plain_table(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match=r"\[\[role\]\]"):
        Settings.from_toml(
            _write(
                tmp_path,
                """
                [role]
                name = "entra"
                issuer = "https://sts.windows.net/tenant/"
                audience = "api://app"
                """,
            )
        )


def test_rejects_invalid_log_level(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="log-level"):
        Settings.from_toml(_write(tmp_path, 'log-level = "TRACE"'))
