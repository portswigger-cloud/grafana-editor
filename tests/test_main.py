# SPDX-License-Identifier: MIT
from __future__ import annotations

from grafana_editor.config import Settings
from grafana_editor.main import make_server_config


def test_server_config_is_plain_http_without_tls_paths() -> None:
    config = make_server_config(Settings())

    assert config.bind == ["0.0.0.0:8000"]
    assert config.certfile is None
    assert config.keyfile is None


def test_server_config_serves_https_with_tls_paths() -> None:
    config = make_server_config(
        Settings(tls_cert_path="/tls/crt", tls_key_path="/tls/key")
    )

    assert config.certfile == "/tls/crt"
    assert config.keyfile == "/tls/key"
