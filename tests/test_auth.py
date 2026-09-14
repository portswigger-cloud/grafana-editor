# SPDX-License-Identifier: MIT
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm

from grafana_editor.auth import RoleTokenVerifier
from grafana_editor.config import RoleConfig

TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
ISSUER = f"https://sts.windows.net/{TENANT_ID}/"
AUDIENCE = f"api://{CLIENT_ID}"
ROLE = RoleConfig(name="entra", issuer=ISSUER, audience=AUDIENCE)


@pytest.fixture(scope="module")
def rsa_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture(scope="module")
def private_pem(rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> str:
    private_key, _ = rsa_key_pair
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture(scope="module")
def signing_key(rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> PyJWK:
    _, public_key = rsa_key_pair
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    return PyJWK(jwk_dict, algorithm="RS256")


def _make_token(
    private_pem: str,
    *,
    audience: str = AUDIENCE,
    issuer: str = ISSUER,
    extra: dict[str, object] | None = None,
    expires_in: int = 300,
) -> str:
    now = int(time.time())
    payload: dict[str, object] = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + expires_in,
        "sub": "some-subject",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, private_pem, algorithm="RS256")


def _verify(signing_key: PyJWK, token: str, *roles: RoleConfig):
    verifier = RoleTokenVerifier(roles or (ROLE,))
    jwks_client = MagicMock()
    jwks_client.get_signing_key_from_jwt.return_value = signing_key
    # Stand in for the client the verifier would build after discovering the
    # issuer's JWKS URI, so no test needs to reach the network.
    verifier._jwks_clients = {
        issuer: jwks_client for issuer in verifier._roles_by_issuer
    }
    return asyncio.run(verifier.verify_token(token))


def test_accepts_token_with_email_claim(private_pem: str, signing_key: PyJWK) -> None:
    token = _make_token(private_pem, extra={"email": "alice@example.com"})
    access_token = _verify(signing_key, token)

    assert access_token is not None
    assert access_token.email == "alice@example.com"


def test_falls_back_to_preferred_username(private_pem: str, signing_key: PyJWK) -> None:
    token = _make_token(private_pem, extra={"preferred_username": "bob@example.com"})
    access_token = _verify(signing_key, token)

    assert access_token is not None
    assert access_token.email == "bob@example.com"


def test_rejects_token_without_any_email_claim(
    private_pem: str, signing_key: PyJWK
) -> None:
    token = _make_token(private_pem)

    assert _verify(signing_key, token) is None


def test_rejects_wrong_audience(private_pem: str, signing_key: PyJWK) -> None:
    token = _make_token(
        private_pem,
        audience="api://someone-else",
        extra={"email": "alice@example.com"},
    )

    assert _verify(signing_key, token) is None


def test_rejects_expired_token(private_pem: str, signing_key: PyJWK) -> None:
    token = _make_token(
        private_pem, extra={"email": "alice@example.com"}, expires_in=-10
    )

    assert _verify(signing_key, token) is None


def test_reports_scopes_qualified_with_the_app_id_uri(
    private_pem: str, signing_key: PyJWK
) -> None:
    """Entra puts bare names in `scp`, but the SDK checks them against
    `AuthSettings.required_scopes`, which holds the qualified form."""
    token = _make_token(
        private_pem,
        extra={"email": "alice@example.com", "scp": "mcp.access other.scope"},
    )
    access_token = _verify(signing_key, token)

    assert access_token is not None
    assert access_token.scopes == [
        f"{AUDIENCE}/mcp.access",
        f"{AUDIENCE}/other.scope",
    ]


def test_reports_the_role_that_matched(private_pem: str, signing_key: PyJWK) -> None:
    token = _make_token(private_pem, extra={"email": "alice@example.com"})
    access_token = _verify(signing_key, token)

    assert access_token is not None
    assert access_token.role == "entra"


def test_accepts_a_token_matching_any_configured_role(
    private_pem: str, signing_key: PyJWK
) -> None:
    """A second [[role]] is how a second issuer is accepted — for instance an
    app registration whose manifest sets requestedAccessTokenVersion to 2 and
    so issues tokens with the v2 issuer instead of the v1 one."""
    v2_issuer = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    v2_role = RoleConfig(name="entra-v2", issuer=v2_issuer, audience=AUDIENCE)
    token = _make_token(
        private_pem, issuer=v2_issuer, extra={"email": "alice@example.com"}
    )

    access_token = _verify(signing_key, token, ROLE, v2_role)

    assert access_token is not None
    assert access_token.role == "entra-v2"


def test_rejects_an_issuer_no_role_names(private_pem: str, signing_key: PyJWK) -> None:
    token = _make_token(
        private_pem,
        issuer="https://login.microsoftonline.com/some-other-tenant/v2.0",
        extra={"email": "alice@example.com"},
    )

    assert _verify(signing_key, token) is None


def test_issuer_rejection_names_both_sides(
    private_pem: str, signing_key: PyJWK, caplog: pytest.LogCaptureFixture
) -> None:
    token = _make_token(
        private_pem,
        issuer="https://login.microsoftonline.com/some-other-tenant/v2.0",
        extra={"email": "alice@example.com"},
    )

    with caplog.at_level("WARNING"):
        assert _verify(signing_key, token) is None

    assert "'iss'" in caplog.text
    assert "https://login.microsoftonline.com/some-other-tenant/v2.0" in caplog.text
    assert ISSUER in caplog.text


def test_audience_rejection_names_both_sides(
    private_pem: str, signing_key: PyJWK, caplog: pytest.LogCaptureFixture
) -> None:
    token = _make_token(
        private_pem,
        audience="api://someone-else",
        extra={"email": "alice@example.com"},
    )

    with caplog.at_level("WARNING"):
        assert _verify(signing_key, token) is None

    assert "'aud'" in caplog.text
    assert "api://someone-else" in caplog.text
    assert AUDIENCE in caplog.text
