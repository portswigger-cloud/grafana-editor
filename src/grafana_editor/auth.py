# SPDX-License-Identifier: MIT
from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import Any

import httpx
import jwt
from jwt import InvalidTokenError, PyJWKClient, PyJWKClientError, algorithms
from jwt.algorithms import HMACAlgorithm, NoneAlgorithm
from mcp.server.auth.provider import AccessToken

from grafana_editor.config import EntraSettings

logger = logging.getLogger(__name__)

# Only public-key algorithms are accepted, so a token cannot be forged by
# picking HS256 (which would let the caller "sign" with the public key text)
# or "none".
PUBLIC_KEY_ALGORITHMS: tuple[str, ...] = tuple(
    name
    for name, algorithm in algorithms.get_default_algorithms().items()
    if not isinstance(algorithm, HMACAlgorithm | NoneAlgorithm)
)


class EntraAccessToken(AccessToken):
    """An access token that also carries the caller's email address.

    FastMCP only understands the base ``AccessToken`` fields, but nothing
    stops a verifier from handing back a subclass with extra fields for the
    server's own tools to read back out of ``get_access_token()``.
    """

    email: str


class EntraTokenVerifier:
    """Validates bearer tokens issued by one Entra ID tenant.

    This server never talks to Entra to authenticate anyone itself: the MCP
    client does the OAuth dance directly against Entra (discovered from this
    server's OAuth Protected Resource Metadata), and by the time a request
    reaches here it carries an access token Entra already issued. All this
    class does is check that token's signature, issuer, audience and
    expiry, the same way any resource server validates a bearer token.
    """

    def __init__(self, settings: EntraSettings) -> None:
        self._settings = settings
        self._jwks_client: PyJWKClient | None = None

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            return await asyncio.to_thread(self._verify, token)
        except (InvalidTokenError, PyJWKClientError, ValueError) as exc:
            logger.warning("Bearer token rejected (%s): %s", type(exc).__name__, exc)
            return None

    def _verify(self, token: str) -> EntraAccessToken:
        jwks_client = self._get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        # PyJWT checks `iss` and `aud` itself, but raises a bare "Invalid
        # issuer" / "Invalid audience" that names neither what it expected
        # nor what the token carried, which makes a misconfigured app
        # registration needlessly hard to diagnose. Check them here instead.
        claims = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=list(PUBLIC_KEY_ALGORITHMS),
            options={
                "require": ["exp", "iat", "iss", "aud"],
                "verify_iss": False,
                "verify_aud": False,
            },
        )
        _require_claim(claims, "iss", self._settings.accepted_issuers)
        _require_claim(claims, "aud", (self._settings.audience,))
        email = _email_from_claims(claims)
        scopes = _scopes_from_claims(claims)
        client_id = claims.get("azp") or claims.get("appid") or claims.get("sub", "")
        return EntraAccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(claims["exp"]),
            email=email,
        )

    def _get_jwks_client(self) -> PyJWKClient:
        if self._jwks_client is None:
            jwks_uri = _discover_jwks_uri(self._settings.tenant_id)
            self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)
        return self._jwks_client


def _discover_jwks_uri(tenant_id: str) -> str:
    """Look up the JWKS URI from the tenant's OIDC discovery document.

    Discovering it rather than hardcoding
    ``https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys``  keeps
    this working for sovereign clouds (e.g. Azure Government) that publish
    their endpoints under a different host.
    """
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
        configuration = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValueError(
            f"failed to discover JWKS URI for tenant '{tenant_id}' from '{url}': {exc}"
        ) from exc
    jwks_uri = configuration.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.strip():
        raise ValueError(
            f"OIDC configuration for tenant '{tenant_id}' did not include jwks_uri"
        )
    return jwks_uri


def _require_claim(claims: dict[str, Any], name: str, accepted: Sequence[str]) -> None:
    """Check one claim against the values this server accepts.

    Raises with both sides spelled out, so a rejected token says which
    setting to go and look at rather than just that something didn't match.
    """
    value = claims.get(name)
    if value in accepted:
        return
    wanted = " or ".join(repr(candidate) for candidate in accepted)
    raise InvalidTokenError(
        f"expected the '{name}' claim to be {wanted}, but it was {value!r}"
    )


def _email_from_claims(claims: dict[str, Any]) -> str:
    """Pick the best available email-shaped claim off an Entra access token.

    ``email`` is only present when the app registration requests it as an
    optional claim; ``preferred_username`` is present by default and is
    usually the user's UPN, which is an email address for most tenants but
    not guaranteed to be one.
    """
    for key in ("email", "preferred_username", "upn"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value
    raise ValueError(
        "token did not include an email, preferred_username, or upn claim; "
        "add 'email' as an optional claim on the app registration"
    )


def _scopes_from_claims(claims: dict[str, Any]) -> list[str]:
    scope = claims.get("scp")
    if isinstance(scope, str):
        return scope.split()
    roles = claims.get("roles")
    if isinstance(roles, list):
        return [role for role in roles if isinstance(role, str)]
    return []
