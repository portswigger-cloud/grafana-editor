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

from grafana_editor.config import RoleConfig

logger = logging.getLogger(__name__)

# Only public-key algorithms are accepted, so a token cannot be forged by
# picking HS256 (which would let the caller "sign" with the public key text)
# or "none".
PUBLIC_KEY_ALGORITHMS: tuple[str, ...] = tuple(
    name
    for name, algorithm in algorithms.get_default_algorithms().items()
    if not isinstance(algorithm, HMACAlgorithm | NoneAlgorithm)
)


class UserAccessToken(AccessToken):
    """An access token that also carries the caller's email address.

    FastMCP only understands the base ``AccessToken`` fields, but nothing
    stops a verifier from handing back a subclass with extra fields for the
    server's own tools to read back out of ``get_access_token()``.
    """

    email: str
    role: str


class RoleTokenVerifier:
    """Validates bearer tokens against the configured ``[[role]]`` entries.

    This server never talks to the authorization server to log anyone in: the
    MCP client does the OAuth dance directly against it (discovered from this
    server's OAuth Protected Resource Metadata), and by the time a request
    reaches here it carries an access token that server already issued. All
    this class does is check that token's signature, issuer, audience and
    expiry, the same way any resource server validates a bearer token.

    A token is accepted if it matches any one role. Roles are looked up by
    the token's ``iss`` claim first, so a token is only ever checked against
    the keys of the issuer that claims to have signed it.
    """

    def __init__(self, roles: Sequence[RoleConfig]) -> None:
        if not roles:
            raise ValueError("at least one role is required")
        roles_by_issuer: dict[str, list[RoleConfig]] = {}
        for role in roles:
            roles_by_issuer.setdefault(role.issuer, []).append(role)
        self._roles_by_issuer = roles_by_issuer
        self._jwks_clients: dict[str, PyJWKClient] = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            return await asyncio.to_thread(self._verify, token)
        except (InvalidTokenError, PyJWKClientError, TypeError, ValueError) as exc:
            logger.warning("Bearer token rejected (%s): %s", type(exc).__name__, exc)
            return None

    def _verify(self, token: str) -> UserAccessToken:
        # Which roles a token could match is decided by its `iss` claim, and
        # that has to be read before the signature can be checked: the issuer
        # is what says where the signing keys live. Nothing is trusted on the
        # strength of this read — `iss` is checked again below, against the
        # same role, once the signature has been verified.
        candidates = self._roles_for_issuer(_unverified_issuer(token))
        signing_key = self._get_jwks_client(candidates).get_signing_key_from_jwt(token)
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
        _require_claim(claims, "iss", [role.issuer for role in candidates])
        _require_claim(claims, "aud", [role.audience for role in candidates])
        role = next(
            role
            for role in candidates
            if role.issuer == claims["iss"] and role.audience == claims["aud"]
        )
        email = _email_from_claims(claims)
        scopes = _scopes_from_claims(claims, role.audience)
        client_id = claims.get("azp") or claims.get("appid") or claims.get("sub", "")
        logger.info("Bearer token accepted for role '%s'", role.name)
        return UserAccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(claims["exp"]),
            email=email,
            role=role.name,
        )

    def _roles_for_issuer(self, issuer: str | None) -> list[RoleConfig]:
        roles = self._roles_by_issuer.get(issuer) if issuer is not None else None
        if roles is None:
            raise _claim_mismatch("iss", sorted(self._roles_by_issuer), issuer)
        return roles

    def _get_jwks_client(self, roles: list[RoleConfig]) -> PyJWKClient:
        issuer = roles[0].issuer
        client = self._jwks_clients.get(issuer)
        if client is None:
            client = PyJWKClient(_jwks_uri(roles), cache_keys=True, lifespan=3600)
            self._jwks_clients[issuer] = client
        return client


def _unverified_issuer(token: str) -> str | None:
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except InvalidTokenError as exc:
        raise InvalidTokenError(f"could not read the token's claims: {exc}") from exc
    issuer = claims.get("iss")
    return issuer if isinstance(issuer, str) else None


def _jwks_uri(roles: list[RoleConfig]) -> str:
    """Where to fetch the signing keys for the issuer these roles share."""
    configured = {role.jwks_uri for role in roles if role.jwks_uri is not None}
    if len(configured) > 1:
        raise ValueError(
            f"roles for issuer '{roles[0].issuer}' name different jwks-uri values: "
            + ", ".join(sorted(repr(uri) for uri in configured))
        )
    if configured:
        return next(iter(configured))
    return _discover_jwks_uri(roles[0])


def _discover_jwks_uri(role: RoleConfig) -> str:
    """Look up the JWKS URI from the issuer's OIDC discovery document.

    Discovering it rather than hardcoding a provider-specific keys endpoint
    (for Entra, ``https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys``)
    is what lets a role point at any OIDC issuer, sovereign Entra clouds that
    publish their endpoints under a different host included.
    """
    url = f"{role.issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
        configuration = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValueError(
            f"failed to discover the JWKS URI for role '{role.name}' "
            f"from '{url}': {exc}"
        ) from exc
    if not isinstance(configuration, dict):
        raise TypeError(
            f"the OpenID configuration for role '{role.name}' at '{url}' "
            f"is not a JSON object, but {type(configuration).__name__}"
        )
    jwks_uri = configuration.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.strip():
        raise ValueError(
            f"the OpenID configuration for role '{role.name}' at '{url}' "
            f"did not include a jwks_uri string, but {jwks_uri!r}"
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
    raise _claim_mismatch(name, accepted, value)


def _claim_mismatch(
    name: str, accepted: Sequence[str], value: object
) -> InvalidTokenError:
    wanted = " or ".join(repr(candidate) for candidate in accepted)
    return InvalidTokenError(
        f"expected the '{name}' claim to be {wanted}, but it was {value!r}"
    )


def _email_from_claims(claims: dict[str, Any]) -> str:
    """Pick the best available email-shaped claim off an access token.

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


def _scopes_from_claims(claims: dict[str, Any], app_id_uri: str) -> list[str]:
    """Read the token's scopes, qualified with the App ID URI.

    Entra puts bare scope names in ``scp`` (``"mcp.access"``), but the scope
    identifier used everywhere else — the authorization request, the metadata
    document's ``scopes_supported``, and so `AuthSettings.required_scopes`
    which the SDK checks these against — is ``{App ID URI}/{name}``. Qualify
    them here so the two are comparable.
    """
    prefix = app_id_uri.rstrip("/")
    names = _scope_names_from_claims(claims)
    return [f"{prefix}/{name}" for name in names]


def _scope_names_from_claims(claims: dict[str, Any]) -> list[str]:
    scope = claims.get("scp")
    if isinstance(scope, str):
        return scope.split()
    roles = claims.get("roles")
    if isinstance(roles, list):
        return [role for role in roles if isinstance(role, str)]
    return []
