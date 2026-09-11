# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.routes import cors_middleware
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from grafana_editor.auth import EntraAccessToken, EntraTokenVerifier
from grafana_editor.config import Settings

logger = logging.getLogger(__name__)


def create_server(settings: Settings, *, disable_auth: bool = False) -> MCPServer:
    token_verifier, auth_settings = _build_auth(settings, disable_auth)

    mcp = MCPServer(
        "Grafana editor",
        instructions=(
            "Edit Grafana on behalf of the user signed in via Microsoft Entra ID "
            "SSO. Currently only exposes 'whoami'; Grafana-editing tools are still "
            "to come."
        ),
        token_verifier=token_verifier,
        auth=auth_settings,
    )

    @mcp.tool()
    def whoami() -> dict[str, str]:
        """Get the email address of the currently signed-in user."""
        access_token = get_access_token()
        if access_token is None:
            raise ToolError("no authenticated user is associated with this request")
        if not isinstance(access_token, EntraAccessToken):
            raise ToolError(
                "authentication is disabled on this server; no user is signed in"
            )
        return {"email": access_token.email}

    return mcp


def _build_auth(
    settings: Settings, disable_auth: bool
) -> tuple[EntraTokenVerifier | None, AuthSettings | None]:
    if disable_auth:
        logger.warning("authentication disabled by --disable-auth")
        return None, None
    if settings.entra is None:
        raise RuntimeError(
            "an [entra] section is required in the config file (or pass --disable-auth)"
        )
    if settings.resource_server_url is None:
        raise RuntimeError(
            "resource-server-url is required in the config file (or pass --disable-auth)"
        )
    token_verifier = EntraTokenVerifier(settings.entra)
    auth_settings = AuthSettings(
        issuer_url=AnyHttpUrl(settings.entra.issuer),
        resource_server_url=AnyHttpUrl(settings.resource_server_url),
        # EntraTokenVerifier already checks the token's audience against
        # settings.entra.audience, so the RFC 8707 resource indicator check
        # below would be redundant.
        validate_token_resource=False,
    )
    return token_verifier, auth_settings


def create_app(settings: Settings, *, disable_auth: bool = False) -> Starlette:
    mcp = create_server(settings, disable_auth=disable_auth)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    routes: list[Route | Mount] = [Route("/healthz", health)]
    if not disable_auth and settings.entra is not None:
        routes.append(_protected_resource_metadata_route(settings))
    routes.append(
        Mount(
            "/",
            app=mcp.streamable_http_app(
                host=settings.listen, json_response=True, stateless_http=True
            ),
        )
    )

    return Starlette(routes=routes, lifespan=lifespan)


def _protected_resource_metadata_route(settings: Settings) -> Route:
    """Serve ``/.well-known/oauth-protected-resource`` (RFC 9728) ourselves.

    The upstream `mcp` SDK also registers a route at this path (nested under
    the streamable HTTP app mounted below), built from
    ``AuthSettings.resource_server_url``, which is a pydantic ``AnyHttpUrl``.
    That type always normalises a bare-origin URL to end in a slash (e.g.
    ``"https://host"`` becomes ``"https://host/"``) — but Entra refuses to
    register an Application ID URI that ends in a slash, so the two can
    never be made to match through the SDK's own route.

    Registering our own route at the same path, earlier in this app's route
    list, means Starlette matches ours first and the SDK's copy (still
    registered, but now unreachable) is never hit. This lets ``resource`` in
    the published metadata be exactly ``resource-server-url`` as configured,
    with no forced trailing slash.
    """
    assert settings.entra is not None
    assert settings.resource_server_url is not None
    body = json.dumps(
        {
            "resource": settings.resource_server_url,
            "authorization_servers": [settings.entra.issuer],
            "bearer_methods_supported": ["header"],
        }
    ).encode()

    async def handle(request: Request) -> Response:
        return Response(
            body,
            media_type="application/json",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    return Route(
        "/.well-known/oauth-protected-resource",
        endpoint=cors_middleware(handle, ["GET", "OPTIONS"]),
        methods=["GET", "OPTIONS"],
    )
