# SPDX-License-Identifier: MIT
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.auth.middleware.auth_context import get_access_token
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

    return Starlette(
        routes=[
            Route("/healthz", health),
            Mount(
                "/",
                app=mcp.streamable_http_app(
                    host=settings.listen, json_response=True, stateless_http=True
                ),
            ),
        ],
        lifespan=lifespan,
    )
