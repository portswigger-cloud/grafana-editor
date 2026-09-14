# SPDX-License-Identifier: MIT
from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager
from typing import Annotated, Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from grafana_editor.auth import RoleTokenVerifier, UserAccessToken
from grafana_editor.config import Settings
from grafana_editor.grafana import GrafanaClient, GrafanaError

logger = logging.getLogger(__name__)

INSTRUCTIONS = """\
Explore and query the datasources of one Grafana instance, on behalf of the \
user signed in via Microsoft Entra ID SSO.

Use this to find out what data actually exists before writing a query or a \
dashboard panel: list_datasources, then list_metrics / describe_metrics / \
list_labels / list_label_values to discover what is there, then query_instant \
or query_range to see real values.

Every datasource argument takes either a datasource uid or its display name. \
Every time argument takes an RFC 3339 timestamp, unix seconds, or a relative \
expression such as now, now-15m or now-6h; omitting them queries the last \
hour. Results are truncated when large, and say so when they are.\
"""

# Time and selector arguments repeat across most tools, so their descriptions
# live here rather than being reworded slightly differently seven times.
Datasource = Annotated[
    str,
    Field(description="The uid or the display name of the Grafana datasource."),
]
Start = Annotated[
    str | None,
    Field(
        description=(
            "Start of the window: RFC 3339, unix seconds, or relative "
            "(now-1h). Defaults to one hour before the end."
        )
    ),
]
End = Annotated[
    str | None,
    Field(
        description=(
            "End of the window: RFC 3339, unix seconds, or relative (now). "
            "Defaults to now."
        )
    ),
]
PromSelector = Annotated[
    str | None,
    Field(
        description=(
            "Optional series selector restricting the result to series that "
            "match it, e.g. '{namespace=\"grafana-editor\"}'. For Loki "
            "datasources this is a log stream selector."
        )
    ),
]


def create_server(
    settings: Settings,
    *,
    disable_auth: bool = False,
    grafana_client: GrafanaClient | None = None,
) -> MCPServer:
    mcp, _ = _build_server(
        settings, disable_auth=disable_auth, grafana_client=grafana_client
    )
    return mcp


def _build_server(
    settings: Settings,
    *,
    disable_auth: bool,
    grafana_client: GrafanaClient | None,
) -> tuple[MCPServer, GrafanaClient]:
    """Build the server and hand back the Grafana client it will use.

    ``create_app`` needs the client itself so that its lifespan can close it,
    and both entry points need to check the config in the same order: a
    server with no usable auth config is misconfigured more fundamentally
    than one that cannot reach Grafana, so that is the failure to report.
    """
    token_verifier, auth_settings = _build_auth(settings, disable_auth)
    grafana = grafana_client or _build_grafana(settings)

    mcp = MCPServer(
        "Grafana editor",
        instructions=INSTRUCTIONS,
        token_verifier=token_verifier,
        auth=auth_settings,
    )

    @mcp.tool()
    def whoami() -> dict[str, str]:
        """Get the email address of the currently signed-in user."""
        access_token = get_access_token()
        if access_token is None:
            raise ToolError("no authenticated user is associated with this request")
        if not isinstance(access_token, UserAccessToken):
            raise ToolError(
                "authentication is disabled on this server; no user is signed in"
            )
        return {"email": access_token.email}

    @mcp.tool()
    async def list_datasources() -> dict[str, Any]:
        """List the datasources configured in Grafana.

        Start here: the uid of a datasource from this list is what every
        other tool takes. A datasource whose "queryable" is false is one
        this server cannot query yet (only Prometheus-shaped backends
        such as Prometheus, Mimir and Thanos, and Loki, are supported).
        """
        datasources = await _guard(grafana.list_datasources())
        return {
            "grafana_url": grafana.base_url,
            "datasources": [ds.as_dict() for ds in datasources],
        }

    @mcp.tool()
    async def list_metrics(
        datasource: Datasource,
        selector: PromSelector = None,
        start: Start = None,
        end: End = None,
    ) -> dict[str, Any]:
        """List the metric names a Prometheus-shaped datasource holds.

        Only metrics with samples inside the time window are listed, so a
        wider window finds more. Pass a selector to narrow a large
        installation down to one workload's metrics.
        """
        return await _guard(
            grafana.list_metrics(datasource, selector=selector, start=start, end=end)
        )

    @mcp.tool()
    async def describe_metrics(
        datasource: Datasource,
        metric: Annotated[
            str | None,
            Field(
                description=(
                    "A single metric name to describe. Omit to get metadata "
                    "for every metric, which can be a lot."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the type, unit and help text a metric was exported with.

        Worth calling before building a panel: whether a metric is a counter,
        a gauge or a histogram decides whether it needs rate(), and the unit
        decides how the panel should be formatted.
        """
        return await _guard(grafana.describe_metrics(datasource, metric))

    @mcp.tool()
    async def list_labels(
        datasource: Datasource,
        selector: PromSelector = None,
        start: Start = None,
        end: End = None,
    ) -> dict[str, Any]:
        """List the label names present on a Prometheus or Loki datasource.

        With a selector, lists only the labels carried by series that match
        it, which is the quick way to learn how one metric is dimensioned.
        """
        return await _guard(
            grafana.list_labels(datasource, selector=selector, start=start, end=end)
        )

    @mcp.tool()
    async def list_label_values(
        datasource: Datasource,
        label: Annotated[
            str,
            Field(
                description=(
                    "The label name to list values for, e.g. 'namespace'. "
                    "Use '__name__' on a Prometheus datasource to list "
                    "metric names."
                )
            ),
        ],
        selector: PromSelector = None,
        start: Start = None,
        end: End = None,
    ) -> dict[str, Any]:
        """List the values one label takes on a Prometheus or Loki datasource.

        This is what fills in a dashboard template variable's options, and
        what tells you whether a label filter you are about to write will
        match anything.
        """
        return await _guard(
            grafana.list_label_values(
                datasource, label, selector=selector, start=start, end=end
            )
        )

    @mcp.tool()
    async def query_instant(
        datasource: Datasource,
        expr: Annotated[
            str,
            Field(
                description=(
                    "The query: PromQL for a Prometheus-shaped datasource, "
                    "LogQL for a Loki one."
                )
            ),
        ],
        at: Annotated[
            str | None,
            Field(
                description=(
                    "The instant to evaluate at: RFC 3339, unix seconds, or "
                    "relative (now-5m). Defaults to now."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Evaluate a query at a single instant and return the values.

        Use this to check that a query returns what you expect, and to see
        which labels come back, before putting it in a panel.
        """
        return await _guard(grafana.query_instant(datasource, expr, at=at))

    @mcp.tool()
    async def query_range(
        datasource: Datasource,
        expr: Annotated[
            str,
            Field(
                description=(
                    "The query: PromQL for a Prometheus-shaped datasource, "
                    "LogQL for a Loki one."
                )
            ),
        ],
        start: Start = None,
        end: End = None,
        step: Annotated[
            str | None,
            Field(
                description=(
                    "Resolution between points, e.g. '30s' or '5m'. Omit to "
                    "get a step that yields a couple of hundred points over "
                    "the window."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Evaluate a query over a time window and return the series.

        This is the shape a time series panel draws. The reply reports the
        step that was used, so a panel can be built with the same one.
        """
        return await _guard(
            grafana.query_range(datasource, expr, start=start, end=end, step=step)
        )

    return mcp, grafana


async def _guard[T](awaitable: Awaitable[T]) -> T:
    """Report a Grafana failure to the caller rather than as a server error.

    A rejected PromQL expression or a datasource name that does not exist is
    something the caller can fix on its next attempt, so the message Grafana
    gave has to reach it. ``ToolError`` is the one exception type MCPServer
    passes through to the client instead of replacing with a generic
    "internal error".
    """
    try:
        return await awaitable
    except GrafanaError as exc:
        raise ToolError(str(exc)) from exc


def _build_auth(
    settings: Settings, disable_auth: bool
) -> tuple[RoleTokenVerifier | None, AuthSettings | None]:
    if disable_auth:
        logger.warning("authentication disabled by --disable-auth")
        return None, None
    missing = [
        name
        for name, value in (
            ("resource-server-url", settings.resource_server_url),
            ("origin", settings.origin),
            ("at least one [[role]]", settings.roles),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"{', '.join(missing)} required in the config file (or pass --disable-auth)"
        )
    token_verifier = RoleTokenVerifier(settings.roles)
    auth_settings = AuthSettings(
        # Pass these as strings rather than pre-built AnyHttpUrl values:
        # AuthSettings sets `url_preserve_empty_path`, so it keeps a
        # path-less URL's canonical slash-free form, whereas constructing
        # AnyHttpUrl ourselves normalises "https://host" to "https://host/"
        # before the model ever sees it. The resource identifier has to match
        # the Entra Application ID URI exactly, and Entra refuses to register
        # one ending in a slash.
        issuer_url=settings.origin,
        resource_server_url=settings.resource_server_url,
        # Advertised as `scopes_supported` in the protected resource
        # metadata, so clients know to ask the authorization server for these
        # scopes rather than falling back to bare OIDC scopes, and required
        # on every request.
        required_scopes=list(settings.scopes),
        # RoleTokenVerifier already checks the token's audience against the
        # role that matched, so the RFC 8707 resource indicator check below
        # would be redundant.
        validate_token_resource=False,
    )
    return token_verifier, auth_settings


def _build_grafana(settings: Settings) -> GrafanaClient:
    if settings.grafana is None:
        raise RuntimeError(
            "a [grafana] section with url and service-account-token-path is "
            "required in the config file"
        )
    return GrafanaClient(settings.grafana)


def create_app(
    settings: Settings,
    *,
    disable_auth: bool = False,
    grafana_client: GrafanaClient | None = None,
) -> Starlette:
    mcp, grafana = _build_server(
        settings, disable_auth=disable_auth, grafana_client=grafana_client
    )

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            await grafana.aclose()

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
