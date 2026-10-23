# SPDX-License-Identifier: MIT
from __future__ import annotations

import functools
import inspect
import logging
import time
from collections.abc import Callable
from typing import Any

from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SERVICE_NAME = "grafana-editor"

logger = logging.getLogger(__name__)
access_logger = logging.getLogger("grafana_editor.access")

# Until `configure_tracing` installs a provider, this hands out no-op spans, so
# instrumented code needs no "is tracing on" checks of its own.
tracer = trace.get_tracer("grafana_editor")

# The parent for requests that should not be traced. The default sampler
# follows its parent's sampled flag, so every span started beneath this one is
# dropped too; it only needs valid ids for the sampler to look at that flag.
_UNSAMPLED_SPAN = trace.NonRecordingSpan(
    trace.SpanContext(
        trace_id=1, span_id=1, is_remote=False, trace_flags=trace.TraceFlags(0)
    )
)


def configure_tracing(endpoint: str) -> TracerProvider:
    """Export spans to the OTLP gRPC collector at ``endpoint``.

    An ``http://`` endpoint is dialled without TLS, an ``https://`` one with
    it. The caller shuts the returned provider down on exit, which is what
    flushes the spans still waiting in the batch.
    """
    provider = TracerProvider(resource=Resource.create({"service.name": SERVICE_NAME}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    logger.info("exporting traces to %s", endpoint)
    return provider


class RequestLoggingMiddleware:
    """Log every HTTP request once it completes, and trace it as a server span.

    Written as plain ASGI rather than with Starlette's ``BaseHTTPMiddleware``,
    which buffers in ways that interfere with streamed MCP responses. Health
    probes are logged at DEBUG so that they do not drown everything else.

    A request to one of ``excluded_paths`` is still logged but runs under an
    unsampled parent, so neither it nor anything it calls emits a span.
    """

    def __init__(
        self, app: ASGIApp, excluded_paths: frozenset[str] = frozenset()
    ) -> None:
        self.app = app
        self.excluded_paths = excluded_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope["method"]
        path = scope["path"]
        headers = {
            k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]
        }
        client = scope.get("client")
        client_addr = f"{client[0]}:{client[1]}" if client else "-"
        status = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        start = time.monotonic()
        span_context = (
            trace.use_span(_UNSAMPLED_SPAN)
            if path in self.excluded_paths
            else tracer.start_as_current_span(
                f"{method} {path}",
                context=propagate.extract(headers),
                kind=SpanKind.SERVER,
                attributes={
                    "http.request.method": method,
                    "url.path": path,
                    "client.address": client[0] if client else "",
                    "user_agent.original": headers.get("user-agent", ""),
                },
            )
        )
        with span_context as span:
            try:
                await self.app(scope, receive, send_wrapper)
            except Exception:
                status = status or 500
                raise
            finally:
                elapsed_ms = (time.monotonic() - start) * 1000
                span.set_attribute("http.response.status_code", status)
                if status >= 500:
                    span.set_status(Status(StatusCode.ERROR))
                access_logger.log(
                    logging.DEBUG if path == "/healthz" else logging.INFO,
                    '%s "%s %s" %d %.1fms "%s"',
                    client_addr,
                    method,
                    path,
                    status,
                    elapsed_ms,
                    headers.get("user-agent", "-"),
                )


def traced_tool[F: Callable[..., Any]](fn: F) -> F:
    """Run an MCP tool function inside a span named after the tool.

    ``functools.wraps`` carries the signature and annotations across, which
    is what MCPServer reads the tool's input schema from.
    """
    name = f"tool {getattr(fn, '__name__', fn)}"

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            logger.info("%s called", name)
            with tracer.start_as_current_span(name) as span:
                _set_arguments(span, kwargs)
                return await fn(*args, **kwargs)

        return async_wrapper  # ty: ignore[invalid-return-type]

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        logger.info("%s called", name)
        with tracer.start_as_current_span(name) as span:
            _set_arguments(span, kwargs)
            return fn(*args, **kwargs)

    return wrapper  # ty: ignore[invalid-return-type]


def _set_arguments(span: trace.Span, kwargs: dict[str, Any]) -> None:
    # Dashboard bodies can be large; their size says enough in a trace.
    for key, value in kwargs.items():
        if isinstance(value, str | int | float | bool):
            span.set_attribute(f"tool.argument.{key}", value)
        elif value is not None:
            span.set_attribute(f"tool.argument.{key}.size", len(repr(value)))
