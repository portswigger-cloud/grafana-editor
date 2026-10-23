# SPDX-License-Identifier: MIT
from __future__ import annotations

import logging
from pathlib import Path

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import SpanKind
from starlette.testclient import TestClient

from grafana_editor.config import GrafanaSettings, Settings, TracesSettings
from grafana_editor.grafana import GrafanaClient
from grafana_editor.server import create_app, create_server


@pytest.fixture(scope="module")
def exporter() -> InMemorySpanExporter:
    # The global provider can be set once per process, so every test in this
    # module shares it and clears what it recorded.
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


@pytest.fixture
def spans(exporter: InMemorySpanExporter) -> InMemorySpanExporter:
    exporter.clear()
    return exporter


def _grafana(tmp_path: Path) -> GrafanaSettings:
    token = tmp_path / "token"
    token.write_text("glsa-test-token")
    return GrafanaSettings(
        url="https://grafana.example.com", service_account_token_path=str(token)
    )


def test_every_request_is_logged_and_traced(
    tmp_path: Path, spans: InMemorySpanExporter, caplog: pytest.LogCaptureFixture
) -> None:
    app = create_app(Settings(grafana=_grafana(tmp_path)), disable_auth=True)

    with (
        caplog.at_level(logging.INFO, logger="grafana_editor.access"),
        TestClient(app) as client,
    ):
        client.get("/no-such-path", headers={"user-agent": "probe/1"})

    [record] = [r for r in caplog.records if r.name == "grafana_editor.access"]
    assert '"GET /no-such-path" 404' in record.getMessage()
    assert '"probe/1"' in record.getMessage()
    [span] = [s for s in spans.get_finished_spans() if s.kind == SpanKind.SERVER]
    assert span.name == "GET /no-such-path"
    assert span.attributes is not None
    assert span.attributes["http.response.status_code"] == 404


def test_an_excluded_path_is_logged_but_emits_no_spans(
    tmp_path: Path, spans: InMemorySpanExporter, caplog: pytest.LogCaptureFixture
) -> None:
    """Excluding a path silences everything beneath it, not just the server
    span: the tool span and the Grafana request span are dropped as well."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    settings = Settings(
        grafana=_grafana(tmp_path),
        traces=TracesSettings(
            endpoint="http://otel:4317", excluded_paths=frozenset({"/mcp"})
        ),
    )
    app = create_app(
        settings,
        disable_auth=True,
        grafana_client=GrafanaClient(
            _grafana(tmp_path),
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ),
    )

    with (
        caplog.at_level(logging.INFO, logger="grafana_editor.access"),
        TestClient(app) as client,
    ):
        response = client.post(
            "/mcp",
            headers={"accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_datasources", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert response.json()["result"]["structuredContent"]["datasources"] == []
    assert any('"POST /mcp" 200' in r.getMessage() for r in caplog.records)
    assert spans.get_finished_spans() == ()


def test_health_probes_are_logged_at_debug(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = create_app(Settings(grafana=_grafana(tmp_path)), disable_auth=True)

    with (
        caplog.at_level(logging.DEBUG, logger="grafana_editor.access"),
        TestClient(app) as client,
    ):
        client.get("/healthz")

    [record] = [r for r in caplog.records if r.name == "grafana_editor.access"]
    assert record.levelno == logging.DEBUG


@pytest.mark.anyio
async def test_a_tool_call_traces_the_grafana_request_inside_it(
    tmp_path: Path, spans: InMemorySpanExporter
) -> None:
    seen_traceparent: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_traceparent.append(request.headers.get("traceparent"))
        if request.url.path == "/api/datasources":
            return httpx.Response(
                200, json=[{"uid": "mimir-uid", "name": "Mimir", "type": "prometheus"}]
            )
        return httpx.Response(200, json={"status": "success", "data": []})

    server = create_server(
        Settings(grafana=_grafana(tmp_path)),
        disable_auth=True,
        grafana_client=GrafanaClient(
            _grafana(tmp_path),
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ),
    )

    await server.call_tool("list_metrics", {"datasource": "Mimir"})

    finished = spans.get_finished_spans()
    [tool] = [span for span in finished if span.name == "tool list_metrics"]
    requests = [span for span in finished if span.name == "grafana GET"]
    assert tool.attributes is not None
    assert tool.attributes["tool.argument.datasource"] == "Mimir"
    assert len(requests) == 2
    assert all(r.parent and r.parent.span_id == tool.context.span_id for r in requests)
    # Grafana sees the trace context too, so its own spans can join the trace.
    assert seen_traceparent[0] is not None
