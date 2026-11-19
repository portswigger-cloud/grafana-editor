# SPDX-License-Identifier: MIT
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from grafana_editor.config import GrafanaSettings
from grafana_editor.grafana import (
    MAX_POINTS_PER_SERIES,
    MAX_SERIES,
    MAX_TRACE_SPANS,
    GrafanaClient,
    GrafanaError,
    TimeWindow,
    parse_duration_seconds,
    parse_time,
)

DATASOURCES = [
    {"uid": "mimir-uid", "name": "Mimir", "type": "prometheus", "isDefault": True},
    {"uid": "loki-uid", "name": "Loki", "type": "loki"},
    {"uid": "tempo-uid", "name": "Tempo", "type": "tempo"},
    {"uid": "cw-uid", "name": "CloudWatch", "type": "cloudwatch"},
]


class Recorder:
    """A stand-in Grafana that records what it was asked for."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = self.routes.get(request.url.path)
        if body is None:
            return httpx.Response(404, json={"message": f"no route {request.url.path}"})
        if isinstance(body, httpx.Response):
            return body
        return httpx.Response(200, json=body)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


def _client(tmp_path: Path, routes: dict[str, Any]) -> tuple[GrafanaClient, Recorder]:
    token = tmp_path / "token"
    token.write_text("glsa-secret\n")
    recorder = Recorder({"/api/datasources": DATASOURCES, **routes})
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder.handle))
    client = GrafanaClient(
        GrafanaSettings(
            url="https://grafana.example.com",
            service_account_token_path=str(token),
        ),
        http_client=http,
    )
    return client, recorder


def _prom(path: str) -> str:
    return f"/api/datasources/proxy/uid/mimir-uid/{path}"


def _loki(path: str) -> str:
    return f"/api/datasources/proxy/uid/loki-uid/{path}"


def _tempo(path: str) -> str:
    return f"/api/datasources/proxy/uid/tempo-uid/{path}"


def _success(data: Any) -> dict[str, Any]:
    return {"status": "success", "data": data}


pytestmark = pytest.mark.anyio


async def test_lists_datasources_and_flags_unqueryable_types(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, {})

    datasources = await client.list_datasources()

    assert [ds.as_dict() for ds in datasources] == [
        {
            "uid": "mimir-uid",
            "name": "Mimir",
            "type": "prometheus",
            "is_default": True,
            "queryable": True,
        },
        {
            "uid": "loki-uid",
            "name": "Loki",
            "type": "loki",
            "is_default": False,
            "queryable": True,
        },
        {
            "uid": "tempo-uid",
            "name": "Tempo",
            "type": "tempo",
            "is_default": False,
            "queryable": True,
        },
        {
            "uid": "cw-uid",
            "name": "CloudWatch",
            "type": "cloudwatch",
            "is_default": False,
            "queryable": False,
        },
    ]


async def test_sends_the_service_account_token(tmp_path: Path) -> None:
    client, recorder = _client(tmp_path, {})

    await client.list_datasources()

    assert recorder.last.headers["authorization"] == "Bearer glsa-secret"


async def test_rereads_the_token_when_the_file_changes(tmp_path: Path) -> None:
    client, recorder = _client(tmp_path, {})
    await client.list_datasources()

    token = tmp_path / "token"
    token.write_text("glsa-rotated")
    await client.list_datasources(refresh=True)

    assert recorder.last.headers["authorization"] == "Bearer glsa-rotated"


async def test_reports_a_missing_token_file(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, {})
    (tmp_path / "token").unlink()

    with pytest.raises(GrafanaError, match="could not read the Grafana service"):
        await client.list_datasources()


async def test_reports_an_empty_token_file(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, {})
    (tmp_path / "token").write_text("   \n")

    with pytest.raises(GrafanaError, match="is empty"):
        await client.list_datasources()


async def test_resolves_a_datasource_by_name_case_insensitively(
    tmp_path: Path,
) -> None:
    client, _ = _client(tmp_path, {})

    assert (await client.resolve_datasource("mimir")).uid == "mimir-uid"
    assert (await client.resolve_datasource("mimir-uid")).uid == "mimir-uid"


async def test_unknown_datasource_lists_what_does_exist(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, {})

    with pytest.raises(GrafanaError) as caught:
        await client.resolve_datasource("Graphite")

    message = str(caught.value)
    assert "'Graphite'" in message
    assert "Mimir (uid mimir-uid)" in message


async def test_rejects_a_datasource_of_an_unsupported_type(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, {})

    with pytest.raises(GrafanaError) as caught:
        await client.list_labels("CloudWatch")

    message = str(caught.value)
    assert "'cloudwatch'" in message
    assert "loki, prometheus, tempo" in message


async def test_lists_prometheus_metrics_with_a_selector(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {_prom("api/v1/label/__name__/values"): _success(["up", "go_goroutines"])},
    )

    result = await client.list_metrics(
        "Mimir", selector='{job="grafana"}', start="now-6h"
    )

    assert result["metrics"] == ["up", "go_goroutines"]
    assert result["total"] == 2
    assert recorder.last.url.params["match[]"] == '{job="grafana"}'
    assert recorder.last.url.params["start"].endswith("Z")


async def test_lists_labels_from_the_loki_endpoint(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path, {_loki("loki/api/v1/labels"): _success(["app", "namespace"])}
    )

    result = await client.list_labels("Loki", selector='{app="argo"}')

    assert result["labels"] == ["app", "namespace"]
    # Loki takes a stream selector as `query`, not as Prometheus' `match[]`.
    assert recorder.last.url.params["query"] == '{app="argo"}'
    assert "match[]" not in recorder.last.url.params


async def test_url_encodes_a_label_name(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path, {_prom("api/v1/label/__name__/values"): _success(["up"])}
    )

    result = await client.list_label_values("Mimir", "__name__")

    assert result["label"] == "__name__"
    assert result["values"] == ["up"]
    assert recorder.last.url.path == _prom("api/v1/label/__name__/values")


async def test_query_range_normalises_prometheus_series(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {
            _prom("api/v1/query_range"): _success(
                {
                    "resultType": "matrix",
                    "result": [
                        {
                            "metric": {"__name__": "up", "job": "grafana"},
                            "values": [[1, "1"], [2, "1"]],
                        }
                    ],
                }
            )
        },
    )

    result = await client.query_range(
        "Mimir", "up", start="2026-09-14T00:00:00Z", end="2026-09-14T01:00:00Z"
    )

    assert result["result_type"] == "matrix"
    assert result["series"] == [
        {"labels": {"__name__": "up", "job": "grafana"}, "values": [[1, "1"], [2, "1"]]}
    ]
    assert result["start"] == "2026-09-14T00:00:00Z"
    assert result["end"] == "2026-09-14T01:00:00Z"
    # An hour at ~200 points snaps to the nearest step a human would pick.
    assert result["step"] == "30s"
    assert recorder.last.url.params["step"] == "30s"


async def test_query_range_normalises_loki_streams(tmp_path: Path) -> None:
    client, _ = _client(
        tmp_path,
        {
            _loki("loki/api/v1/query_range"): _success(
                {
                    "resultType": "streams",
                    "result": [
                        {"stream": {"app": "argo"}, "values": [["1757800000", "hello"]]}
                    ],
                }
            )
        },
    )

    result = await client.query_range("Loki", '{app="argo"}')

    # A Loki stream's labels arrive under "stream" but come back as "labels",
    # so a caller does not need a branch per datasource type.
    assert result["series"] == [
        {"labels": {"app": "argo"}, "values": [["1757800000", "hello"]]}
    ]


async def test_query_instant_keeps_the_single_value(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {
            _prom("api/v1/query"): _success(
                {
                    "resultType": "vector",
                    "result": [{"metric": {"job": "grafana"}, "value": [1, "7"]}],
                }
            )
        },
    )

    result = await client.query_instant("Mimir", "up", at="2026-09-14T12:00:00Z")

    assert result["series"] == [{"labels": {"job": "grafana"}, "value": [1, "7"]}]
    assert recorder.last.url.params["time"] == "2026-09-14T12:00:00Z"


async def test_truncates_a_result_with_too_many_series(tmp_path: Path) -> None:
    series = [
        {"metric": {"i": str(i)}, "values": [[1, "1"]]} for i in range(MAX_SERIES + 10)
    ]
    client, _ = _client(
        tmp_path,
        {
            _prom("api/v1/query_range"): _success(
                {"resultType": "matrix", "result": series}
            )
        },
    )

    result = await client.query_range("Mimir", "up")

    assert len(result["series"]) == MAX_SERIES
    assert result["series_count"] == MAX_SERIES + 10
    assert str(MAX_SERIES + 10) in result["truncated"]


async def test_keeps_the_most_recent_points_when_truncating(tmp_path: Path) -> None:
    points = [[i, str(i)] for i in range(MAX_POINTS_PER_SERIES + 5)]
    client, _ = _client(
        tmp_path,
        {
            _prom("api/v1/query_range"): _success(
                {"resultType": "matrix", "result": [{"metric": {}, "values": points}]}
            )
        },
    )

    result = await client.query_range("Mimir", "up")

    values = result["series"][0]["values"]
    assert len(values) == MAX_POINTS_PER_SERIES
    assert values[-1] == [MAX_POINTS_PER_SERIES + 4, str(MAX_POINTS_PER_SERIES + 4)]
    assert "coarser step" in result["truncated"]


async def test_surfaces_a_promql_error_from_the_datasource(tmp_path: Path) -> None:
    client, _ = _client(
        tmp_path,
        {
            _prom("api/v1/query_range"): httpx.Response(
                400,
                json={
                    "status": "error",
                    "errorType": "bad_data",
                    "error": 'parse error: unexpected "("',
                },
            )
        },
    )

    with pytest.raises(GrafanaError) as caught:
        await client.query_range("Mimir", "up(")

    assert 'parse error: unexpected "("' in str(caught.value)


async def test_surfaces_a_grafana_error_message(tmp_path: Path) -> None:
    client, _ = _client(
        tmp_path,
        {_prom("api/v1/query"): httpx.Response(403, json={"message": "Access denied"})},
    )

    with pytest.raises(GrafanaError) as caught:
        await client.query_instant("Mimir", "up")

    message = str(caught.value)
    assert "403" in message
    assert "Access denied" in message


async def test_reports_a_non_json_response(tmp_path: Path) -> None:
    client, _ = _client(
        tmp_path,
        {
            _prom("api/v1/query"): httpx.Response(
                200, text="<html>gateway timeout</html>"
            )
        },
    )

    with pytest.raises(GrafanaError, match="not JSON"):
        await client.query_instant("Mimir", "up")


async def test_describe_metrics_asks_for_one_metric(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {
            _prom("api/v1/metadata"): _success(
                {"up": [{"type": "gauge", "help": "1 if up", "unit": ""}]}
            )
        },
    )

    result = await client.describe_metrics("Mimir", "up")

    assert result["metrics"]["up"][0]["type"] == "gauge"
    assert recorder.last.url.params["metric"] == "up"


async def test_a_datasource_added_since_the_cache_filled_is_found(
    tmp_path: Path,
) -> None:
    client, recorder = _client(tmp_path, {})
    await client.list_datasources()
    recorder.routes["/api/datasources"] = [
        *DATASOURCES,
        {"uid": "new-uid", "name": "New", "type": "prometheus"},
    ]

    # The cache is still warm, so this only succeeds if a miss triggers a refetch.
    assert (await client.resolve_datasource("New")).uid == "new-uid"


async def test_lists_tempo_attributes_as_traceql_spells_them(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {
            _tempo("api/v2/search/tags"): {
                "scopes": [
                    {"name": "resource", "tags": ["service.name"]},
                    {"name": "span", "tags": ["http.route", "http.method"]},
                    {"name": "intrinsic", "tags": ["duration", "name"]},
                ]
            }
        },
    )

    result = await client.list_labels(
        "Tempo",
        selector='{resource.service.name="api"}',
        start="2026-09-14T00:00:00Z",
        end="2026-09-14T01:00:00Z",
    )

    assert result["labels"] == [
        "resource.service.name",
        "span.http.route",
        "span.http.method",
        "duration",
        "name",
    ]
    params = recorder.last.url.params
    assert params["q"] == '{resource.service.name="api"}'
    # Tempo's tag endpoints only read unix seconds.
    assert params["start"] == "1789344000"
    assert params["end"] == "1789347600"


async def test_lists_tempo_attribute_values(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {
            _tempo("api/v2/search/tag/resource.service.name/values"): {
                "tagValues": [
                    {"type": "string", "value": "api"},
                    {"type": "string", "value": "worker"},
                ]
            }
        },
    )

    result = await client.list_label_values("Tempo", "resource.service.name")

    assert result["values"] == ["api", "worker"]
    assert result["label"] == "resource.service.name"
    assert "q" not in recorder.last.url.params


async def test_query_range_runs_traceql_metrics_as_a_matrix(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {
            _tempo("api/metrics/query_range"): {
                "series": [
                    {
                        "labels": [
                            {
                                "key": "span.http.route",
                                "value": {"stringValue": "/login"},
                            }
                        ],
                        "samples": [
                            {"timestampMs": "1757808000000", "value": 2.5},
                            {"timestampMs": "1757808030000"},
                        ],
                    }
                ]
            }
        },
    )

    expr = '{resource.service.name="api"} | rate() by (span.http.route)'
    result = await client.query_range(
        "Tempo", expr, start="2026-09-14T00:00:00Z", end="2026-09-14T01:00:00Z"
    )

    assert result["result_type"] == "matrix"
    # A sample Tempo leaves the value out of is a zero, as protobuf JSON omits it.
    assert result["series"] == [
        {
            "labels": {"span.http.route": "/login"},
            "values": [[1757808000.0, "2.5"], [1757808030.0, "0"]],
        }
    ]
    assert result["step"] == "30s"
    params = recorder.last.url.params
    assert params["q"] == expr
    assert params["step"] == "30s"
    assert params["start"] == "1789344000"
    assert "query" not in params


async def test_query_instant_is_refused_on_tempo(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, {})

    with pytest.raises(GrafanaError, match="'tempo'"):
        await client.query_instant("Tempo", "{} | rate()")


async def test_searches_traces_with_traceql(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {
            _tempo("api/search"): {
                "traces": [
                    {
                        "traceID": "2f3e0cee77ae5dc9c17ade3689eb2e54",
                        "rootServiceName": "api",
                        "rootTraceName": "GET /login",
                        "startTimeUnixNano": "1757808000123000000",
                        "durationMs": 812,
                        "spanSets": [
                            {
                                "matched": 7,
                                "spans": [
                                    {
                                        "spanID": "563d623c76514f8e",
                                        "name": "SELECT users",
                                        "startTimeUnixNano": "1757808000200000000",
                                        "durationNanos": "640000000",
                                        "attributes": [
                                            {
                                                "key": "db.system",
                                                "value": {"stringValue": "postgresql"},
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        },
    )

    result = await client.search_traces(
        "Tempo", "{status=error}", start="now-6h", limit=5, spans_per_span_set=1
    )

    assert result["trace_count"] == 1
    assert result["traces"] == [
        {
            "trace_id": "2f3e0cee77ae5dc9c17ade3689eb2e54",
            "root_service": "api",
            "root_name": "GET /login",
            "start": "2025-09-14T00:00:00.123Z",
            "duration_ms": 812,
            "span_sets": [
                {
                    "matched": 7,
                    "spans": [
                        {
                            "span_id": "563d623c76514f8e",
                            "name": "SELECT users",
                            "start": "2025-09-14T00:00:00.200Z",
                            "duration_ms": 640.0,
                            "attributes": {"db.system": "postgresql"},
                        }
                    ],
                }
            ],
        }
    ]
    assert "truncated" not in result
    params = recorder.last.url.params
    assert params["q"] == "{status=error}"
    assert params["limit"] == "5"
    assert params["spss"] == "1"


async def test_a_full_trace_search_says_there_may_be_more(tmp_path: Path) -> None:
    client, recorder = _client(
        tmp_path,
        {_tempo("api/search"): {"traces": [{"traceID": "ab"}, {"traceID": "cd"}]}},
    )

    result = await client.search_traces("Tempo", "{}", limit=500)

    assert recorder.last.url.params["limit"] == "100"
    assert "capped at 100" in result["truncated"]

    result = await client.search_traces("Tempo", "{}", limit=2)

    assert "more may match" in result["truncated"]


async def test_get_trace_flattens_otlp_spans_in_start_order(tmp_path: Path) -> None:
    trace_id = "2f3e0cee77ae5dc9c17ade3689eb2e54"
    client, recorder = _client(
        tmp_path,
        {
            _tempo(f"api/v2/traces/{trace_id}"): {
                "trace": {
                    "resourceSpans": [
                        {
                            "resource": {
                                "attributes": [
                                    {
                                        "key": "service.name",
                                        "value": {"stringValue": "db-proxy"},
                                    }
                                ]
                            },
                            "scopeSpans": [
                                {
                                    "spans": [
                                        {
                                            # Base64, as Tempo's OTLP JSON has it.
                                            "spanId": "AAAAAAAAAAI=",
                                            "parentSpanId": "AAAAAAAAAAE=",
                                            "name": "query",
                                            "kind": "SPAN_KIND_CLIENT",
                                            "startTimeUnixNano": "2000000000",
                                            "endTimeUnixNano": "2500000000",
                                            "status": {
                                                "code": "STATUS_CODE_ERROR",
                                                "message": "timeout",
                                            },
                                            "attributes": [
                                                {
                                                    "key": "db.rows",
                                                    "value": {"intValue": "42"},
                                                }
                                            ],
                                            "events": [
                                                {
                                                    "name": "exception",
                                                    "attributes": [
                                                        {
                                                            "key": "exception.type",
                                                            "value": {
                                                                "stringValue": "Timeout"
                                                            },
                                                        }
                                                    ],
                                                }
                                            ],
                                        }
                                    ]
                                }
                            ],
                        },
                        {
                            "resource": {
                                "attributes": [
                                    {
                                        "key": "service.name",
                                        "value": {"stringValue": "api"},
                                    }
                                ]
                            },
                            "scopeSpans": [
                                {
                                    "spans": [
                                        {
                                            "spanId": "AAAAAAAAAAE=",
                                            "name": "GET /login",
                                            "kind": 2,
                                            "startTimeUnixNano": "1000000000",
                                            "endTimeUnixNano": "3000000000",
                                        }
                                    ]
                                }
                            ],
                        },
                    ]
                }
            }
        },
    )

    result = await client.get_trace("Tempo", trace_id.upper())

    assert result["trace_id"] == trace_id
    assert result["span_count"] == 2
    assert result["services"] == ["api", "db-proxy"]
    assert result["duration_ms"] == 2000.0
    root, child = result["spans"]
    assert root == {
        "span_id": "0000000000000001",
        "parent_span_id": None,
        "name": "GET /login",
        "service": "api",
        "kind": "server",
        "start": "1970-01-01T00:00:01.000Z",
        "duration_ms": 2000.0,
        "status": "unset",
        "attributes": {},
    }
    assert child["parent_span_id"] == "0000000000000001"
    assert child["kind"] == "client"
    assert child["status"] == "error"
    assert child["status_message"] == "timeout"
    assert child["attributes"] == {"db.rows": 42}
    assert child["events"] == [
        {"name": "exception", "attributes": {"exception.type": "Timeout"}}
    ]
    # No window was given, so none is sent: a default one would miss old traces.
    assert "start" not in recorder.last.url.params


async def test_get_trace_truncates_a_huge_trace(tmp_path: Path) -> None:
    spans = [
        {"spanId": f"{i:016x}", "startTimeUnixNano": str(i), "endTimeUnixNano": str(i)}
        for i in range(MAX_TRACE_SPANS + 3)
    ]
    client, _ = _client(
        tmp_path,
        {
            _tempo("api/v2/traces/ab"): {
                "trace": {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
            }
        },
    )

    result = await client.get_trace("Tempo", "ab")

    assert result["span_count"] == MAX_TRACE_SPANS + 3
    assert len(result["spans"]) == MAX_TRACE_SPANS
    assert str(MAX_TRACE_SPANS + 3) in result["truncated"]


async def test_get_trace_rejects_something_that_is_not_a_trace_id(
    tmp_path: Path,
) -> None:
    client, recorder = _client(tmp_path, {})

    with pytest.raises(GrafanaError, match="not a trace id"):
        await client.get_trace("Tempo", "../../api/admin")

    assert all("traces" not in r.url.path for r in recorder.requests)


async def test_trace_search_needs_a_tempo_datasource(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, {})

    with pytest.raises(GrafanaError, match="needs one of tempo"):
        await client.search_traces("Mimir", "{}")


def test_parse_time_accepts_the_three_forms() -> None:
    assert parse_time("2026-09-14T12:00:00Z", default_to=_never) == datetime(
        2026, 9, 14, 12, tzinfo=UTC
    )
    assert parse_time("1757800000", default_to=_never) == datetime.fromtimestamp(
        1757800000, UTC
    )

    relative = parse_time("now-2h", default_to=_never)
    assert timedelta(hours=2) - (datetime.now(UTC) - relative) < timedelta(seconds=5)


def test_parse_time_names_what_it_expected_and_what_it_got() -> None:
    with pytest.raises(GrafanaError) as caught:
        parse_time("last tuesday", default_to=_never)

    message = str(caught.value)
    assert "'last tuesday'" in message
    assert "RFC 3339" in message
    assert "now-15m" in message


def test_an_empty_window_is_rejected() -> None:
    with pytest.raises(GrafanaError, match="the time window is empty"):
        TimeWindow.parse("2026-09-14T12:00:00Z", "2026-09-14T11:00:00Z")


@pytest.mark.parametrize(
    ("value", "seconds"),
    [("30", 30.0), ("30s", 30.0), ("5m", 300.0), ("2h", 7200.0), ("500ms", 0.5)],
)
def test_parse_duration(value: str, seconds: float) -> None:
    assert parse_duration_seconds(value) == seconds


@pytest.mark.parametrize("value", ["", "0s", "-5m", "soon", "5 fortnights"])
def test_parse_duration_rejects_nonsense(value: str) -> None:
    with pytest.raises(GrafanaError):
        parse_duration_seconds(value)


@pytest.mark.parametrize(
    ("span", "step"),
    [
        (timedelta(minutes=5), 5.0),
        (timedelta(hours=1), 30.0),
        (timedelta(days=1), 600.0),
        (timedelta(days=90), 43200.0),
    ],
)
def test_auto_step_snaps_to_a_round_number(span: timedelta, step: float) -> None:
    end = datetime(2026, 9, 14, 12, tzinfo=UTC)

    assert TimeWindow(start=end - span, end=end).auto_step_seconds() == step


def _never() -> datetime:
    raise AssertionError("the default should not have been needed")
