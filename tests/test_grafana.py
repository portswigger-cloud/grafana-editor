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
        await client.list_labels("Tempo")

    message = str(caught.value)
    assert "'tempo'" in message
    assert "loki, prometheus" in message


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
