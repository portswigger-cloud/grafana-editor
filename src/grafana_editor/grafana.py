# SPDX-License-Identifier: MIT
"""A thin, opinionated client for the bits of Grafana this server exposes.

Two things happen here that callers would otherwise have to do themselves,
and which are the whole point of putting a server in front of the Grafana
API rather than handing out a token:

* A datasource can be named by uid *or* by its display name, and the
  difference between a Prometheus-shaped backend (Prometheus, Mimir,
  Thanos) and a Loki one is resolved from the datasource's own type rather
  than asked of the caller. The caller says "list the labels on 'Mimir'".
* Times are accepted as RFC 3339, unix seconds, or ``now-1h``, and a range
  query with no step gets one that yields a sensible number of points.

Everything reaches the backends through Grafana's datasource proxy, so the
service account token is the only credential involved and Grafana's own
access control still applies.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from grafana_editor.config import GrafanaSettings

logger = logging.getLogger(__name__)

PROMETHEUS = "prometheus"
LOKI = "loki"

# Grafana reports a Mimir or Thanos backend as plain "prometheus"; the
# AWS-managed variant ships under its own plugin id but speaks the same API.
DATASOURCE_FLAVOURS: dict[str, str] = {
    "prometheus": PROMETHEUS,
    "grafana-amazonprometheus-datasource": PROMETHEUS,
    "loki": LOKI,
}

# Query results are shaped for a model's context window rather than for a
# browser: a range query over a wide window can otherwise run to megabytes
# of JSON, most of it redundant. Truncation is always reported in the
# result, never silent.
MAX_SERIES = 50
MAX_POINTS_PER_SERIES = 500
MAX_LIST_ITEMS = 2000

DEFAULT_TIMEOUT_SECONDS = 30.0
DATASOURCE_CACHE_SECONDS = 60.0
RANGE_QUERY_TARGET_POINTS = 200

# Steps a human would pick, so an auto-chosen step reads as deliberate
# rather than as an artefact of dividing the window by 200.
_NICE_STEPS_SECONDS = (
    1, 5, 10, 15, 30,
    60, 120, 300, 600, 900, 1800,
    3600, 7200, 10800, 21600, 43200,
    86400, 172800, 604800,
)  # fmt: skip

_RELATIVE_TIME = re.compile(r"^now(?:-(\d+)([smhdw]))?$", re.IGNORECASE)
_TIME_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

_DURATION = re.compile(r"^(\d+(?:\.\d+)?)(ms|s|m|h|d|w)?$", re.IGNORECASE)


class GrafanaError(Exception):
    """A Grafana or datasource API call could not be completed."""


@dataclass(frozen=True)
class Datasource:
    uid: str
    name: str
    type: str
    is_default: bool

    @property
    def flavour(self) -> str | None:
        """Which query API this datasource speaks, or None if unsupported."""
        return DATASOURCE_FLAVOURS.get(self.type)

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "name": self.name,
            "type": self.type,
            "is_default": self.is_default,
            "queryable": self.flavour is not None,
        }


class _TokenFile:
    """The service account token, re-read whenever the file changes.

    Kubernetes updates a mounted secret in place when it rotates, so the
    token cannot be read once at startup and kept forever. Re-reading it for
    every API call would be a file read per call for a value that changes
    about once a quarter, so the read is gated on the file's size and mtime,
    which only costs a stat.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._stamp: tuple[int, int] | None = None
        self._token = ""

    def read(self) -> str:
        try:
            stat = self._path.stat()
            stamp = (stat.st_mtime_ns, stat.st_size)
            if stamp != self._stamp:
                token = self._path.read_text(encoding="utf-8").strip()
                self._token = token
                self._stamp = stamp
        except OSError as exc:
            raise GrafanaError(
                f"could not read the Grafana service account token from "
                f"'{self._path}': {exc}"
            ) from exc
        if not self._token:
            raise GrafanaError(
                f"the Grafana service account token file '{self._path}' is empty"
            )
        return self._token


class GrafanaClient:
    """Calls the Grafana HTTP API as a single service account."""

    def __init__(
        self,
        settings: GrafanaSettings,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = settings.url
        self._token = _TokenFile(settings.service_account_token_path)
        self._http = http_client or httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT_SECONDS, follow_redirects=False
        )
        self._datasources: list[Datasource] | None = None
        self._datasources_expire_at = 0.0

    @property
    def base_url(self) -> str:
        return self._base_url

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- Grafana's own API ------------------------------------------------

    async def list_datasources(self, *, refresh: bool = False) -> list[Datasource]:
        if (
            not refresh
            and self._datasources is not None
            and time.monotonic() < self._datasources_expire_at
        ):
            return self._datasources
        payload = await self._api_request("GET", "/api/datasources")
        if not isinstance(payload, list):
            raise GrafanaError(
                "expected /api/datasources to return a list of datasources, got "
                f"{type(payload).__name__}"
            )
        datasources = [
            Datasource(
                uid=str(item.get("uid", "")),
                name=str(item.get("name", "")),
                type=str(item.get("type", "")),
                is_default=bool(item.get("isDefault", False)),
            )
            for item in payload
            if isinstance(item, dict)
        ]
        self._datasources = datasources
        self._datasources_expire_at = time.monotonic() + DATASOURCE_CACHE_SECONDS
        return datasources

    async def resolve_datasource(self, reference: str) -> Datasource:
        """Find a datasource by uid, or failing that by display name.

        A model that has just read a dashboard is as likely to be holding a
        datasource's name as its uid, and telling the two apart is this
        server's job rather than the caller's.
        """
        found = _match_datasource(await self.list_datasources(), reference)
        if found is not None:
            return found
        # A datasource created since the cache was filled is worth one
        # refetch before telling the caller it does not exist.
        fresh = await self.list_datasources(refresh=True)
        found = _match_datasource(fresh, reference)
        if found is not None:
            return found
        known = ", ".join(f"{ds.name} (uid {ds.uid})" for ds in fresh) or "none"
        raise GrafanaError(
            f"no datasource has the uid or name '{reference}'; Grafana has: {known}"
        )

    async def require_flavour(self, reference: str, *flavours: str) -> Datasource:
        datasource = await self.resolve_datasource(reference)
        if datasource.flavour not in flavours:
            raise GrafanaError(
                f"datasource '{datasource.name}' (uid {datasource.uid}) is of type "
                f"'{datasource.type}', and this call needs one of "
                f"{', '.join(sorted(flavours))}"
            )
        return datasource

    # -- Prometheus and Loki, through the datasource proxy ----------------

    async def list_metrics(
        self,
        datasource: str,
        *,
        selector: str | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, PROMETHEUS)
        window = TimeWindow.parse(start, end)
        params: dict[str, Any] = window.as_prometheus_params()
        if selector:
            params["match[]"] = selector
        payload = await self._datasource_request(
            source, "api/v1/label/__name__/values", params=params
        )
        return _string_list_result(source, _unwrap(payload), key="metrics")

    async def describe_metrics(
        self, datasource: str, metric: str | None = None
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, PROMETHEUS)
        params = {"metric": metric} if metric else {}
        payload = await self._datasource_request(
            source, "api/v1/metadata", params=params
        )
        data = _unwrap(payload)
        if not isinstance(data, dict):
            raise GrafanaError(
                f"expected metric metadata to be an object, got {type(data).__name__}"
            )
        return {
            "datasource": source.as_dict(),
            "metrics": {
                name: entries for name, entries in list(data.items())[:MAX_LIST_ITEMS]
            },
        }

    async def list_labels(
        self,
        datasource: str,
        *,
        selector: str | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, PROMETHEUS, LOKI)
        window = TimeWindow.parse(start, end)
        if source.flavour == PROMETHEUS:
            params = window.as_prometheus_params()
            if selector:
                params["match[]"] = selector
            path = "api/v1/labels"
        else:
            params = window.as_loki_params()
            if selector:
                params["query"] = selector
            path = "loki/api/v1/labels"
        payload = await self._datasource_request(source, path, params=params)
        return _string_list_result(source, _unwrap(payload), key="labels")

    async def list_label_values(
        self,
        datasource: str,
        label: str,
        *,
        selector: str | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, PROMETHEUS, LOKI)
        window = TimeWindow.parse(start, end)
        quoted = quote(label, safe="")
        if source.flavour == PROMETHEUS:
            params = window.as_prometheus_params()
            if selector:
                params["match[]"] = selector
            path = f"api/v1/label/{quoted}/values"
        else:
            params = window.as_loki_params()
            if selector:
                params["query"] = selector
            path = f"loki/api/v1/label/{quoted}/values"
        payload = await self._datasource_request(source, path, params=params)
        result = _string_list_result(source, _unwrap(payload), key="values")
        result["label"] = label
        return result

    async def query_instant(
        self,
        datasource: str,
        expr: str,
        *,
        at: str | None = None,
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, PROMETHEUS, LOKI)
        moment = parse_time(at, default_to=_now)
        params: dict[str, Any] = {
            "query": expr,
            "time": _rfc3339(moment),
        }
        if source.flavour == LOKI:
            params["limit"] = MAX_SERIES
            path = "loki/api/v1/query"
        else:
            path = "api/v1/query"
        payload = await self._datasource_request(source, path, params=params)
        return _query_result(source, expr, _unwrap(payload))

    async def query_range(
        self,
        datasource: str,
        expr: str,
        *,
        start: str | None = None,
        end: str | None = None,
        step: str | None = None,
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, PROMETHEUS, LOKI)
        window = TimeWindow.parse(start, end)
        step_seconds = (
            parse_duration_seconds(step) if step else window.auto_step_seconds()
        )
        params: dict[str, Any] = {
            "query": expr,
            "start": _rfc3339(window.start),
            "end": _rfc3339(window.end),
            "step": _step_string(step_seconds),
        }
        if source.flavour == LOKI:
            params["limit"] = MAX_SERIES
            path = "loki/api/v1/query_range"
        else:
            path = "api/v1/query_range"
        payload = await self._datasource_request(source, path, params=params)
        result = _query_result(source, expr, _unwrap(payload))
        result["start"] = _rfc3339(window.start)
        result["end"] = _rfc3339(window.end)
        result["step"] = params["step"]
        return result

    # -- transport --------------------------------------------------------

    async def _datasource_request(
        self, datasource: Datasource, path: str, *, params: dict[str, Any]
    ) -> Any:
        return await self._api_request(
            "GET",
            f"/api/datasources/proxy/uid/{datasource.uid}/{path}",
            params=params,
        )

    async def _api_request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None
    ) -> Any:
        url = f"{self._base_url}{path}"
        try:
            response = await self._http.request(
                method,
                url,
                params=params,
                headers={
                    "Authorization": f"Bearer {self._token.read()}",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise GrafanaError(f"{method} {path} on Grafana failed: {exc}") from exc
        if response.status_code >= 400:
            raise GrafanaError(
                f"{method} {path} on Grafana returned "
                f"{response.status_code}: {_error_detail(response)}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise GrafanaError(
                f"{method} {path} on Grafana returned a body that is not JSON "
                f"({response.headers.get('content-type', 'no content-type')}): {exc}"
            ) from exc


def _match_datasource(
    datasources: list[Datasource], reference: str
) -> Datasource | None:
    for datasource in datasources:
        if datasource.uid == reference:
            return datasource
    folded = reference.casefold()
    named = [ds for ds in datasources if ds.name.casefold() == folded]
    return named[0] if len(named) == 1 else None


def _error_detail(response: httpx.Response) -> str:
    """Pull the most specific message out of an error response.

    Grafana reports its own errors as ``{"message": ...}``, while a
    Prometheus or Loki error passed through the datasource proxy arrives as
    ``{"error": ..., "errorType": ...}``. Either is far more use to the
    caller than the status code alone.
    """
    try:
        payload = response.json()
    except ValueError:
        return _truncate(response.text.strip() or "no response body")
    if isinstance(payload, dict):
        for key in ("error", "message"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return _truncate(value.strip())
    return _truncate(str(payload))


def _truncate(text: str, limit: int = 500) -> str:
    return text if len(text) <= limit else f"{text[:limit]}... (truncated)"


def _unwrap(payload: Any) -> Any:
    """Take the ``data`` out of a Prometheus- or Loki-shaped envelope."""
    if not isinstance(payload, dict):
        raise GrafanaError(
            f"expected the datasource to return an object, got {type(payload).__name__}"
        )
    status = payload.get("status")
    if status != "success":
        detail = payload.get("error") or payload.get("errorType") or status
        raise GrafanaError(f"the datasource did not accept the request: {detail}")
    if "data" not in payload:
        raise GrafanaError("the datasource returned a success response with no data")
    return payload["data"]


def _string_list_result(
    datasource: Datasource, data: Any, *, key: str
) -> dict[str, Any]:
    if data is None:
        data = []
    if not isinstance(data, list):
        raise GrafanaError(
            f"expected a list of {key}, got {type(data).__name__}",
        )
    values = [item for item in data if isinstance(item, str)]
    result: dict[str, Any] = {
        "datasource": datasource.as_dict(),
        key: values[:MAX_LIST_ITEMS],
        "total": len(values),
    }
    if len(values) > MAX_LIST_ITEMS:
        result["truncated"] = (
            f"{len(values)} {key} matched; only the first {MAX_LIST_ITEMS} are listed. "
            f"Narrow the request with a selector."
        )
    return result


def _query_result(datasource: Datasource, expr: str, data: Any) -> dict[str, Any]:
    """Flatten a Prometheus or Loki query response into one shape.

    Prometheus puts a series' labels under ``metric`` and Loki under
    ``stream``; instant queries carry a single ``value`` and range queries a
    list of ``values``. Callers get ``labels`` either way, so a skill does
    not need a branch per datasource type.
    """
    if not isinstance(data, dict):
        raise GrafanaError(f"expected a query result object, got {type(data).__name__}")
    result_type = data.get("resultType")
    raw = data.get("result")
    if not isinstance(raw, list):
        # "scalar" and "string" results carry a bare value rather than a list.
        return {
            "datasource": datasource.as_dict(),
            "query": expr,
            "result_type": result_type,
            "result": raw,
        }

    notes: list[str] = []
    if len(raw) > MAX_SERIES:
        notes.append(
            f"{len(raw)} series matched; only the first {MAX_SERIES} are included. "
            f"Aggregate the query or add label filters."
        )
    series: list[dict[str, Any]] = []
    for entry in raw[:MAX_SERIES]:
        if not isinstance(entry, dict):
            continue
        labels = entry.get("metric") or entry.get("stream") or {}
        shaped: dict[str, Any] = {"labels": labels}
        if "value" in entry:
            shaped["value"] = entry["value"]
        points = entry.get("values")
        if isinstance(points, list):
            if len(points) > MAX_POINTS_PER_SERIES:
                notes.append(
                    f"a series returned {len(points)} points; only the last "
                    f"{MAX_POINTS_PER_SERIES} are included. Use a coarser step."
                )
                points = points[-MAX_POINTS_PER_SERIES:]
            shaped["values"] = points
        series.append(shaped)

    shaped_result: dict[str, Any] = {
        "datasource": datasource.as_dict(),
        "query": expr,
        "result_type": result_type,
        "series_count": len(raw),
        "series": series,
    }
    if notes:
        # Duplicated per-series point warnings say nothing extra.
        shaped_result["truncated"] = " ".join(dict.fromkeys(notes))
    return shaped_result


def _now() -> datetime:
    return datetime.now(UTC)


def _rfc3339(moment: datetime) -> str:
    """Format a time the way both Prometheus and Loki accept it.

    Sending RFC 3339 to both avoids the trap that Prometheus reads a bare
    number as unix *seconds* while Loki reads it as unix *nanoseconds*.
    """
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime

    @classmethod
    def parse(cls, start: str | None, end: str | None) -> TimeWindow:
        parsed_end = parse_time(end, default_to=_now)
        parsed_start = parse_time(
            start, default_to=lambda: parsed_end - timedelta(hours=1)
        )
        if parsed_start >= parsed_end:
            raise GrafanaError(
                f"the time window is empty: start '{_rfc3339(parsed_start)}' is not "
                f"before end '{_rfc3339(parsed_end)}'"
            )
        return cls(start=parsed_start, end=parsed_end)

    def as_prometheus_params(self) -> dict[str, Any]:
        return {"start": _rfc3339(self.start), "end": _rfc3339(self.end)}

    def as_loki_params(self) -> dict[str, Any]:
        # Loki takes the same RFC 3339 form, so this is the same call as the
        # Prometheus one today. The two are kept apart because the endpoints
        # they feed are versioned separately and have diverged before.
        return self.as_prometheus_params()

    def auto_step_seconds(self) -> float:
        span = (self.end - self.start).total_seconds()
        ideal = span / RANGE_QUERY_TARGET_POINTS
        for candidate in _NICE_STEPS_SECONDS:
            if candidate >= ideal:
                return float(candidate)
        return float(_NICE_STEPS_SECONDS[-1])


def parse_time(value: str | None, *, default_to: Callable[[], datetime]) -> datetime:
    """Read a time given as RFC 3339, unix seconds, or ``now-1h``."""
    if value is None or not value.strip():
        return default_to()
    text = value.strip()
    relative = _RELATIVE_TIME.match(text)
    if relative:
        if relative.group(1) is None:
            return _now()
        seconds = int(relative.group(1)) * _TIME_UNIT_SECONDS[relative.group(2).lower()]
        return _now() - timedelta(seconds=seconds)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        pass
    else:
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    try:
        return datetime.fromtimestamp(float(text), UTC)
    except (ValueError, OverflowError, OSError):
        raise GrafanaError(
            f"could not read '{value}' as a time; expected an RFC 3339 timestamp "
            f"such as 2026-09-14T10:00:00Z, unix seconds, or a relative expression "
            f"such as now, now-15m, now-1h or now-7d"
        ) from None


def parse_duration_seconds(value: str) -> float:
    """Read a Prometheus-style duration such as ``30s``, ``5m`` or ``1h``."""
    match = _DURATION.match(value.strip())
    if match is None:
        raise GrafanaError(
            f"could not read '{value}' as a duration; expected a number with an "
            f"optional unit of ms, s, m, h, d or w, such as 30s, 5m or 1h"
        )
    amount = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    seconds = amount * 0.001 if unit == "ms" else amount * _TIME_UNIT_SECONDS[unit]
    if seconds <= 0:
        raise GrafanaError(f"a step must be longer than zero, but '{value}' is not")
    return seconds


def _step_string(seconds: float) -> str:
    if seconds >= 1 and seconds == int(seconds):
        return f"{int(seconds)}s"
    return f"{seconds}s"
