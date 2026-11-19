# SPDX-License-Identifier: MIT
"""A thin, opinionated client for the bits of Grafana this server exposes.

Two things happen here that callers would otherwise have to do themselves,
and which are the whole point of putting a server in front of the Grafana
API rather than handing out a token:

* A datasource can be named by uid *or* by its display name, and the
  difference between a Prometheus-shaped backend (Prometheus, Mimir,
  Thanos), a Loki one and a Tempo one is resolved from the datasource's own
  type rather than asked of the caller. The caller says "list the labels on
  'Mimir'".
* Times are accepted as RFC 3339, unix seconds, or ``now-1h``, and a range
  query with no step gets one that yields a sensible number of points.

Everything reaches the backends through Grafana's datasource proxy, so the
service account token is the only credential involved and Grafana's own
access control still applies.
"""

from __future__ import annotations

import base64
import binascii
import logging
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from opentelemetry import propagate
from opentelemetry.trace import SpanKind, Status, StatusCode

from grafana_editor.config import GrafanaSettings
from grafana_editor.telemetry import tracer

logger = logging.getLogger(__name__)

PROMETHEUS = "prometheus"
LOKI = "loki"
TEMPO = "tempo"

# Grafana reports a Mimir or Thanos backend as plain "prometheus"; the
# AWS-managed variant ships under its own plugin id but speaks the same API.
DATASOURCE_FLAVOURS: dict[str, str] = {
    "prometheus": PROMETHEUS,
    "grafana-amazonprometheus-datasource": PROMETHEUS,
    "loki": LOKI,
    "tempo": TEMPO,
}

# Query results are shaped for a model's context window rather than for a
# browser: a range query over a wide window can otherwise run to megabytes
# of JSON, most of it redundant. Truncation is always reported in the
# result, never silent.
MAX_SERIES = 50
MAX_POINTS_PER_SERIES = 500
MAX_LIST_ITEMS = 2000
MAX_TRACES = 100
MAX_TRACE_SPANS = 500
MAX_ATTRIBUTE_CHARS = 1000

# Tempo reports intrinsics (name, duration, status, ...) unscoped in TraceQL,
# while every other scope's attributes are written as "<scope>.<name>".
_TEMPO_INTRINSIC_SCOPE = "intrinsic"

_HEX_ID = re.compile(r"^[0-9a-fA-F]+$")
_OTLP_STATUS_CODES = {0: "unset", 1: "ok", 2: "error"}
_OTLP_SPAN_KINDS = {
    0: "unspecified",
    1: "internal",
    2: "server",
    3: "client",
    4: "producer",
    5: "consumer",
}

DEFAULT_TIMEOUT_SECONDS = 30.0
DATASOURCE_CACHE_SECONDS = 60.0
FOLDER_CACHE_SECONDS = 300.0

# Grafana migrates a dashboard forward from whatever schemaVersion it is saved
# with, so this only has to be recent enough that no migration rewrites a
# modern panel. A caller that knows better can set its own inside `dashboard`.
DASHBOARD_SCHEMA_VERSION = 41

# Marks a dashboard as this server's, and whose it is. Written as tags rather
# than inferred from the title prefix so that listing one person's dashboards
# is a search Grafana can answer rather than string matching done here.
EDITOR_TAG = "grafana-editor"
AUTHOR_TAG_PREFIX = "author:"

MAX_DASHBOARDS_LISTED = 200

DASHBOARD_DEFAULTS: dict[str, Any] = {
    "schemaVersion": DASHBOARD_SCHEMA_VERSION,
    "editable": True,
    "timezone": "browser",
    "time": {"from": "now-6h", "to": "now"},
    "panels": [],
}
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


@dataclass(frozen=True)
class Folder:
    uid: str
    title: str


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
        self._sandbox_folder_name = settings.sandbox_folder
        self._folder: Folder | None = None
        self._folder_expires_at = 0.0

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
        source = await self.require_flavour(datasource, PROMETHEUS, LOKI, TEMPO)
        window = TimeWindow.parse(start, end)
        if source.flavour == TEMPO:
            params = window.as_tempo_params()
            if selector:
                params["q"] = selector
            payload = await self._datasource_request(
                source, "api/v2/search/tags", params=params
            )
            return _string_list_result(source, _tempo_tags(payload), key="labels")
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
        source = await self.require_flavour(datasource, PROMETHEUS, LOKI, TEMPO)
        window = TimeWindow.parse(start, end)
        quoted = quote(label, safe="")
        if source.flavour == TEMPO:
            params = window.as_tempo_params()
            if selector:
                params["q"] = selector
            payload = await self._datasource_request(
                source, f"api/v2/search/tag/{quoted}/values", params=params
            )
            result = _string_list_result(
                source, _tempo_tag_values(payload), key="values"
            )
            result["label"] = label
            return result
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
        source = await self.require_flavour(datasource, PROMETHEUS, LOKI, TEMPO)
        window = TimeWindow.parse(start, end)
        step_string = _step_string(
            parse_duration_seconds(step) if step else window.auto_step_seconds()
        )
        if source.flavour == TEMPO:
            # TraceQL metrics: Tempo names the query `q` and has no
            # Prometheus envelope, so it is reshaped into the same series.
            payload = await self._datasource_request(
                source,
                "api/metrics/query_range",
                params={"q": expr, **window.as_tempo_params(), "step": step_string},
            )
            result = _query_result(source, expr, _tempo_matrix(payload))
        else:
            params: dict[str, Any] = {
                "query": expr,
                "start": _rfc3339(window.start),
                "end": _rfc3339(window.end),
                "step": step_string,
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
        result["step"] = step_string
        return result

    # -- Tempo, through the datasource proxy ------------------------------

    async def search_traces(
        self,
        datasource: str,
        query: str,
        *,
        start: str | None = None,
        end: str | None = None,
        limit: int = 20,
        spans_per_span_set: int = 3,
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, TEMPO)
        window = TimeWindow.parse(start, end)
        if limit < 1:
            raise GrafanaError(f"limit must be at least 1, not {limit}")
        if spans_per_span_set < 1:
            raise GrafanaError(
                f"spans_per_span_set must be at least 1, not {spans_per_span_set}"
            )
        wanted = min(limit, MAX_TRACES)
        params: dict[str, Any] = {
            "q": query,
            **window.as_tempo_params(),
            "limit": wanted,
            "spss": spans_per_span_set,
        }
        payload = await self._datasource_request(source, "api/search", params=params)
        if not isinstance(payload, dict):
            raise GrafanaError(
                f"expected a trace search result object, got {type(payload).__name__}"
            )
        raw = payload.get("traces") or []
        if not isinstance(raw, list):
            raise GrafanaError(
                f"expected a list of traces, got {type(raw).__name__}",
            )
        traces = [_search_trace(item) for item in raw if isinstance(item, dict)]
        result: dict[str, Any] = {
            "datasource": source.as_dict(),
            "query": query,
            "start": _rfc3339(window.start),
            "end": _rfc3339(window.end),
            "trace_count": len(traces),
            "traces": traces,
        }
        notes: list[str] = []
        if limit > MAX_TRACES:
            notes.append(f"limit was capped at {MAX_TRACES}.")
        if len(traces) >= wanted:
            notes.append(
                f"the search stopped at {wanted} traces, so more may match. "
                f"Narrow the query or the time window, or aggregate with a "
                f"TraceQL metrics query in query_range."
            )
        if notes:
            result["truncated"] = " ".join(notes)
        return result

    async def get_trace(
        self,
        datasource: str,
        trace_id: str,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        source = await self.require_flavour(datasource, TEMPO)
        clean_id = trace_id.strip()
        if not _HEX_ID.match(clean_id) or len(clean_id) > 32:
            raise GrafanaError(
                f"'{trace_id}' is not a trace id; expected up to 32 hex digits, "
                f"as search_traces returns them"
            )
        # Without a window Tempo looks through every block it has, which is
        # slower but finds a trace of any age; a default of the last hour
        # would silently miss an older one.
        params: dict[str, Any] = {}
        if start or end:
            params = TimeWindow.parse(start, end).as_tempo_params()
        payload = await self._datasource_request(
            source, f"api/v2/traces/{clean_id.lower()}", params=params
        )
        return _trace_result(source, clean_id.lower(), payload)

    # -- dashboards in the sandbox folder ---------------------------------

    async def sandbox_folder(self, *, refresh: bool = False) -> Folder:
        """Resolve the configured sandbox folder's title to its uid.

        Cached, because every dashboard call needs it and folders are not
        renamed often. Matched case-insensitively: the folder is named by a
        human in the Grafana UI, so "sandbox" and "Sandbox" are the same
        request as far as a caller is concerned.
        """
        if (
            not refresh
            and self._folder is not None
            and time.monotonic() < self._folder_expires_at
        ):
            return self._folder
        wanted = self._sandbox_folder_name
        payload = await self._api_request(
            "GET", "/api/search", params={"type": "dash-folder", "limit": 5000}
        )
        if not isinstance(payload, list):
            raise GrafanaError(
                f"expected a list of folders from Grafana, got {type(payload).__name__}"
            )
        folders = [
            Folder(uid=str(item["uid"]), title=str(item["title"]))
            for item in payload
            if isinstance(item, dict) and item.get("uid") and item.get("title")
        ]
        matches = [f for f in folders if f.title.casefold() == wanted.casefold()]
        if len(matches) == 1:
            self._folder = matches[0]
            self._folder_expires_at = time.monotonic() + FOLDER_CACHE_SECONDS
            return matches[0]
        if len(matches) > 1:
            uids = ", ".join(f.uid for f in matches)
            raise GrafanaError(
                f"{len(matches)} folders in Grafana are titled '{wanted}' "
                f"(uids {uids}), so which one to write to is ambiguous"
            )
        known = ", ".join(sorted(f.title for f in folders)) or "none"
        raise GrafanaError(
            f"Grafana has no folder titled '{wanted}', which is this server's "
            f"configured sandbox-folder; the folders it does have are: {known}"
        )

    async def create_dashboard(
        self,
        *,
        author: str,
        title: str,
        dashboard: dict[str, Any],
        message: str | None = None,
    ) -> dict[str, Any]:
        folder = await self.sandbox_folder()
        body = _dashboard_body(author, title, dashboard)
        payload = await self._api_request(
            "POST",
            "/api/dashboards/db",
            json={
                # uid and id are cleared rather than passed through: a
                # dashboard object copied from an existing one still carries
                # them, and Grafana would overwrite that dashboard instead of
                # creating a new one.
                "dashboard": {**body, "uid": None, "id": None},
                "folderUid": folder.uid,
                "message": message or f"created by {author} via grafana-editor",
                "overwrite": False,
            },
        )
        return self._saved(payload, folder, body["title"])

    async def update_dashboard(
        self,
        *,
        author: str,
        uid: str,
        dashboard: dict[str, Any],
        title: str | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        folder, existing = await self._sandbox_dashboard(uid)
        body = _dashboard_body(
            author,
            # Keeping the stored title when none is given is what makes
            # updating panels alone leave the name, and its prefix, alone.
            title if title is not None else str(existing.get("title") or ""),
            dashboard,
            already_prefixed=title is None,
        )
        payload = await self._api_request(
            "POST",
            "/api/dashboards/db",
            json={
                "dashboard": {
                    **body,
                    "uid": uid,
                    "id": existing.get("id"),
                    # The version read back a moment ago, so a save that would
                    # discard someone's concurrent edit in the UI fails with
                    # Grafana's version conflict rather than winning silently.
                    "version": existing.get("version"),
                },
                "folderUid": folder.uid,
                "message": message or f"updated by {author} via grafana-editor",
                "overwrite": False,
            },
        )
        return self._saved(payload, folder, body["title"])

    async def delete_dashboard(self, *, author: str, uid: str) -> dict[str, Any]:
        folder, existing = await self._sandbox_dashboard(uid)
        title = str(existing.get("title") or "")
        # The sandbox is shared, so only the caller's own drafts, recognised by
        # the title prefix create_dashboard gave them, may be deleted.
        if not has_author_prefix(author, title):
            raise GrafanaError(
                f"dashboard '{uid}' is titled '{title}', which does not start "
                f"with '{author}: ', so it is not one of your dashboards and "
                f"this server will not delete it"
            )
        await self._api_request("DELETE", f"/api/dashboards/uid/{quote(uid, safe='')}")
        return {
            "uid": uid,
            "title": title,
            "folder": folder.title,
        }

    async def get_dashboard(self, uid: str) -> dict[str, Any]:
        payload = await self._fetch_dashboard(uid)
        meta = payload.get("meta") or {}
        dashboard = payload.get("dashboard") or {}
        folder = await self.sandbox_folder()
        return {
            "uid": str(dashboard.get("uid") or uid),
            "title": dashboard.get("title"),
            "url": self._absolute(meta.get("url")),
            "version": dashboard.get("version"),
            "folder": meta.get("folderTitle"),
            # Says up front whether update_dashboard will accept this uid,
            # rather than letting the caller find out by being refused.
            "writable": meta.get("folderUid") == folder.uid,
            "dashboard": dashboard,
        }

    async def list_dashboards(self, *, author: str | None = None) -> dict[str, Any]:
        folder = await self.sandbox_folder()
        params: dict[str, Any] = {
            "type": "dash-db",
            "folderUIDs": folder.uid,
            "limit": MAX_DASHBOARDS_LISTED,
        }
        if author:
            params["tag"] = f"{AUTHOR_TAG_PREFIX}{author}"
        payload = await self._api_request("GET", "/api/search", params=params)
        if not isinstance(payload, list):
            raise GrafanaError(
                f"expected a list of dashboards from Grafana, got "
                f"{type(payload).__name__}"
            )
        return {
            "folder": folder.title,
            "dashboards": [
                {
                    "uid": item.get("uid"),
                    "title": item.get("title"),
                    "url": self._absolute(item.get("url")),
                    "tags": item.get("tags") or [],
                }
                for item in payload
                if isinstance(item, dict)
            ],
        }

    async def _sandbox_dashboard(self, uid: str) -> tuple[Folder, dict[str, Any]]:
        """Fetch a dashboard this server may write to, or refuse with why not.

        Every write to an existing dashboard goes through here, so the rule
        that nothing outside the sandbox folder is changed lives in one place.
        """
        folder = await self.sandbox_folder()
        current = await self._fetch_dashboard(uid)
        meta = current.get("meta") or {}
        if meta.get("folderUid") != folder.uid:
            raise GrafanaError(
                f"dashboard '{uid}' is in the folder "
                f"'{meta.get('folderTitle') or meta.get('folderUid') or 'General'}', "
                f"and this server only writes to '{folder.title}'"
            )
        return folder, current.get("dashboard") or {}

    async def _fetch_dashboard(self, uid: str) -> dict[str, Any]:
        payload = await self._api_request(
            "GET", f"/api/dashboards/uid/{quote(uid, safe='')}"
        )
        if not isinstance(payload, dict) or not isinstance(
            payload.get("dashboard"), dict
        ):
            raise GrafanaError(
                f"Grafana did not return a dashboard for uid '{uid}': "
                f"{_truncate(str(payload))}"
            )
        return payload

    def _saved(self, payload: Any, folder: Folder, title: str) -> dict[str, Any]:
        """Shape Grafana's save response, which does not echo the title back."""
        if not isinstance(payload, dict) or not payload.get("uid"):
            raise GrafanaError(
                f"Grafana did not confirm the dashboard was saved: "
                f"{_truncate(str(payload))}"
            )
        return {
            "uid": str(payload["uid"]),
            "title": title,
            "url": self._absolute(payload.get("url")),
            "version": payload.get("version"),
            "folder": folder.title,
        }

    def _absolute(self, url: Any) -> str | None:
        """Turn the root-relative URL Grafana returns into one a human can open."""
        if not isinstance(url, str) or not url:
            return None
        return f"{self._base_url}{url}" if url.startswith("/") else url

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
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self._token.read()}",
            "Accept": "application/json",
        }
        start = time.monotonic()
        with tracer.start_as_current_span(
            f"grafana {method}",
            kind=SpanKind.CLIENT,
            attributes={"http.request.method": method, "url.full": url},
        ) as span:
            propagate.inject(headers)
            try:
                response = await self._http.request(
                    method, url, params=params, json=json, headers=headers
                )
            except httpx.HTTPError as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                logger.warning("Grafana %s %s failed: %s", method, path, exc)
                raise GrafanaError(f"{method} {path} on Grafana failed: {exc}") from exc
            span.set_attribute("http.response.status_code", response.status_code)
            if response.status_code >= 400:
                span.set_status(Status(StatusCode.ERROR))
        logger.debug(
            "Grafana %s %s returned %d in %.1fms",
            method,
            path,
            response.status_code,
            (time.monotonic() - start) * 1000,
        )
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


def author_from_email(email: str) -> str:
    """The part of an email address before the @, used to prefix titles."""
    local = email.split("@", 1)[0].strip()
    if not local:
        raise GrafanaError(
            f"could not read a user name out of the email address '{email}'"
        )
    return local


def prefixed_title(author: str, title: str) -> str:
    """Prefix a dashboard title with its author, without doubling the prefix.

    A caller that passes a title it read back off an existing dashboard
    already has the prefix on it, and prefixing again would give
    "noa.resare: noa.resare: Server Temperature". Case is left alone
    otherwise: title-casing would turn "CPU usage" into "Cpu Usage".
    """
    clean = " ".join(title.split())
    if not clean:
        raise GrafanaError("a dashboard needs a title, but the title given was empty")
    if has_author_prefix(author, clean):
        return clean
    return f"{author}: {clean}"


def has_author_prefix(author: str, title: str) -> bool:
    """Whether a title carries the prefix prefixed_title gives this author."""
    clean = " ".join(title.split())
    return clean.casefold().startswith(f"{author}: ".casefold())


def _dashboard_body(
    author: str,
    title: str,
    dashboard: dict[str, Any],
    *,
    already_prefixed: bool = False,
) -> dict[str, Any]:
    inner = _dashboard_object(dashboard)
    body = {**DASHBOARD_DEFAULTS, **inner}
    body["title"] = title if already_prefixed else prefixed_title(author, title)
    body["tags"] = _dashboard_tags(author, inner.get("tags"))
    return body


def _dashboard_object(dashboard: Any) -> dict[str, Any]:
    """Take the dashboard out of whatever shape the caller passed it in.

    A caller holding Grafana's own save payload, or the body of a
    ``GET /api/dashboards/uid/...`` reply, has the dashboard one level down
    under "dashboard". Unwrapping it beats saving a dashboard whose only
    content is a nested copy of itself, and a real dashboard object never has
    a "dashboard" key of its own.
    """
    if not isinstance(dashboard, dict):
        raise GrafanaError(
            f"the dashboard must be a JSON object, not a {type(dashboard).__name__}"
        )
    inner = dashboard.get("dashboard")
    if isinstance(inner, dict):
        dashboard = inner
    panels = dashboard.get("panels")
    if panels is not None and not isinstance(panels, list):
        raise GrafanaError(
            f"dashboard.panels must be a list of panel objects, not a "
            f"{type(panels).__name__}"
        )
    return dashboard


def _dashboard_tags(author: str, existing: Any) -> list[str]:
    tags = [
        tag
        for tag in (existing if isinstance(existing, list) else [])
        if isinstance(tag, str)
        and tag != EDITOR_TAG
        and not tag.startswith(AUTHOR_TAG_PREFIX)
    ]
    return [*tags, EDITOR_TAG, f"{AUTHOR_TAG_PREFIX}{author}"]


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


def _tempo_tags(payload: Any) -> list[str]:
    """Flatten Tempo's per-scope tag lists into names TraceQL accepts as written.

    ``{"scopes": [{"name": "span", "tags": ["http.route"]}]}`` becomes
    ``span.http.route``, while intrinsics such as ``duration`` stay bare,
    because that is how each is spelled in a TraceQL query and in a tag values
    lookup.
    """
    if not isinstance(payload, dict):
        raise GrafanaError(
            f"expected Tempo's tags to be an object, got {type(payload).__name__}"
        )
    names: list[str] = []
    for scope in payload.get("scopes") or []:
        if not isinstance(scope, dict):
            continue
        scope_name = str(scope.get("name") or "")
        for tag in scope.get("tags") or []:
            if not isinstance(tag, str):
                continue
            if scope_name == _TEMPO_INTRINSIC_SCOPE or not scope_name:
                names.append(tag)
            else:
                names.append(f"{scope_name}.{tag}")
    return list(dict.fromkeys(names))


def _tempo_tag_values(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        raise GrafanaError(
            f"expected Tempo's tag values to be an object, got {type(payload).__name__}"
        )
    values: list[str] = []
    for entry in payload.get("tagValues") or []:
        if isinstance(entry, dict) and entry.get("value") is not None:
            values.append(str(entry["value"]))
    return values


def _tempo_matrix(payload: Any) -> dict[str, Any]:
    """Recast a TraceQL metrics response as a Prometheus matrix.

    Tempo returns ``{"series": [{"labels": [{"key", "value": {...}}],
    "samples": [{"timestampMs", "value"}]}]}``. Reshaping it means a range
    query reads the same whichever language it was written in.
    """
    if not isinstance(payload, dict):
        raise GrafanaError(
            f"expected a TraceQL metrics result object, got {type(payload).__name__}"
        )
    result: list[dict[str, Any]] = []
    for series in payload.get("series") or []:
        if not isinstance(series, dict):
            continue
        labels = {
            key: str(value)
            for key, value in _otlp_attributes(series.get("labels")).items()
        }
        values = [
            [int(sample["timestampMs"]) / 1000, _sample_string(sample.get("value"))]
            for sample in series.get("samples") or []
            if isinstance(sample, dict) and sample.get("timestampMs") is not None
        ]
        result.append({"metric": labels, "values": values})
    return {"resultType": "matrix", "result": result}


def _sample_string(value: Any) -> str:
    """Render a sample the way Prometheus does: as a string, without a '.0'."""
    try:
        # Protobuf's JSON encoding leaves a zero out entirely.
        number = float(value if value is not None else 0)
    except (TypeError, ValueError):
        return str(value)
    return str(int(number)) if number.is_integer() else repr(number)


def _search_trace(trace: dict[str, Any]) -> dict[str, Any]:
    span_sets = trace.get("spanSets")
    if not isinstance(span_sets, list):
        # Older Tempo versions return a single "spanSet" rather than a list.
        single = trace.get("spanSet")
        span_sets = [single] if isinstance(single, dict) else []
    return {
        "trace_id": _otlp_id(trace.get("traceID")),
        "root_service": trace.get("rootServiceName"),
        "root_name": trace.get("rootTraceName"),
        "start": _nanos_to_rfc3339(trace.get("startTimeUnixNano")),
        "duration_ms": trace.get("durationMs"),
        "span_sets": [
            {
                "matched": span_set.get("matched"),
                "spans": [
                    {
                        "span_id": _otlp_id(span.get("spanID")),
                        "name": span.get("name"),
                        "start": _nanos_to_rfc3339(span.get("startTimeUnixNano")),
                        "duration_ms": _nanos_to_ms(span.get("durationNanos")),
                        "attributes": _otlp_attributes(span.get("attributes")),
                    }
                    for span in span_set.get("spans") or []
                    if isinstance(span, dict)
                ],
            }
            for span_set in span_sets
            if isinstance(span_set, dict)
        ],
    }


def _trace_result(
    datasource: Datasource, trace_id: str, payload: Any
) -> dict[str, Any]:
    """Flatten an OTLP trace into one list of spans, in start order.

    The OTLP shape nests spans under resource and scope, and carries the
    service name as a resource attribute, which is three levels a caller
    would otherwise have to walk to answer "which service was slow".
    """
    if not isinstance(payload, dict):
        raise GrafanaError(f"expected a trace object, got {type(payload).__name__}")
    # /api/v2/traces wraps the trace in "trace"; /api/traces does not.
    body = payload.get("trace") if isinstance(payload.get("trace"), dict) else payload
    resources = body.get("resourceSpans") or body.get("batches") or []

    spans: list[tuple[int, dict[str, Any]]] = []
    for resource_spans in resources:
        if not isinstance(resource_spans, dict):
            continue
        resource = _otlp_attributes(
            (resource_spans.get("resource") or {}).get("attributes")
        )
        service = resource.get("service.name")
        scopes = (
            resource_spans.get("scopeSpans")
            or resource_spans.get("instrumentationLibrarySpans")
            or []
        )
        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            for span in scope.get("spans") or []:
                if isinstance(span, dict):
                    spans.append(_trace_span(span, service))
    spans.sort(key=lambda pair: pair[0])

    starts = [start for start, _ in spans]
    ends = [start + span["_duration_ns"] for start, span in spans]
    shaped = [
        {key: value for key, value in span.items() if key != "_duration_ns"}
        for _, span in spans
    ]
    result: dict[str, Any] = {
        "datasource": datasource.as_dict(),
        "trace_id": trace_id,
        "span_count": len(shaped),
        "services": sorted({s["service"] for s in shaped if s.get("service")}),
        "start": _nanos_to_rfc3339(min(starts)) if starts else None,
        "duration_ms": (max(ends) - min(starts)) / 1e6 if starts else None,
        "spans": shaped[:MAX_TRACE_SPANS],
    }
    if len(shaped) > MAX_TRACE_SPANS:
        result["truncated"] = (
            f"the trace has {len(shaped)} spans; only the first {MAX_TRACE_SPANS} "
            f"by start time are included. Use search_traces with a TraceQL "
            f"query to find specific spans in it."
        )
    return result


def _trace_span(span: dict[str, Any], service: Any) -> tuple[int, dict[str, Any]]:
    start = _int_or_none(span.get("startTimeUnixNano")) or 0
    end = _int_or_none(span.get("endTimeUnixNano")) or start
    raw_status = span.get("status")
    status: dict[str, Any] = raw_status if isinstance(raw_status, dict) else {}
    shaped: dict[str, Any] = {
        "span_id": _otlp_id(span.get("spanId")),
        "parent_span_id": _otlp_id(span.get("parentSpanId")) or None,
        "name": span.get("name"),
        "service": service,
        "kind": _otlp_enum(span.get("kind"), "SPAN_KIND_", _OTLP_SPAN_KINDS),
        "start": _nanos_to_rfc3339(start),
        "duration_ms": (end - start) / 1e6,
        "status": _otlp_enum(status.get("code"), "STATUS_CODE_", _OTLP_STATUS_CODES),
        "attributes": _otlp_attributes(span.get("attributes")),
        "_duration_ns": end - start,
    }
    if status.get("message"):
        shaped["status_message"] = status["message"]
    events = [
        {
            "name": event.get("name"),
            "attributes": _otlp_attributes(event.get("attributes")),
        }
        for event in span.get("events") or []
        if isinstance(event, dict)
    ]
    # Events are where exceptions are recorded, which is usually the reason
    # someone is looking at a single trace at all.
    if events:
        shaped["events"] = events
    return start, shaped


def _otlp_enum(value: Any, prefix: str, by_number: dict[int, str]) -> str:
    """Read an OTLP enum given either as its number or its full name."""
    if isinstance(value, int):
        return by_number.get(value, str(value))
    if isinstance(value, str) and value:
        return value.removeprefix(prefix).lower()
    return by_number[0]


def _otlp_id(value: Any) -> str:
    """A trace or span id as hex, whichever encoding Tempo used for it.

    Tempo's JSON writes ids in OTLP traces as base64 (protobuf's encoding of
    bytes) but as hex in search results, and hex is what a caller pastes
    into a TraceQL query or Grafana's search box.
    """
    if not isinstance(value, str) or not value:
        return ""
    if _HEX_ID.match(value):
        return value.lower()
    try:
        return base64.b64decode(value, validate=True).hex()
    except (binascii.Error, ValueError):
        return value


def _otlp_attributes(attributes: Any) -> dict[str, Any]:
    if not isinstance(attributes, list):
        return {}
    return {
        str(item["key"]): _otlp_value(item.get("value"))
        for item in attributes
        if isinstance(item, dict) and "key" in item
    }


def _otlp_value(value: Any) -> Any:
    """Unwrap an OTLP AnyValue such as ``{"stringValue": "GET"}``."""
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return _truncate(str(value["stringValue"]), MAX_ATTRIBUTE_CHARS)
    if "intValue" in value:
        # int64 is a string in protobuf's JSON encoding.
        number = _int_or_none(value["intValue"])
        return number if number is not None else value["intValue"]
    if "doubleValue" in value:
        return value["doubleValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "arrayValue" in value:
        items = (value["arrayValue"] or {}).get("values") or []
        return [_otlp_value(item) for item in items]
    if "kvlistValue" in value:
        return _otlp_attributes((value["kvlistValue"] or {}).get("values"))
    return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _nanos_to_rfc3339(value: Any) -> str | None:
    nanos = _int_or_none(value)
    if nanos is None:
        return None
    moment = datetime.fromtimestamp(nanos / 1e9, UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _nanos_to_ms(value: Any) -> float | None:
    nanos = _int_or_none(value)
    return nanos / 1e6 if nanos is not None else None


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

    def as_tempo_params(self) -> dict[str, Any]:
        # Tempo's search and tag endpoints take only unix seconds. The end is
        # rounded up so a window ending mid-second still includes that second.
        return {
            "start": int(self.start.timestamp()),
            "end": math.ceil(self.end.timestamp()),
        }

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
