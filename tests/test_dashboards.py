# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from grafana_editor.config import GrafanaSettings
from grafana_editor.grafana import (
    GrafanaClient,
    GrafanaError,
    author_from_email,
    prefixed_title,
)

FOLDERS = [
    {"uid": "sandbox-uid", "title": "Sandbox", "type": "dash-folder"},
    {"uid": "prod-uid", "title": "Production", "type": "dash-folder"},
]

pytestmark = pytest.mark.anyio


class FakeGrafana:
    """Enough of the Grafana dashboard API to exercise the client against."""

    def __init__(
        self,
        *,
        folders: list[dict[str, Any]] | None = None,
        dashboards: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.folders = folders if folders is not None else FOLDERS
        self.dashboards = dashboards or {}
        self.saves: list[dict[str, Any]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/search":
            return self._search(request)
        if path.startswith("/api/dashboards/uid/"):
            uid = path.rsplit("/", 1)[-1]
            stored = self.dashboards.get(uid)
            if stored is None:
                return httpx.Response(404, json={"message": "Dashboard not found"})
            return httpx.Response(200, json=stored)
        if path == "/api/dashboards/db" and request.method == "POST":
            return self._save(request)
        return httpx.Response(404, json={"message": f"no route {path}"})

    def _search(self, request: httpx.Request) -> httpx.Response:
        params = request.url.params
        if params.get("type") == "dash-folder":
            return httpx.Response(200, json=self.folders)
        rows = [
            {
                "uid": uid,
                "title": stored["dashboard"]["title"],
                "url": stored["meta"]["url"],
                "tags": stored["dashboard"].get("tags", []),
                "folderUid": stored["meta"].get("folderUid"),
            }
            for uid, stored in self.dashboards.items()
            if stored["meta"].get("folderUid") == params.get("folderUIDs")
        ]
        tag = params.get("tag")
        if tag:
            rows = [row for row in rows if tag in row["tags"]]
        return httpx.Response(200, json=rows)

    def _save(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.saves.append(body)
        dashboard = body["dashboard"]
        uid = dashboard.get("uid") or "generated-uid"
        version = (dashboard.get("version") or 0) + 1
        slug = dashboard["title"].lower().replace(" ", "-").replace(":", "")
        url = f"/d/{uid}/{slug}"
        self.dashboards[uid] = {
            "meta": {"url": url, "folderUid": body.get("folderUid")},
            "dashboard": {**dashboard, "uid": uid, "version": version},
        }
        return httpx.Response(
            200, json={"uid": uid, "url": url, "version": version, "status": "success"}
        )


def _client(
    tmp_path: Path, fake: FakeGrafana, *, sandbox: str = "Sandbox"
) -> GrafanaClient:
    token = tmp_path / "token"
    token.write_text("glsa-test-token")
    return GrafanaClient(
        GrafanaSettings(
            url="https://grafana.example.com",
            service_account_token_path=str(token),
            sandbox_folder=sandbox,
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    )


def _stored(
    uid: str, *, title: str, folder_uid: str, version: int = 3
) -> dict[str, Any]:
    return {
        "meta": {"url": f"/d/{uid}/x", "folderUid": folder_uid, "folderTitle": "x"},
        "dashboard": {
            "uid": uid,
            "id": 7,
            "title": title,
            "version": version,
            "panels": [{"type": "timeseries", "title": "old"}],
        },
    }


# -- title prefixing ---------------------------------------------------------


def test_author_is_the_local_part_of_the_email() -> None:
    assert author_from_email("noa.resare@portswigger.net") == "noa.resare"


def test_prefixes_the_title_with_the_author() -> None:
    assert (
        prefixed_title("noa.resare", "Server Temperature")
        == "noa.resare: Server Temperature"
    )


def test_does_not_double_an_existing_prefix() -> None:
    once = prefixed_title("noa.resare", "Server Temperature")

    assert prefixed_title("noa.resare", once) == once


def test_leaves_the_caller_s_capitalisation_alone() -> None:
    # Title-casing would turn CPU into Cpu, so the title is passed through as
    # given and only the prefix is added.
    assert (
        prefixed_title("noa.resare", "CPU usage by pod")
        == "noa.resare: CPU usage by pod"
    )


def test_collapses_surrounding_and_repeated_whitespace() -> None:
    assert prefixed_title("noa.resare", "  Server   Temperature\n") == (
        "noa.resare: Server Temperature"
    )


def test_an_empty_title_is_rejected() -> None:
    with pytest.raises(GrafanaError, match="needs a title"):
        prefixed_title("noa.resare", "   ")


# -- creating ----------------------------------------------------------------


async def test_creates_in_the_sandbox_folder_with_a_prefixed_title(
    tmp_path: Path,
) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)

    result = await client.create_dashboard(
        author="noa.resare",
        title="Server Temperature",
        dashboard={"panels": [{"type": "timeseries", "title": "Temp"}]},
    )

    assert result["title"] == "noa.resare: Server Temperature"
    assert result["folder"] == "Sandbox"
    # A URL a human can open, not the root-relative one Grafana returns.
    assert result["url"] == (
        "https://grafana.example.com/d/generated-uid/noa.resare-server-temperature"
    )
    saved = fake.saves[-1]
    assert saved["folderUid"] == "sandbox-uid"
    assert saved["overwrite"] is False
    assert saved["dashboard"]["panels"] == [{"type": "timeseries", "title": "Temp"}]


async def test_create_clears_any_uid_carried_in_by_the_caller(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)

    # A dashboard object copied from an existing one still has its uid, and
    # passing it through would overwrite that dashboard instead of creating one.
    await client.create_dashboard(
        author="noa.resare",
        title="Copy",
        dashboard={"uid": "someone-elses-uid", "id": 42, "panels": []},
    )

    assert fake.saves[-1]["dashboard"]["uid"] is None
    assert fake.saves[-1]["dashboard"]["id"] is None


async def test_create_tags_the_dashboard_with_its_author(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)

    await client.create_dashboard(
        author="noa.resare", title="Tagged", dashboard={"tags": ["capacity"]}
    )

    assert fake.saves[-1]["dashboard"]["tags"] == [
        "capacity",
        "grafana-editor",
        "author:noa.resare",
    ]


async def test_create_fills_in_dashboard_defaults(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)

    await client.create_dashboard(author="noa.resare", title="Bare", dashboard={})

    dashboard = fake.saves[-1]["dashboard"]
    assert dashboard["schemaVersion"] == 41
    assert dashboard["time"] == {"from": "now-6h", "to": "now"}
    assert dashboard["panels"] == []


async def test_caller_defaults_win_over_the_servers(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)

    await client.create_dashboard(
        author="noa.resare",
        title="Explicit",
        dashboard={"time": {"from": "now-7d", "to": "now"}, "schemaVersion": 39},
    )

    dashboard = fake.saves[-1]["dashboard"]
    assert dashboard["time"] == {"from": "now-7d", "to": "now"}
    assert dashboard["schemaVersion"] == 39


async def test_unwraps_a_dashboard_passed_as_a_save_payload(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)

    # What a caller holds after reading get_dashboard, or Grafana's own export.
    await client.create_dashboard(
        author="noa.resare",
        title="Nested",
        dashboard={"dashboard": {"panels": [{"type": "stat"}]}, "folderUid": "ignored"},
    )

    dashboard = fake.saves[-1]["dashboard"]
    assert dashboard["panels"] == [{"type": "stat"}]
    assert "dashboard" not in dashboard


async def test_rejects_panels_that_are_not_a_list(tmp_path: Path) -> None:
    client = _client(tmp_path, FakeGrafana())

    with pytest.raises(GrafanaError) as caught:
        await client.create_dashboard(
            author="noa.resare", title="Wrong", dashboard={"panels": {"type": "stat"}}
        )

    assert "panels must be a list" in str(caught.value)
    assert "dict" in str(caught.value)


async def test_rejects_a_dashboard_that_is_not_an_object(tmp_path: Path) -> None:
    client = _client(tmp_path, FakeGrafana())

    with pytest.raises(GrafanaError, match="must be a JSON object"):
        await client.create_dashboard(
            author="noa.resare",
            title="Wrong",
            dashboard=[{"type": "stat"}],  # ty: ignore[invalid-argument-type]
        )


# -- the sandbox folder ------------------------------------------------------


async def test_matches_the_folder_title_case_insensitively(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake, sandbox="sandbox")

    assert (await client.sandbox_folder()).uid == "sandbox-uid"


async def test_a_missing_sandbox_folder_lists_the_folders_that_exist(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path, FakeGrafana(), sandbox="Scratch")

    with pytest.raises(GrafanaError) as caught:
        await client.sandbox_folder()

    message = str(caught.value)
    assert "'Scratch'" in message
    assert "Production, Sandbox" in message


async def test_two_folders_of_the_same_name_is_an_error_not_a_guess(
    tmp_path: Path,
) -> None:
    fake = FakeGrafana(
        folders=[
            {"uid": "one", "title": "Sandbox"},
            {"uid": "two", "title": "Sandbox"},
        ]
    )
    client = _client(tmp_path, fake)

    with pytest.raises(GrafanaError) as caught:
        await client.sandbox_folder()

    assert "ambiguous" in str(caught.value)
    assert "one, two" in str(caught.value)


async def test_the_folder_lookup_is_cached(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)

    await client.sandbox_folder()
    fake.folders = []

    # Still resolves, so the second call did not re-query.
    assert (await client.sandbox_folder()).uid == "sandbox-uid"


# -- updating ----------------------------------------------------------------


async def test_update_replaces_panels_and_keeps_the_stored_title(
    tmp_path: Path,
) -> None:
    fake = FakeGrafana(
        dashboards={
            "abc": _stored(
                "abc", title="noa.resare: Server Temperature", folder_uid="sandbox-uid"
            )
        }
    )
    client = _client(tmp_path, fake)

    result = await client.update_dashboard(
        author="someone.else",
        uid="abc",
        dashboard={"panels": [{"type": "stat", "title": "new"}]},
    )

    assert result["title"] == "noa.resare: Server Temperature"
    saved = fake.saves[-1]["dashboard"]
    assert saved["uid"] == "abc"
    assert saved["panels"] == [{"type": "stat", "title": "new"}]
    # The version just read back, so a concurrent UI edit loses rather than
    # being silently overwritten.
    assert saved["version"] == 3


async def test_update_with_a_new_title_prefixes_it(tmp_path: Path) -> None:
    fake = FakeGrafana(
        dashboards={
            "abc": _stored("abc", title="noa.resare: Old", folder_uid="sandbox-uid")
        }
    )
    client = _client(tmp_path, fake)

    result = await client.update_dashboard(
        author="noa.resare", uid="abc", dashboard={}, title="Rack Temperature"
    )

    assert result["title"] == "noa.resare: Rack Temperature"


async def test_update_refuses_a_dashboard_outside_the_sandbox(tmp_path: Path) -> None:
    fake = FakeGrafana(
        dashboards={"prod": _stored("prod", title="Live SLOs", folder_uid="prod-uid")}
    )
    client = _client(tmp_path, fake)

    with pytest.raises(GrafanaError) as caught:
        await client.update_dashboard(
            author="noa.resare", uid="prod", dashboard={"panels": []}
        )

    assert "only writes to 'Sandbox'" in str(caught.value)
    # Nothing was sent to Grafana's save endpoint.
    assert fake.saves == []


async def test_update_surfaces_a_version_conflict(tmp_path: Path) -> None:
    fake = FakeGrafana(
        dashboards={
            "abc": _stored("abc", title="noa.resare: X", folder_uid="sandbox-uid")
        }
    )

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/dashboards/db":
            return httpx.Response(
                412, json={"message": "the dashboard has been changed by someone else"}
            )
        return fake.handle(request)

    token = tmp_path / "token"
    token.write_text("t")
    client = GrafanaClient(
        GrafanaSettings(
            url="https://grafana.example.com", service_account_token_path=str(token)
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )

    with pytest.raises(GrafanaError) as caught:
        await client.update_dashboard(author="noa.resare", uid="abc", dashboard={})

    assert "changed by someone else" in str(caught.value)
    assert "412" in str(caught.value)


# -- reading and listing -----------------------------------------------------


async def test_get_dashboard_reports_whether_it_is_writable(tmp_path: Path) -> None:
    fake = FakeGrafana(
        dashboards={
            "abc": _stored("abc", title="noa.resare: X", folder_uid="sandbox-uid"),
            "prod": _stored("prod", title="Live SLOs", folder_uid="prod-uid"),
        }
    )
    client = _client(tmp_path, fake)

    assert (await client.get_dashboard("abc"))["writable"] is True
    assert (await client.get_dashboard("prod"))["writable"] is False


async def test_get_dashboard_returns_an_absolute_url(tmp_path: Path) -> None:
    fake = FakeGrafana(
        dashboards={
            "abc": _stored("abc", title="noa.resare: X", folder_uid="sandbox-uid")
        }
    )
    client = _client(tmp_path, fake)

    result = await client.get_dashboard("abc")

    assert result["url"] == "https://grafana.example.com/d/abc/x"
    assert result["dashboard"]["panels"] == [{"type": "timeseries", "title": "old"}]


async def test_get_dashboard_reports_an_unknown_uid(tmp_path: Path) -> None:
    client = _client(tmp_path, FakeGrafana())

    with pytest.raises(GrafanaError) as caught:
        await client.get_dashboard("nope")

    assert "Dashboard not found" in str(caught.value)


async def test_list_dashboards_can_be_narrowed_to_one_author(tmp_path: Path) -> None:
    fake = FakeGrafana()
    client = _client(tmp_path, fake)
    await client.create_dashboard(author="noa.resare", title="Mine", dashboard={})

    everything = await client.list_dashboards()
    mine = await client.list_dashboards(author="noa.resare")
    someone_else = await client.list_dashboards(author="other.person")

    assert everything["folder"] == "Sandbox"
    assert [d["title"] for d in mine["dashboards"]] == ["noa.resare: Mine"]
    assert someone_else["dashboards"] == []
