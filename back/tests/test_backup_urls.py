import asyncio
import os
import sys

import httpx

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost/test")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auto_discovery
import models
import bc_client
from bc_client import bc_url
from main import discover_from_link

REAL_ASYNC_CLIENT = httpx.AsyncClient


class _ScalarResult:
    def __init__(self, value=None):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class FakeDB:
    def __init__(self, client):
        self.client = client
        self.assets = []
        self.logs = []
        self.commits = 0

    async def execute(self, stmt):
        entity = stmt.column_descriptions[0]["entity"]
        params = stmt.compile().params
        if entity is models.Client:
            return _ScalarResult(self.client)
        if entity is models.Asset:
            bc_device_id = params.get("bc_device_id_1")
            backup_id = params.get("backup_id_1")
            hostname = params.get("hostname_1")
            client_id = params.get("client_id_1")
            for asset in self.assets:
                if bc_device_id is not None and asset.bc_device_id == bc_device_id:
                    return _ScalarResult(asset)
                if backup_id is not None and asset.backup_id == backup_id:
                    return _ScalarResult(asset)
                if hostname is not None and client_id is not None:
                    if asset.hostname == hostname and asset.client_id == client_id:
                        return _ScalarResult(asset)
            return _ScalarResult()
        raise AssertionError(f"Consulta inesperada: {stmt}")

    def add(self, item):
        if isinstance(item, models.Asset):
            self.assets.append(item)
        elif isinstance(item, models.ExecutionLog):
            self.logs.append(item)
        else:
            raise AssertionError(f"Objeto inesperado: {item!r}")

    async def commit(self):
        self.commits += 1


class _AsyncClientFactory:
    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def __call__(self, *args, **kwargs):
        async def handler(request):
            self.requests.append(request)
            return self.handler(request)

        return REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler))


def _make_client(server_url):
    server = models.BCServer(id=7, name="BC", url=server_url, token="secret-token")
    link = models.ClientBCLink(id=11, client_id=3, external_group_id="grp-1")
    link.bc_server = server
    client = models.Client(id=3, name="Cliente", auto_approve_assets=True)
    client.bc_links = [link]
    return client, link, server


def test_bc_url_uses_persisted_api_prefix_without_duplication():
    _, _, server = _make_client("https://backup.example/api/v1/external")

    assert (
        bc_url(server, "groups", "grp-1", "backups")
        == "https://backup.example/api/v1/external/groups/grp-1/backups"
    )


def test_discover_with_prefixed_url_fetches_all_pages_and_creates_assets(monkeypatch):
    async def run():
        client, _, _ = _make_client("https://backup.example/api/v1/external")
        db = FakeDB(client)

        def handler(request):
            assert "/api/v1/external/api/v1/external/" not in str(request.url)
            assert request.url.path == "/api/v1/external/groups/grp-1/backups"
            page = request.url.params.get("page")
            if page == "1":
                return httpx.Response(
                    200,
                    json={
                        "items": [{"id": 101, "device_name": "router-a"}],
                        "pages": 2,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "items": [{"id": 102, "device_name": "switch-b"}],
                    "pages": 2,
                },
            )

        factory = _AsyncClientFactory(handler)
        monkeypatch.setattr(auto_discovery.httpx, "AsyncClient", factory)

        result = await auto_discovery.sync_discovered_assets(client.id, db, link_id=11)

        assert result["status"] == "success"
        assert result["added"] == 2
        assert [asset.hostname for asset in db.assets] == ["router-a", "switch-b"]
        assert [request.url.params.get("page") for request in factory.requests] == ["1", "2"]
        assert db.logs[-1].status == "success"

    asyncio.run(run())


def test_discover_keeps_latest_backup_per_device(monkeypatch):
    async def run():
        client, _, _ = _make_client("https://backup.example/api/v1/external")
        db = FakeDB(client)

        def handler(request):
            page = request.url.params.get("page")
            if page == "1":
                return httpx.Response(
                    200,
                    json={
                        "items": [
                            {
                                "id": "new-backup",
                                "device_id": "device-1",
                                "device_name": "router-a",
                            }
                        ],
                        "pages": 2,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": "old-backup",
                            "device_id": "device-1",
                            "device_name": "router-a",
                        }
                    ],
                    "pages": 2,
                },
            )

        monkeypatch.setattr(auto_discovery.httpx, "AsyncClient", _AsyncClientFactory(handler))

        result = await auto_discovery.sync_discovered_assets(client.id, db, link_id=11)

        assert result["status"] == "success"
        assert result["added"] == 1
        assert len(db.assets) == 1
        assert db.assets[0].backup_id == "new-backup"
        assert db.assets[0].bc_device_id == "device-1"

    asyncio.run(run())


def test_discover_without_api_prefix_warns_and_returns_visible_error(monkeypatch):
    async def run():
        client, _, _ = _make_client("https://backup.example")
        db = FakeDB(client)
        warnings = []

        def handler(request):
            assert request.url.path == "/groups/grp-1/backups"
            return httpx.Response(404, json={"detail": "Endpoint nao encontrado."})

        monkeypatch.setattr(auto_discovery.httpx, "AsyncClient", _AsyncClientFactory(handler))
        monkeypatch.setattr(bc_client.logger, "warning", lambda *args, **kwargs: warnings.append(args))

        result = await auto_discovery.sync_discovered_assets(client.id, db, link_id=11)

        assert result["status"] == "error"
        assert result["errors"][0]["status_code"] == 404
        assert result["errors"][0]["url"].endswith("/groups/grp-1/backups?status=success&page=1&per_page=100")
        assert db.logs[-1].status == "error"
        assert any("BCServer.url deve terminar com %s" in args[0] for args in warnings)

    asyncio.run(run())


def test_discover_http_error_is_not_reported_as_success(monkeypatch):
    async def run():
        client, _, _ = _make_client("https://backup.example/api/v1/external")
        db = FakeDB(client)

        def handler(request):
            return httpx.Response(500, text="boom")

        monkeypatch.setattr(auto_discovery.httpx, "AsyncClient", _AsyncClientFactory(handler))

        response = await discover_from_link(client.id, 11, background_tasks=_BackgroundTasks(), db=db)

        assert response.status_code == 502
        assert db.logs[-1].status == "error"
        assert "HTTP 500" in db.logs[-1].detail
        assert db.assets == []

    asyncio.run(run())


def test_discover_timeout_is_logged_as_error(monkeypatch):
    async def run():
        client, _, _ = _make_client("https://backup.example/api/v1/external")
        db = FakeDB(client)

        def handler(request):
            raise httpx.TimeoutException("timed out", request=request)

        monkeypatch.setattr(auto_discovery.httpx, "AsyncClient", _AsyncClientFactory(handler))

        result = await auto_discovery.sync_discovered_assets(client.id, db, link_id=11)

        assert result["status"] == "error"
        assert result["errors"][0]["status_code"] is None
        assert "Timeout" in result["errors"][0]["message"]
        assert db.logs[-1].status == "error"

    asyncio.run(run())


def test_backup_download_uses_helper_url_without_duplication():
    async def run():
        _, _, server = _make_client("https://backup.example/api/v1/external")
        seen = []

        async def handler(request):
            seen.append(str(request.url))
            return httpx.Response(200, content=b"config")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            response = await auto_discovery._download_backup(client, server, "bk-1")

        assert response.status_code == 200
        assert seen == ["https://backup.example/api/v1/external/backups/bk-1/download"]

    asyncio.run(run())


class _BackgroundTasks:
    def add_task(self, *args, **kwargs):
        raise AssertionError("Nao deve agendar extracao quando discover falha")
