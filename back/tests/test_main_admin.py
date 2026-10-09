"""Cobertura de fluxos administrativos globais em main.py."""

import asyncio

import httpx
import pytest

import auto_discovery
import main
import models


class _ScalarResult:
    def __init__(self, values):
        self.values = list(values)

    def scalars(self):
        return self

    def all(self):
        return self.values

    def first(self):
        return self.values[0] if self.values else None


class _FakeDB:
    def __init__(self, servers=None, clients=None):
        self.servers = list(servers or [])
        self.clients = list(clients or [])
        self.commits = 0
        self.rollbacks = 0
        self._next_client_id = 100

    async def execute(self, stmt):
        entity = stmt.column_descriptions[0]["entity"]
        params = stmt.compile().params

        if entity is models.BCServer:
            return _ScalarResult(self.servers)

        if entity is models.Client:
            if "external_group_id_1" in params:
                ext_id = params["external_group_id_1"]
                return _ScalarResult([c for c in self.clients if c.external_group_id == ext_id])
            if "name_1" in params:
                name = params["name_1"]
                exclude_id = next((v for k, v in params.items() if k.startswith("id_")), None)
                return _ScalarResult(
                    [c for c in self.clients if c.name == name and c.id != exclude_id]
                )
            return _ScalarResult(self.clients)

        raise AssertionError(f"Consulta inesperada: {stmt}")

    def add(self, item):
        if isinstance(item, models.Client):
            item.id = self._next_client_id
            self._next_client_id += 1
            self.clients.append(item)
            return
        raise AssertionError(f"Objeto inesperado: {item!r}")

    async def commit(self):
        self.commits += 1

    async def refresh(self, item):
        return None

    async def rollback(self):
        self.rollbacks += 1

    async def get(self, model, item_id):
        if model is models.BCServer:
            return next((server for server in self.servers if server.id == item_id), None)
        if model is models.Client:
            return next((client for client in self.clients if client.id == item_id), None)
        return None


class _FakeAsyncClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        self.requests.append((url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _run(coro):
    return asyncio.run(coro)


def _server(server_id=1, name="BC", url="https://bc.example/api/v1/external"):
    return models.BCServer(id=server_id, name=name, url=url, token="secret-token")


def test_sync_bc_groups_and_assets_warns_when_no_servers():
    db = _FakeDB()

    result = _run(main._sync_bc_groups_and_assets(db))

    assert result["status"] == "warning"
    assert result["message"] == "Nenhum servidor BackupCenter cadastrado."
    assert result["servers"] == 0


def test_sync_bc_groups_and_assets_creates_updates_extracts_and_reports_partial(monkeypatch):
    existing = models.Client(
        id=5,
        name="Nome antigo",
        external_group_id="grp-existing",
        bc_server_id=None,
        vlan_prefix=None,
    )
    db = _FakeDB(servers=[_server()], clients=[existing])
    http_client = _FakeAsyncClient(
        [
            httpx.Response(
                200,
                json={
                    "groups": [
                        {"id": "grp-new", "name": "Grupo novo"},
                        {"id": "grp-skip"},
                        {"id": "grp-existing", "name": "Grupo existente"},
                    ]
                },
            )
        ]
    )
    job = {}
    synced = []
    extracted = []

    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: http_client)

    async def fake_sync(client_id, db_arg):
        synced.append(client_id)
        return {"status": "success", "added": 2, "restored": 1}

    async def fake_extract(client_id, db_arg):
        extracted.append(client_id)
        if client_id == existing.id:
            return {"error": "config invalida"}
        return {"message": "ok"}

    monkeypatch.setattr(auto_discovery, "sync_discovered_assets", fake_sync)
    monkeypatch.setattr(auto_discovery, "extract_client_configs_bc", fake_extract)

    result = _run(main._sync_bc_groups_and_assets(db, extract_configs=True, job=job))

    assert result["status"] == "partial"
    assert result["groups_seen"] == 2
    assert result["clients_created"] == 1
    assert result["clients_synced"] == 2
    assert result["assets_added"] == 4
    assert result["assets_restored"] == 2
    assert result["extracted"] == 1
    assert result["errors"][0]["message"] == "config invalida"
    assert existing.bc_server_id == 1
    assert existing.name == "Grupo existente"
    assert existing.vlan_prefix == "[Grupo existente]"
    assert synced == [100, 5]
    assert extracted == [100, 5]
    assert job["progress"]["errors"] == 1


def test_sync_bc_groups_and_assets_collects_http_and_server_errors(monkeypatch):
    db = _FakeDB(
        servers=[
            _server(1, "BC HTTP"),
            _server(2, "BC Timeout"),
        ]
    )
    http_client = _FakeAsyncClient(
        [
            httpx.Response(503, json={"detail": "indisponivel"}),
            httpx.TimeoutException("tempo esgotado"),
        ]
    )
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: http_client)

    result = _run(main._sync_bc_groups_and_assets(db))

    assert result["status"] == "error"
    assert result["groups_seen"] == 0
    assert result["errors"][0]["server_name"] == "BC HTTP"
    assert "HTTP 503" in result["errors"][0]["message"]
    assert result["errors"][1]["server_name"] == "BC Timeout"
    assert "tempo esgotado" in result["errors"][1]["message"]
    assert db.rollbacks == 1


def test_unique_client_name_adds_suffix_when_name_already_exists():
    db = _FakeDB(
        clients=[
            models.Client(id=1, name="Grupo"),
            models.Client(id=2, name="Grupo (2)"),
        ]
    )

    result = _run(main._unique_client_name(db, "Grupo"))

    assert result == "Grupo (3)"


def test_fetch_bc_groups_direct_covers_success_missing_and_exception(monkeypatch):
    db = _FakeDB(servers=[_server(7)])
    http_client = _FakeAsyncClient(
        [
            httpx.Response(200, json={"groups": [{"id": "grp-1", "name": "Grupo 1"}]}),
            RuntimeError("falha de rede"),
        ]
    )
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: http_client)

    result = _run(main.fetch_bc_groups(7, db))
    assert result == [{"id": "grp-1", "name": "Grupo 1"}]

    with pytest.raises(main.HTTPException) as exc:
        _run(main.fetch_bc_groups(999, db))
    assert exc.value.status_code == 404
    assert exc.value.detail["code"] == "bc_server_not_found"

    failed = _run(main.fetch_bc_groups(7, db))
    assert failed == []


def test_fetch_bc_assets_direct_covers_success_empty_and_exception(monkeypatch):
    server = _server(8)
    client = models.Client(id=10, name="Grupo", external_group_id="grp-10", bc_server_id=8)
    db = _FakeDB(servers=[server], clients=[client])
    http_client = _FakeAsyncClient(
        [
            httpx.Response(200, json={"items": [{"id": "bk-1", "device_name": "SW-1"}]}),
            RuntimeError("falha de rede"),
        ]
    )
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: http_client)

    result = _run(main.fetch_bc_assets("grp-10", db))
    assert result == [{"id": "bk-1", "device_name": "SW-1"}]

    assert _run(main.fetch_bc_assets("grp-missing", db)) == []

    failed = _run(main.fetch_bc_assets("grp-10", db))
    assert failed == []
