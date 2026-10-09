"""Cobertura extra de endpoints de orquestracao, jobs, logs e dados extraidos."""
import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

import auto_discovery
import database
import main
import models
from main import ALLOWED_ORIGINS, app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    main.GLOBAL_JOBS.clear()
    with TestClient(app) as c:
        yield c, headers
    main.GLOBAL_JOBS.clear()


def _run(coro):
    return asyncio.run(coro)


def test_cors_headers_are_present_on_session_invalid_401(client):
    c, _ = client
    origin = "http://example.test" if ALLOWED_ORIGINS == ["*"] else ALLOWED_ORIGINS[0]

    response = c.get("/api/clients", headers={"Origin": origin})

    assert response.status_code == 401
    assert "access-control-allow-origin" in response.headers


def test_list_drivers_returns_all_vendors(client):
    c, _ = client

    response = c.get("/api/drivers")

    assert response.status_code == 200
    assert len(response.json()) >= 4


def test_list_drivers_includes_known_vendors(client):
    c, _ = client

    response = c.get("/api/drivers")
    vendor_keys = {item["vendor_key"] for item in response.json()}

    assert {"cisco", "datacom", "huawei", "mikrotik"}.issubset(vendor_keys)


def test_list_drivers_returns_metadata_keys(client):
    c, _ = client

    response = c.get("/api/drivers")
    expected_keys = {
        "vendor_key",
        "display_name",
        "supports_ssh_extract",
        "supports_bc_extract",
    }

    assert all(set(item) == expected_keys for item in response.json())


class _QueuedAsyncClient:
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

    async def request(self, method, url, **kwargs):
        return await self.get(url, **kwargs)


async def _seed_extracted_data():
    async with database.AsyncSessionLocal() as db:
        group = models.Client(name="Grupo Extra")
        asset = models.Asset(hostname="SW-Extra", client=group, is_approved=True)
        vlan = models.Vlan(vid=100, name="CORP", description="Usuarios", client=group, asset=asset)
        subnet = models.Subnet(network="10.100.0.0", mask=24, description="Usuarios", client=group, asset=asset)
        db.add_all([group, asset, vlan, subnet])
        await db.commit()
        await db.refresh(group)
        return group.id


async def _seed_logs():
    async with database.AsyncSessionLocal() as db:
        db.add_all(
            [
                models.ExecutionLog(client_id=1, operation="sync_phpipam", status="error", message="falha"),
                models.ExecutionLog(client_id=1, operation="extract_bc", status="success", message="ok"),
                models.ExecutionLog(client_id=2, operation="sync_phpipam", status="error", message="outro"),
            ]
        )
        await db.commit()


def test_discover_assets_endpoint_calls_discovery_and_extract(client, monkeypatch):
    c, h = client
    calls = []

    async def fake_sync(client_id, db):
        calls.append(("sync", client_id))
        return {"status": "success", "added": 2, "message": "ok"}

    async def fake_extract(client_id, db):
        calls.append(("extract", client_id))
        return {"message": "extraido"}

    monkeypatch.setattr(auto_discovery, "sync_discovered_assets", fake_sync)
    monkeypatch.setattr(auto_discovery, "extract_client_configs_bc", fake_extract)

    r = c.post("/api/clients/123/discover-assets", headers=h)

    assert r.status_code == 200
    assert r.json()["added"] == 2
    assert calls == [("sync", 123), ("extract", 123)]


def test_discover_assets_endpoint_wraps_unexpected_error(client, monkeypatch):
    c, h = client

    async def fake_sync(client_id, db):
        raise RuntimeError("BC offline")

    monkeypatch.setattr(auto_discovery, "sync_discovered_assets", fake_sync)

    r = c.post("/api/clients/123/discover-assets", headers=h)

    assert r.status_code == 502
    assert r.json()["detail"]["code"] == "bc_unreachable"


def test_discover_from_link_success_schedules_background_extract(client, monkeypatch):
    c, h = client
    calls = []

    async def fake_sync(client_id, db, link_id=None):
        calls.append(("sync", client_id, link_id))
        return {"status": "success", "added": 1}

    async def fake_bg(client_id):
        calls.append(("bg", client_id))

    monkeypatch.setattr(auto_discovery, "sync_discovered_assets", fake_sync)
    monkeypatch.setattr(main, "_run_extract_bg", fake_bg)

    r = c.post("/api/clients/1/bc-links/7/discover", headers=h)

    assert r.status_code == 200
    assert r.json()["added"] == 1
    assert calls == [("sync", 1, 7), ("bg", 1)]


def test_discover_from_link_returns_502_when_link_sync_fails(client, monkeypatch):
    c, h = client

    async def fake_sync(client_id, db, link_id=None):
        return {"status": "error", "message": "falhou", "errors": [{"message": "timeout"}]}

    monkeypatch.setattr(auto_discovery, "sync_discovered_assets", fake_sync)

    r = c.post("/api/clients/1/bc-links/7/discover", headers=h)

    assert r.status_code == 502
    assert r.json()["status"] == "error"


def test_resolve_vlan_conflicts_endpoint_passes_schema_payload(client, monkeypatch):
    c, h = client
    seen = {}

    async def fake_resolve(client_id, resolutions, db):
        seen["client_id"] = client_id
        seen["resolutions"] = resolutions
        return {"resolved": 1, "errors": [], "message": "ok"}

    monkeypatch.setattr(auto_discovery, "resolve_vlan_conflicts", fake_resolve)

    r = c.post(
        "/api/clients/5/resolve-vlan-conflicts",
        headers=h,
        json={
            "resolutions": [
                {
                    "vid": 10,
                    "asset_id": 20,
                    "domain_id": 1,
                    "vlan_ipam_id": "123",
                    "local_vlan_id": 30,
                    "new_name": "USERS",
                    "action": "update_name",
                }
            ]
        },
    )

    assert r.status_code == 200
    assert r.json()["resolved"] == 1
    assert seen["client_id"] == 5
    assert seen["resolutions"][0]["vid"] == 10


def test_resolve_vlan_conflicts_endpoint_wraps_error(client, monkeypatch):
    c, h = client

    async def fake_resolve(client_id, resolutions, db):
        raise RuntimeError("falha")

    monkeypatch.setattr(auto_discovery, "resolve_vlan_conflicts", fake_resolve)

    r = c.post(
        "/api/clients/5/resolve-vlan-conflicts",
        headers=h,
        json={"resolutions": [{"vid": 10, "asset_id": 20, "domain_id": 1, "action": "update_name"}]},
    )

    assert r.status_code == 502
    assert r.json()["detail"]["code"] == "ipam_conflict_resolution_failed"


def test_extracted_data_routes_return_vlans_and_subnets(client):
    c, h = client
    group_id = _run(_seed_extracted_data())

    vlans = c.get(f"/api/clients/{group_id}/vlans", headers=h)
    subnets = c.get(f"/api/clients/{group_id}/subnets", headers=h)

    assert vlans.status_code == 200
    assert vlans.json()[0]["vid"] == 100
    assert subnets.status_code == 200
    assert subnets.json()[0]["network"] == "10.100.0.0"


def test_logs_endpoints_filter_global_and_client_logs(client):
    c, h = client
    _run(_seed_logs())

    global_logs = c.get("/api/logs?operation=sync_phpipam&status=error&client_id=1", headers=h)
    client_logs = c.get("/api/clients/1/logs?limit=10", headers=h)

    assert global_logs.status_code == 200
    assert len(global_logs.json()) == 1
    assert global_logs.json()[0]["message"] == "falha"
    assert client_logs.status_code == 200
    assert {log["client_id"] for log in client_logs.json()} == {1}


def test_backup_discover_all_groups_success_and_error(client, monkeypatch):
    c, h = client

    async def ok(db, *, extract_configs=False, job=None):
        return {"status": "success", "groups_created": 1}

    monkeypatch.setattr(main, "_sync_bc_groups_and_assets", ok)
    r1 = c.post("/api/backup/discover-all-groups", headers=h)
    assert r1.status_code == 200
    assert r1.json()["groups_created"] == 1

    async def err(db, *, extract_configs=False, job=None):
        return {"status": "error", "message": "BC offline"}

    monkeypatch.setattr(main, "_sync_bc_groups_and_assets", err)
    r2 = c.post("/api/backup/discover-all-groups", headers=h)
    assert r2.status_code == 502
    assert r2.json()["message"] == "BC offline"


def test_global_extract_job_endpoint_creates_reuses_and_fetches_job(client, monkeypatch):
    c, h = client

    async def no_op_job(job_id):
        return None

    monkeypatch.setattr(main, "_run_global_extract_job", no_op_job)

    created = c.post("/api/backup/extract-all", headers=h)
    assert created.status_code == 200
    job_id = created.json()["job_id"]
    assert main.GLOBAL_JOBS[job_id]["status"] == "queued"

    fetched = c.get(f"/api/jobs/{job_id}", headers=h)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == job_id

    duplicate = c.post("/api/backup/extract-all", headers=h)
    assert duplicate.status_code == 200
    assert duplicate.json()["job_id"] == job_id

    missing = c.get("/api/jobs/missing", headers=h)
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "job_not_found"


def test_sync_phpipam_endpoint_success_and_error(client, monkeypatch):
    c, h = client

    async def ok(client_id, db):
        return {"message": "phpIPAM ok"}

    monkeypatch.setattr(auto_discovery, "sync_data_to_phpipam", ok)
    assert c.post("/api/clients/1/sync-phpipam", headers=h).json()["message"] == "phpIPAM ok"

    async def boom(client_id, db):
        raise RuntimeError("falha")

    monkeypatch.setattr(auto_discovery, "sync_data_to_phpipam", boom)
    r = c.post("/api/clients/1/sync-phpipam", headers=h)
    assert r.status_code == 502
    assert r.json()["detail"]["code"] == "ipam_sync_failed"


def test_sync_netbox_endpoint_success_and_error(client, monkeypatch):
    c, h = client

    async def ok(client_id, db):
        return {"message": "NetBox ok"}

    monkeypatch.setattr(auto_discovery, "sync_data_to_netbox", ok)
    assert c.post("/api/clients/1/sync-netbox", headers=h).json()["message"] == "NetBox ok"

    async def boom(client_id, db):
        raise RuntimeError("falha")

    monkeypatch.setattr(auto_discovery, "sync_data_to_netbox", boom)
    r = c.post("/api/clients/1/sync-netbox", headers=h)
    assert r.status_code == 502
    assert r.json()["detail"]["code"] == "netbox_sync_failed"


def test_create_l2_domain_endpoint_success_400_and_502(client, monkeypatch):
    c, h = client

    async def ok(client_id, name, db):
        return {"id": 10, "name": name}

    monkeypatch.setattr(auto_discovery, "create_l2_domain_phpipam", ok)
    assert c.post("/api/clients/1/create-l2-domain", headers=h, json={"name": "L2"}).json()["id"] == 10

    async def domain_error(client_id, name, db):
        return {"error": "sem permissao"}

    monkeypatch.setattr(auto_discovery, "create_l2_domain_phpipam", domain_error)
    r400 = c.post("/api/clients/1/create-l2-domain", headers=h, json={"name": "L2"})
    assert r400.status_code == 400
    assert r400.json()["detail"]["code"] == "ipam_l2_domain_create_failed"

    async def boom(client_id, name, db):
        raise RuntimeError("falha")

    monkeypatch.setattr(auto_discovery, "create_l2_domain_phpipam", boom)
    r502 = c.post("/api/clients/1/create-l2-domain", headers=h, json={"name": "L2"})
    assert r502.status_code == 502


def test_create_vlan_group_endpoint_success_400_and_502(client, monkeypatch):
    c, h = client

    async def ok(client_id, name, db):
        return {"id": 10, "name": name}

    monkeypatch.setattr(auto_discovery, "create_vlan_group_netbox", ok)
    assert c.post("/api/clients/1/create-vlan-group", headers=h, json={"name": "VG"}).json()["id"] == 10

    async def group_error(client_id, name, db):
        return {"error": "sem permissao"}

    monkeypatch.setattr(auto_discovery, "create_vlan_group_netbox", group_error)
    r400 = c.post("/api/clients/1/create-vlan-group", headers=h, json={"name": "VG"})
    assert r400.status_code == 400
    assert r400.json()["detail"]["code"] == "netbox_vlan_group_create_failed"

    async def boom(client_id, name, db):
        raise RuntimeError("falha")

    monkeypatch.setattr(auto_discovery, "create_vlan_group_netbox", boom)
    r502 = c.post("/api/clients/1/create-vlan-group", headers=h, json={"name": "VG"})
    assert r502.status_code == 502


def test_extract_configs_manual_endpoint_success_and_error(client, monkeypatch):
    c, h = client

    async def ok(client_id, db):
        return {"message": "manual ok"}

    monkeypatch.setattr(auto_discovery, "extract_client_configs_manual", ok)
    assert c.post("/api/clients/1/extract-configs-manual", headers=h).json()["message"] == "manual ok"

    async def boom(client_id, db):
        raise RuntimeError("falha")

    monkeypatch.setattr(auto_discovery, "extract_client_configs_manual", boom)
    r = c.post("/api/clients/1/extract-configs-manual", headers=h)
    assert r.status_code == 502
    assert r.json()["detail"]["code"] == "ssh_extract_failed"


def test_backup_remote_group_and_asset_routes_cover_success_and_errors(client, monkeypatch):
    c, h = client
    server = c.post(
        "/api/backup/servers",
        headers=h,
        json={"name": "BC-remote", "url": "https://bc.remote/api/v1/external", "token": "tok"},
    ).json()
    group = c.post(
        "/api/clients",
        headers=h,
        json={
            "name": "Grupo BC remoto",
            "bc_server_id": server["id"],
            "external_group_id": "grp-remote",
        },
    ).json()
    http_client = _QueuedAsyncClient(
        [
            httpx.Response(200, json={"groups": [{"id": "grp-remote", "name": "Grupo remoto"}]}),
            httpx.Response(200, json={"items": [{"id": "backup-1", "device_name": "SW-1"}]}),
            RuntimeError("BC caiu"),
        ]
    )
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: http_client)

    groups = c.get(f"/api/backup/servers/{server['id']}/groups", headers=h)
    assets = c.get("/api/backup/groups/grp-remote/assets", headers=h)
    missing_server = c.get("/api/backup/servers/999999/groups", headers=h)
    failed_groups = c.get(f"/api/backup/servers/{server['id']}/groups", headers=h)
    missing_group = c.get("/api/backup/groups/grp-missing/assets", headers=h)

    assert group["external_group_id"] == "grp-remote"
    assert groups.status_code == 200
    assert groups.json()[0]["name"] == "Grupo remoto"
    assert assets.status_code == 200
    assert assets.json()[0]["device_name"] == "SW-1"
    assert missing_server.status_code == 404
    assert missing_server.json()["detail"]["code"] == "bc_server_not_found"
    assert failed_groups.status_code == 200
    assert failed_groups.json() == []
    assert missing_group.status_code == 200
    assert missing_group.json() == []


def test_phpipam_probe_and_remote_lookup_routes(client, monkeypatch):
    c, h = client
    token_calls = []
    http_client = _QueuedAsyncClient(
        [
            httpx.Response(200, json={"data": [{"id": 1, "name": "L2"}]}),
            httpx.Response(200, json={"data": [{"id": 2, "name": "Secao"}]}),
            httpx.Response(200, json={"data": [{"id": 3, "name": "L2 Remoto"}]}),
            httpx.Response(200, json={"data": [{"id": 4, "name": "Secao Remota"}]}),
        ]
    )

    async def fake_token(base_url, token_name, user, password):
        token_calls.append((base_url, token_name, user, password))
        return "fresh-token"

    monkeypatch.setattr(auto_discovery, "_get_phpipam_token", fake_token)
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: http_client)

    probe = c.post(
        "/api/phpipam/probe",
        headers=h,
        json={
            "ip": "https://example.com",
            "token_name": "horus",
            "token": "stale-token",
            "phpipam_user": "svc",
            "phpipam_pass": "secret",
        },
    )
    group = c.post(
        "/api/clients",
        headers=h,
        json={
            "name": "Grupo phpIPAM remoto",
            "ip": "https://example.com",
            "token_name": "horus",
            "token": "stored-token",
            "phpipam_user": "svc",
            "phpipam_pass": "secret",
        },
    ).json()
    l2_domains = c.get(f"/api/clients/{group['id']}/remote-l2-domains", headers=h)
    sections = c.get(f"/api/clients/{group['id']}/remote-sections", headers=h)

    assert probe.status_code == 200
    assert probe.json()["ok"] is True
    assert probe.json()["l2_domains"][0]["name"] == "L2"
    assert probe.json()["sections"][0]["name"] == "Secao"
    assert l2_domains.json()[0]["name"] == "L2 Remoto"
    assert sections.json()[0]["name"] == "Secao Remota"
    assert token_calls[0] == ("https://example.com", "horus", "svc", "secret")


def test_phpipam_probe_error_branches(client, monkeypatch):
    c, h = client
    first_http = _QueuedAsyncClient([httpx.Response(500, json={"error": "boom"})])
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: first_http)

    bad_status = c.post(
        "/api/phpipam/probe",
        headers=h,
        json={"ip": "https://example.com", "token_name": "horus", "token": "tok"},
    )
    assert bad_status.status_code == 200
    assert bad_status.json()["error"] == "phpIPAM retornou 500"

    second_http = _QueuedAsyncClient([RuntimeError("sem rota")])
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: second_http)

    failed = c.post(
        "/api/phpipam/probe",
        headers=h,
        json={"ip": "https://example.com", "token_name": "horus", "token": "tok"},
    )
    assert failed.status_code == 200
    assert failed.json()["error"] == "sem rota"


def test_netbox_probe_and_remote_lookup_routes(client, monkeypatch):
    c, h = client
    http_client = _QueuedAsyncClient(
        [
            httpx.Response(200, json={"results": [{"id": 1, "name": "VG"}]}),
            httpx.Response(200, json={"results": [{"id": 2, "name": "Site"}]}),
            httpx.Response(200, json={"results": [{"id": 3, "name": "VG Remoto"}]}),
            httpx.Response(200, json={"results": [{"id": 4, "name": "Site Remoto"}]}),
        ]
    )
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: http_client)

    probe = c.post(
        "/api/netbox/probe",
        headers=h,
        json={"ip": "https://example.com", "token": "nbt_secret"},
    )
    group = c.post(
        "/api/clients",
        headers=h,
        json={
            "name": "Grupo NetBox remoto",
            "system": "netbox",
            "netbox_url": "https://example.com",
            "netbox_token": "nbt_secret",
        },
    ).json()
    vlan_groups = c.get(f"/api/clients/{group['id']}/remote-vlan-groups", headers=h)
    sites = c.get(f"/api/clients/{group['id']}/remote-sites", headers=h)

    assert probe.status_code == 200
    assert probe.json()["ok"] is True
    assert probe.json()["vlan_groups"][0]["name"] == "VG"
    assert probe.json()["sites"][0]["name"] == "Site"
    assert vlan_groups.json()[0]["name"] == "VG Remoto"
    assert sites.json()[0]["name"] == "Site Remoto"
    assert http_client.requests[0][1]["headers"]["Authorization"] == "Bearer nbt_secret"


def test_netbox_probe_error_branches(client, monkeypatch):
    c, h = client
    bad_status_client = _QueuedAsyncClient([httpx.Response(503, json={"detail": "down"})])
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: bad_status_client)

    bad_status = c.post(
        "/api/netbox/probe",
        headers=h,
        json={"ip": "https://example.com", "token": "plain-token"},
    )
    assert bad_status.status_code == 200
    assert bad_status.json()["error"] == "NetBox retornou 503"

    failed_client = _QueuedAsyncClient([RuntimeError("sem dns")])
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *args, **kwargs: failed_client)

    failed = c.post(
        "/api/netbox/probe",
        headers=h,
        json={"ip": "https://example.com", "token": "plain-token"},
    )
    assert failed.status_code == 200
    assert failed.json()["error"] == "sem dns"
