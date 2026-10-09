"""Testes de endpoints diversos: vlans, subnets, bc-links, logs, jobs."""
import pytest
from fastapi.testclient import TestClient
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


@pytest.fixture
def group_id(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json={"name": "Grupo-Misc"})
    return r.json()["id"]


@pytest.fixture
def bc_server_id(client):
    c, h = client
    r = c.post(
        "/api/backupcenter/servers",
        headers=h,
        json={"name": "BC-Misc", "url": "https://bc.local", "token": "tok"},
    )
    return r.json()["id"]


# ──────────────────────────────────────────
# VLANs e subnets
# ──────────────────────────────────────────

def test_list_vlans_empty_for_new_client(client, group_id):
    c, h = client
    r = c.get(f"/api/clients/{group_id}/vlans", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_list_subnets_empty_for_new_client(client, group_id):
    c, h = client
    r = c.get(f"/api/clients/{group_id}/subnets", headers=h)
    assert r.status_code == 200
    assert r.json() == []


# ──────────────────────────────────────────
# BC Links
# ──────────────────────────────────────────

def test_list_bc_links_empty(client, group_id):
    c, h = client
    r = c.get(f"/api/clients/{group_id}/bc-links", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_create_bc_link(client, group_id, bc_server_id):
    c, h = client
    r = c.post(
        f"/api/clients/{group_id}/bc-links",
        headers=h,
        json={"bc_server_id": bc_server_id, "external_group_id": "grp-42", "label": "Site A"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["bc_server_id"] == bc_server_id
    assert data["external_group_id"] == "grp-42"
    assert data["bc_server_name"] == "BC-Misc"


def test_create_bc_link_duplicate_returns_409(client, group_id, bc_server_id):
    c, h = client
    payload = {"bc_server_id": bc_server_id, "external_group_id": "grp-X"}
    r1 = c.post(f"/api/clients/{group_id}/bc-links", headers=h, json=payload)
    assert r1.status_code == 200
    r2 = c.post(f"/api/clients/{group_id}/bc-links", headers=h, json=payload)
    assert r2.status_code == 409
    assert r2.json()["detail"]["code"] == "bc_link_duplicate"


def test_delete_bc_link(client, group_id, bc_server_id):
    c, h = client
    created = c.post(
        f"/api/clients/{group_id}/bc-links",
        headers=h,
        json={"bc_server_id": bc_server_id, "external_group_id": "grp-del"},
    ).json()
    r = c.delete(f"/api/clients/{group_id}/bc-links/{created['id']}", headers=h)
    assert r.status_code == 200

    after = c.get(f"/api/clients/{group_id}/bc-links", headers=h).json()
    assert after == []


def test_delete_bc_link_not_found(client, group_id):
    c, h = client
    r = c.delete(f"/api/clients/{group_id}/bc-links/99999", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "bc_link_not_found"


def test_delete_bc_link_wrong_client_returns_404(client, group_id, bc_server_id):
    """Link existe mas pertence a outro cliente — deve retornar 404."""
    c, h = client
    # Cria link no group_id
    link = c.post(
        f"/api/clients/{group_id}/bc-links",
        headers=h,
        json={"bc_server_id": bc_server_id, "external_group_id": "grp-Z"},
    ).json()
    # Cria outro grupo
    other = c.post("/api/clients", headers=h, json={"name": "Outro"}).json()
    r = c.delete(f"/api/clients/{other['id']}/bc-links/{link['id']}", headers=h)
    assert r.status_code == 404


# ──────────────────────────────────────────
# Logs (per client e global)
# ──────────────────────────────────────────

def test_client_logs_empty(client, group_id):
    c, h = client
    r = c.get(f"/api/clients/{group_id}/logs", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_client_logs_pagination(client, group_id):
    c, h = client
    r = c.get(f"/api/clients/{group_id}/logs?page=2&limit=10", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_global_logs_empty(client):
    c, h = client
    r = c.get("/api/logs", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_global_logs_with_filters(client):
    c, h = client
    r = c.get("/api/logs?operation=sync_assets&status=success&client_id=1&page=1&limit=20", headers=h)
    assert r.status_code == 200


# ──────────────────────────────────────────
# Jobs (in-memory dict)
# ──────────────────────────────────────────

def test_get_job_not_found(client):
    c, h = client
    r = c.get("/api/jobs/inexistente-uuid", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "job_not_found"


# ──────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────

def test_discovery_clients_no_servers(client):
    """Sem servidores BC cadastrados, discovery retorna warning."""
    c, h = client
    r = c.post("/api/discovery/clients", headers=h)
    assert r.status_code == 200
    # função real retorna dict com status='warning' ou similar
    assert isinstance(r.json(), dict)
