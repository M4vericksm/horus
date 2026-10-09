"""Testes CRUD para ativos (assets)."""
import pytest
from fastapi.testclient import TestClient
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


@pytest.fixture
def client_with_group(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json={"name": "GrupoTeste"})
    assert r.status_code == 200
    return c, h, r.json()["id"]


def _asset_payload(client_id, hostname="sw-01", **overrides):
    base = {
        "hostname": hostname,
        "client_id": client_id,
        "ip_address": "10.0.0.1",
        "vendor": "mikrotik",
        "model": "CCR2004",
        "serial_number": "ABC123",
        "category": "borda",
    }
    base.update(overrides)
    return base


def test_create_asset_manual(client_with_group):
    c, h, gid = client_with_group
    r = c.post("/api/assets", headers=h, json=_asset_payload(gid))
    assert r.status_code == 200
    assert "adicionado" in r.json()["message"].lower()


def test_list_assets_for_client(client_with_group):
    c, h, gid = client_with_group
    c.post("/api/assets", headers=h, json=_asset_payload(gid, hostname="sw-a"))
    c.post("/api/assets", headers=h, json=_asset_payload(gid, hostname="sw-b", ip_address="10.0.0.2"))
    r = c.get(f"/api/clients/{gid}/assets", headers=h)
    assert r.status_code == 200
    hostnames = [a["hostname"] for a in r.json()]
    assert "sw-a" in hostnames
    assert "sw-b" in hostnames


def test_list_assets_empty_when_no_assets(client_with_group):
    c, h, gid = client_with_group
    r = c.get(f"/api/clients/{gid}/assets", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_update_asset(client_with_group):
    c, h, gid = client_with_group
    # Cria e descobre o id via listing
    c.post("/api/assets", headers=h, json=_asset_payload(gid, hostname="orig"))
    asset = c.get(f"/api/clients/{gid}/assets", headers=h).json()[0]

    r = c.put(f"/api/assets/{asset['id']}", headers=h, json={"hostname": "novo-hostname", "model": "RB5009"})
    assert r.status_code == 200

    refreshed = c.get(f"/api/clients/{gid}/assets", headers=h).json()[0]
    assert refreshed["hostname"] == "novo-hostname"
    assert refreshed["model"] == "RB5009"


def test_update_asset_not_found(client_with_group):
    c, h, _ = client_with_group
    r = c.put("/api/assets/99999", headers=h, json={"hostname": "x"})
    assert r.status_code == 404


def test_delete_asset(client_with_group):
    c, h, gid = client_with_group
    c.post("/api/assets", headers=h, json=_asset_payload(gid, hostname="del-me"))
    asset = c.get(f"/api/clients/{gid}/assets", headers=h).json()[0]

    r = c.delete(f"/api/assets/{asset['id']}", headers=h)
    assert r.status_code == 200

    after = c.get(f"/api/clients/{gid}/assets", headers=h).json()
    assert all(a["id"] != asset["id"] for a in after)


def test_delete_asset_not_found(client_with_group):
    c, h, _ = client_with_group
    r = c.delete("/api/assets/99999", headers=h)
    assert r.status_code == 404


def test_update_asset_hostname_keep_token_is_ignored(client_with_group):
    """Hostname='KEEP' não deve substituir o hostname atual."""
    c, h, gid = client_with_group
    c.post("/api/assets", headers=h, json=_asset_payload(gid, hostname="original"))
    asset = c.get(f"/api/clients/{gid}/assets", headers=h).json()[0]

    c.put(f"/api/assets/{asset['id']}", headers=h, json={"hostname": "KEEP", "model": "RB5009"})
    refreshed = c.get(f"/api/clients/{gid}/assets", headers=h).json()[0]
    assert refreshed["hostname"] == "original"
    assert refreshed["model"] == "RB5009"
