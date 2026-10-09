"""Testes CRUD para servidores Backup API."""
import pytest
from fastapi.testclient import TestClient
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


def _payload(name="BC-1", url="https://bc.example.com", token="tok123"):
    return {"name": name, "url": url, "token": token}


def test_list_bc_servers_empty(client):
    c, h = client
    r = c.get("/api/backup/servers", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_create_bc_server(client):
    c, h = client
    r = c.post("/api/backup/servers", headers=h, json=_payload())
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "BC-1"
    assert data["url"] == "https://bc.example.com"
    assert data["id"] is not None


def test_create_bc_server_persists_in_listing(client):
    c, h = client
    c.post("/api/backup/servers", headers=h, json=_payload(name="BC-A"))
    c.post("/api/backup/servers", headers=h, json=_payload(name="BC-B", url="https://b.example.com"))
    r = c.get("/api/backup/servers", headers=h)
    names = [s["name"] for s in r.json()]
    assert "BC-A" in names
    assert "BC-B" in names


def test_update_bc_server(client):
    c, h = client
    created = c.post("/api/backup/servers", headers=h, json=_payload(name="BC-old")).json()
    r = c.put(
        f"/api/backup/servers/{created['id']}",
        headers=h,
        json=_payload(name="BC-new", url="https://updated.example.com", token="newtok"),
    )
    assert r.status_code == 200
    assert r.json()["name"] == "BC-new"
    assert r.json()["url"] == "https://updated.example.com"


def test_update_bc_server_not_found(client):
    c, h = client
    r = c.put("/api/backup/servers/99999", headers=h, json=_payload())
    assert r.status_code == 404


def test_delete_bc_server(client):
    c, h = client
    created = c.post("/api/backup/servers", headers=h, json=_payload(name="BC-del")).json()
    r = c.delete(f"/api/backup/servers/{created['id']}", headers=h)
    assert r.status_code == 200

    r2 = c.get("/api/backup/servers", headers=h)
    assert created["id"] not in [s["id"] for s in r2.json()]


def test_delete_bc_server_not_found_returns_200_idempotent(client):
    """delete_bc_server é idempotente — retorna 200 mesmo para id inexistente."""
    c, h = client
    r = c.delete("/api/backup/servers/99999", headers=h)
    assert r.status_code == 200
    assert "removido" in r.json()["message"].lower()
