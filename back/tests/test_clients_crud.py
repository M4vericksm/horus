"""Testes de integração CRUD — clientes (GET, POST, PUT, DELETE)."""
import pytest
from fastapi.testclient import TestClient
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


# ──────────────────────────────────────────
# GET /api/clients
# ──────────────────────────────────────────

def test_list_clients_empty(client):
    c, h = client
    r = c.get("/api/clients", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_list_clients_requires_auth(client):
    c, _ = client
    r = c.get("/api/clients")
    assert r.status_code == 401


# ──────────────────────────────────────────
# POST /api/clients
# ──────────────────────────────────────────

def test_create_client(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json={"name": "Cliente Teste"})
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "Cliente Teste"
    assert data["id"] is not None
    assert data["system"] == "phpIPAM"


def test_create_client_duplicate_name_returns_409(client):
    c, h = client
    c.post("/api/clients", headers=h, json={"name": "Duplicado"})
    r2 = c.post("/api/clients", headers=h, json={"name": "Duplicado"})
    assert r2.status_code == 409
    assert r2.json()["detail"]["code"] == "client_name_conflict"


def test_create_client_requires_name(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json={})
    assert r.status_code == 422


# ──────────────────────────────────────────
# GET /api/clients/{id}
# ──────────────────────────────────────────

def test_get_client_by_id(client):
    c, h = client
    created = c.post("/api/clients", headers=h, json={"name": "AtlasTest"}).json()
    r = c.get(f"/api/clients/{created['id']}", headers=h)
    assert r.status_code == 200
    assert r.json()["name"] == "AtlasTest"


def test_get_client_not_found(client):
    c, h = client
    r = c.get("/api/clients/99999", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "client_not_found"


# ──────────────────────────────────────────
# PUT /api/clients/{id}
# ──────────────────────────────────────────

def test_update_client(client):
    c, h = client
    created = c.post("/api/clients", headers=h, json={"name": "Original"}).json()
    r = c.put(f"/api/clients/{created['id']}", headers=h, json={"name": "Atualizado"})
    assert r.status_code == 200

    r2 = c.get(f"/api/clients/{created['id']}", headers=h)
    assert r2.json()["name"] == "Atualizado"


def test_update_client_not_found(client):
    c, h = client
    r = c.put("/api/clients/99999", headers=h, json={"name": "X"})
    assert r.status_code == 404


# ──────────────────────────────────────────
# DELETE /api/clients/{id}
# ──────────────────────────────────────────

def test_delete_client(client):
    c, h = client
    created = c.post("/api/clients", headers=h, json={"name": "ParaDeletar"}).json()
    r = c.delete(f"/api/clients/{created['id']}", headers=h)
    assert r.status_code == 200
    assert "removido" in r.json()["message"]

    r2 = c.get(f"/api/clients/{created['id']}", headers=h)
    assert r2.status_code == 404


def test_delete_client_not_found(client):
    c, h = client
    r = c.delete("/api/clients/99999", headers=h)
    assert r.status_code == 404


# ──────────────────────────────────────────
# Contagem pós-criação
# ──────────────────────────────────────────

def test_list_returns_created_clients(client):
    c, h = client
    c.post("/api/clients", headers=h, json={"name": "Alpha"})
    c.post("/api/clients", headers=h, json={"name": "Beta"})
    r = c.get("/api/clients", headers=h)
    names = [x["name"] for x in r.json()]
    assert "Alpha" in names
    assert "Beta" in names
