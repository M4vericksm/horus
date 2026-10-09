"""Testes de endpoints de probe/test com HTTP mockado via respx."""
import pytest
import respx
import httpx
from fastapi.testclient import TestClient
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


# ──────────────────────────────────────────
# /api/backupcenter/servers/test
# ──────────────────────────────────────────

@respx.mock
def test_bc_server_test_success(client):
    c, h = client
    respx.get(url__regex=r".*/groups.*").mock(
        return_value=httpx.Response(200, json={"groups": []})
    )
    r = c.post(
        "/api/backupcenter/servers/test",
        headers=h,
        json={"url": "https://8.8.8.8", "token": "t"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True


@respx.mock
def test_bc_server_test_unauthorized(client):
    c, h = client
    respx.get(url__regex=r".*/groups.*").mock(
        return_value=httpx.Response(401)
    )
    r = c.post(
        "/api/backupcenter/servers/test",
        headers=h,
        json={"url": "https://8.8.8.8", "token": "wrong"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert r.json()["auth_error"] is True


@respx.mock
def test_bc_server_test_500_returns_warning(client):
    c, h = client
    respx.get(url__regex=r".*/groups.*").mock(
        return_value=httpx.Response(500)
    )
    r = c.post(
        "/api/backupcenter/servers/test",
        headers=h,
        json={"url": "https://8.8.8.8", "token": "t"},
    )
    body = r.json()
    assert body["ok"] is False
    assert "HTTP 500" in body["message"]


@respx.mock
def test_bc_server_test_timeout(client):
    c, h = client
    respx.get(url__regex=r".*/groups.*").mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    r = c.post(
        "/api/backupcenter/servers/test",
        headers=h,
        json={"url": "https://8.8.8.8", "token": "t"},
    )
    body = r.json()
    assert body["ok"] is False
    assert "timeout" in body["message"].lower() or "demorou" in body["message"].lower()


@respx.mock
def test_bc_server_test_ssl_error(client):
    c, h = client
    respx.get(url__regex=r".*/groups.*").mock(
        side_effect=httpx.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")
    )
    r = c.post(
        "/api/backupcenter/servers/test",
        headers=h,
        json={"url": "https://8.8.8.8", "token": "t"},
    )
    body = r.json()
    assert body["ok"] is False
    assert body["ssl_error"] is True


# ──────────────────────────────────────────
# /api/phpipam/test
# ──────────────────────────────────────────

@respx.mock
def test_phpipam_test_success(client):
    c, h = client
    respx.get(url__regex=r".*/api/.+/sections/.*").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    r = c.post(
        "/api/phpipam/test",
        headers=h,
        json={"url": "https://8.8.4.4", "token_name": "app", "token": "t"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True


@respx.mock
def test_phpipam_test_401_auth_error(client):
    c, h = client
    respx.get(url__regex=r".*/sections/.*").mock(return_value=httpx.Response(401))
    r = c.post(
        "/api/phpipam/test",
        headers=h,
        json={"url": "https://8.8.4.4", "token_name": "app", "token": "wrong"},
    )
    assert r.json()["auth_error"] is True


@respx.mock
def test_phpipam_test_404_endpoint(client):
    c, h = client
    respx.get(url__regex=r".*/sections/.*").mock(return_value=httpx.Response(404))
    r = c.post(
        "/api/phpipam/test",
        headers=h,
        json={"url": "https://8.8.4.4", "token_name": "wrong-app", "token": "t"},
    )
    body = r.json()
    assert body["ok"] is False
    assert "404" in body["message"] or "encontrado" in body["message"].lower()


# ──────────────────────────────────────────
# /api/netbox/probe
# ──────────────────────────────────────────

@respx.mock
def test_netbox_probe_success(client):
    c, h = client
    respx.get(url__regex=r".*/api/ipam/vlan-groups/.*").mock(
        return_value=httpx.Response(200, json={"results": [{"id": 1, "name": "G1"}]})
    )
    respx.get(url__regex=r".*/api/dcim/sites/.*").mock(
        return_value=httpx.Response(200, json={"results": [{"id": 1, "name": "SP"}]})
    )
    r = c.post(
        "/api/netbox/probe",
        headers=h,
        json={"ip": "https://9.9.9.9", "token": "tok"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert len(body["vlan_groups"]) == 1
    assert len(body["sites"]) == 1


@respx.mock
def test_netbox_probe_returns_error_on_non_200(client):
    c, h = client
    respx.get(url__regex=r".*/api/ipam/vlan-groups/.*").mock(
        return_value=httpx.Response(403)
    )
    r = c.post(
        "/api/netbox/probe",
        headers=h,
        json={"ip": "https://9.9.9.9", "token": "tok"},
    )
    body = r.json()
    assert body["ok"] is False
    assert "403" in (body["error"] or "")


# ──────────────────────────────────────────
# /api/phpipam/probe
# ──────────────────────────────────────────

@respx.mock
def test_phpipam_probe_success(client):
    c, h = client
    respx.get(url__regex=r".*/api/.+/l2domains/all/.*").mock(
        return_value=httpx.Response(200, json={"data": [{"id": 1, "name": "default"}]})
    )
    respx.get(url__regex=r".*/api/.+/sections/.*").mock(
        return_value=httpx.Response(200, json={"data": [{"id": 1, "name": "Customers"}]})
    )
    r = c.post(
        "/api/phpipam/probe",
        headers=h,
        json={"ip": "https://8.8.4.4", "token_name": "app", "token": "t"},
    )
    body = r.json()
    assert body["ok"] is True
    assert len(body["l2_domains"]) == 1
    assert len(body["sections"]) == 1
