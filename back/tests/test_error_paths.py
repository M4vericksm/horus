"""Cobertura de branches de erro (404/400/502) dos endpoints de integração."""
import pytest
from fastapi.testclient import TestClient
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


# ──────────────────────────────────────────
# fetch_bc_groups — 404 servidor inexistente
# ──────────────────────────────────────────

def test_fetch_bc_groups_server_not_found(client):
    c, h = client
    r = c.get("/api/backup/servers/99999/groups", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "bc_server_not_found"


# ──────────────────────────────────────────
# Endpoints test (BC/phpIPAM) — bloqueio anti-SSRF
# ──────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/",
    "http://169.254.169.254/",
    "http://[::1]/",
])
def test_bc_test_blocks_private_urls(client, url):
    c, h = client
    r = c.post(
        "/api/backup/servers/test",
        headers=h,
        json={"url": url, "token": "any"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "url_blocked"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://169.254.169.254/metadata",
])
def test_phpipam_test_blocks_private_urls(client, url):
    c, h = client
    r = c.post(
        "/api/phpipam/test",
        headers=h,
        json={"url": url, "token_name": "app", "token": "t"},
    )
    assert r.status_code == 400


def test_netbox_probe_blocks_private_url(client):
    c, h = client
    r = c.post(
        "/api/netbox/probe",
        headers=h,
        json={"ip": "http://127.0.0.1/", "token": "tok"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "url_blocked"


def test_phpipam_probe_blocks_private_url(client):
    c, h = client
    r = c.post(
        "/api/phpipam/probe",
        headers=h,
        json={"ip": "http://127.0.0.1/", "token_name": "app", "token": "t"},
    )
    assert r.status_code == 400


# ──────────────────────────────────────────
# Cliente inexistente em endpoints que dependem de cliente
# ──────────────────────────────────────────

def test_remote_l2_domains_returns_empty_when_client_missing(client):
    c, h = client
    r = c.get("/api/clients/99999/remote-l2-domains", headers=h)
    # endpoint retorna [] (lista vazia) quando cliente não tem ip/token
    assert r.status_code == 200
    assert r.json() == []


def test_remote_sections_returns_empty_when_client_missing(client):
    c, h = client
    r = c.get("/api/clients/99999/remote-sections", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_remote_vlan_groups_returns_empty_when_client_missing(client):
    c, h = client
    r = c.get("/api/clients/99999/remote-vlan-groups", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_remote_sites_returns_empty_when_client_missing(client):
    c, h = client
    r = c.get("/api/clients/99999/remote-sites", headers=h)
    assert r.status_code == 200
    assert r.json() == []


# ──────────────────────────────────────────
# Endpoints background (extract, sync) com cliente inexistente
# ──────────────────────────────────────────

def test_extract_configs_starts_background_even_for_unknown_client(client):
    """extract-configs apenas agenda em background — não valida cliente."""
    c, h = client
    r = c.post("/api/clients/99999/extract-configs", headers=h)
    assert r.status_code == 200
    assert "background" in r.json()["message"].lower() or "segundo plano" in r.json()["message"].lower()


def test_extract_configs_bc_starts_background(client):
    c, h = client
    r = c.post("/api/clients/99999/extract-configs-bc", headers=h)
    assert r.status_code == 200


def test_extract_all_starts_background(client):
    c, h = client
    r = c.post("/api/clients/99999/extract-all", headers=h)
    assert r.status_code == 200


# ──────────────────────────────────────────
# Listagens (vazias) para cliente inexistente
# ──────────────────────────────────────────

def test_list_assets_for_unknown_client_returns_empty(client):
    c, h = client
    r = c.get("/api/clients/99999/assets", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_list_vlans_for_unknown_client_returns_empty(client):
    c, h = client
    r = c.get("/api/clients/99999/vlans", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_list_subnets_for_unknown_client_returns_empty(client):
    c, h = client
    r = c.get("/api/clients/99999/subnets", headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_list_bc_links_for_unknown_client_returns_empty(client):
    c, h = client
    r = c.get("/api/clients/99999/bc-links", headers=h)
    assert r.status_code == 200
    assert r.json() == []
