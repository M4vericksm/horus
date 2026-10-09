"""Integração Zabbix (modo A, leitura) + AUTO IPAM (Zabbix → phpIPAM).

Cobre: helpers do zabbix_client, fallback de auth Bearer→corpo, endpoints
/api/zabbix/test e /api/clients/{id}/monitoring/*, e o sync AUTO IPAM que grava
os IPs observados nos blocos declarados do phpIPAM.
"""
import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import zabbix_client as zbx
from main import app, RATE_BUCKETS

ZBX_BASE = "https://9.9.9.9"      # Zabbix

# Amostra de hosts do Zabbix: um up (available=1), um down (available=2),
# um sem poll ainda (available=0) e um IP fora do bloco declarado.
HOSTS = [
    {"hostid": "1", "host": "core-rt", "name": "Core Router", "status": "0",
     "interfaces": [{"ip": "10.10.10.1", "dns": "", "type": "2", "main": "1", "available": "1"}]},
    {"hostid": "2", "host": "sw-acc", "name": "Switch Acesso", "status": "0",
     "interfaces": [{"ip": "10.10.10.2", "dns": "sw.local", "type": "1", "main": "1", "available": "2"}]},
    {"hostid": "3", "host": "olt-1", "name": "OLT 1", "status": "0",
     "interfaces": [{"ip": "10.10.10.3", "dns": "", "type": "2", "main": "1", "available": "0"}]},
    {"hostid": "4", "host": "fora", "name": "Fora do bloco", "status": "0",
     "interfaces": [{"ip": "192.168.99.9", "dns": "", "type": "2", "main": "1", "available": "1"}]},
]

TRIGGERS = [
    {"triggerid": "10", "description": "Link down", "priority": "5", "lastchange": "1700000000",
     "hosts": [{"hostid": "1", "host": "core-rt", "name": "Core Router"}]},
    {"triggerid": "11", "description": "High CPU", "priority": "3", "lastchange": "1700000100",
     "hosts": [{"hostid": "2", "host": "sw-acc", "name": "Switch Acesso"}]},
]


def _jsonrpc_router(request):
    """Roteia a resposta JSON-RPC pelo método da requisição."""
    body = json.loads(request.content)
    method = body.get("method")
    result = {"apiinfo.version": "6.0.15", "host.get": HOSTS, "trigger.get": TRIGGERS}.get(method, [])
    return httpx.Response(200, json={"jsonrpc": "2.0", "result": result, "id": 1})


# ──────────────────────────────────────────
# Unit: helpers do zabbix_client
# ──────────────────────────────────────────

def test_normalize_endpoint_appends_jsonrpc():
    assert zbx._normalize_endpoint("https://9.9.9.9") == "https://9.9.9.9/api_jsonrpc.php"
    assert zbx._normalize_endpoint("https://9.9.9.9/api_jsonrpc.php") == "https://9.9.9.9/api_jsonrpc.php"
    # sem scheme → assume https (não vaza token em http claro)
    assert zbx._normalize_endpoint("9.9.9.9").startswith("https://")


def test_summarize_hosts_counts_states():
    s = zbx.summarize_hosts(HOSTS)
    assert s["total"] == 4
    assert s["up"] == 2       # core-rt + fora
    assert s["down"] == 1     # sw-acc
    assert s["unknown"] == 1  # olt-1 (available=0)


def test_summarize_problems_by_severity():
    s = zbx.summarize_problems([
        {"severity_label": "disaster"}, {"severity_label": "average"}, {"severity_label": "disaster"},
    ])
    assert s["total"] == 3
    assert s["by_severity"]["disaster"] == 2
    assert s["by_severity"]["average"] == 1


def test_is_documentable_ip_descarta_lixo_de_inventario():
    """Casos vistos no Zabbix real de um provedor (6.2.9)."""
    assert zbx.is_documentable_ip("10.255.255.1")
    assert zbx.is_documentable_ip("198.51.100.18")
    assert not zbx.is_documentable_ip("127.0.0.1")      # Zabbix server local
    assert not zbx.is_documentable_ip("0.0.0.0")
    assert not zbx.is_documentable_ip("169.254.1.1")    # APIPA
    assert not zbx.is_documentable_ip("224.0.0.1")      # multicast
    assert not zbx.is_documentable_ip("")
    assert not zbx.is_documentable_ip("nao-e-ip")


def test_extract_host_ips_filtra_loopback():
    hosts = [{"hostid": "9", "host": "zbx", "name": "Zabbix server",
              "interfaces": [{"ip": "127.0.0.1", "available": "1"}]}]
    assert zbx.extract_host_ips(hosts) == []


def test_extract_host_ips_dedup_and_available():
    ips = zbx.extract_host_ips(HOSTS)
    by_ip = {i["ip"]: i for i in ips}
    assert by_ip["10.10.10.1"]["available"] is True
    assert by_ip["10.10.10.2"]["available"] is False
    assert by_ip["10.10.10.2"]["hostname"] == "Switch Acesso"
    assert "192.168.99.9" in by_ip


# ──────────────────────────────────────────
# Unit: fallback de autenticação Bearer → campo auth
# ──────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_client_auth_fallback_bearer_to_body():
    calls = {"bearer": 0, "body": 0}

    def router(request):
        body = json.loads(request.content)
        if body.get("method") == "host.get":
            if request.headers.get("Authorization"):     # tentativa Bearer
                calls["bearer"] += 1
                return httpx.Response(200, json={"error": {"data": "Not authorised."}, "id": 1})
            calls["body"] += 1                            # fallback: auth no corpo
            assert body.get("auth") == "tok"
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": HOSTS, "id": 1})
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": [], "id": 1})

    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=router)
    async with zbx.ZabbixClient(ZBX_BASE, "tok") as z:
        hosts = await z.get_hosts()
    assert len(hosts) == 4
    assert calls["bearer"] == 1 and calls["body"] == 1


# ──────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────

@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


def _make_client_with_zabbix(c, h, **extra):
    payload = {"name": f"Prov Zbx {id(extra)}", "zabbix_url": ZBX_BASE,
               "zabbix_token": "zbx-token", "zabbix_verify_tls": True}
    payload.update(extra)
    r = c.post("/api/clients", headers=h, json=payload)
    assert r.status_code == 200, r.text
    return r.json()["id"]


@respx.mock
def test_zabbix_test_endpoint_success(client):
    c, h = client
    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=_jsonrpc_router)
    r = c.post("/api/zabbix/test", headers=h,
               json={"url": ZBX_BASE, "token": "tok", "verify_tls": True})
    body = r.json()
    assert body["ok"] is True
    assert body["version"] == "6.0.15"
    assert body["host_count"] == 4


@respx.mock
def test_zabbix_test_endpoint_auth_error(client):
    c, h = client

    def router(request):
        b = json.loads(request.content)
        if b.get("method") == "apiinfo.version":
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": "6.0.15", "id": 1})
        return httpx.Response(200, json={"error": {"data": "Not authorised."}, "id": 1})

    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=router)
    r = c.post("/api/zabbix/test", headers=h, json={"url": ZBX_BASE, "token": "bad"})
    body = r.json()
    assert body["ok"] is False
    assert body["auth_error"] is True


def test_zabbix_test_endpoint_blocks_internal_url(client):
    c, h = client
    # Loopback é sempre bloqueado (ALWAYS_BLOCKED), independe de ALLOW_PRIVATE_TARGETS.
    r = c.post("/api/zabbix/test", headers=h, json={"url": "http://127.0.0.1", "token": "t"})
    assert r.status_code == 400


@respx.mock
def test_monitoring_summary_endpoint(client):
    c, h = client
    cid = _make_client_with_zabbix(c, h)
    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=_jsonrpc_router)
    r = c.get(f"/api/clients/{cid}/monitoring/summary", headers=h)
    body = r.json()
    assert body["ok"] is True
    assert body["hosts"]["total"] == 4
    assert body["hosts"]["up"] == 2
    assert body["problems"]["total"] == 2
    assert body["problems"]["by_severity"]["disaster"] == 1


@respx.mock
def test_monitoring_problems_endpoint(client):
    c, h = client
    cid = _make_client_with_zabbix(c, h)
    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=_jsonrpc_router)
    r = c.get(f"/api/clients/{cid}/monitoring/problems", headers=h)
    body = r.json()
    assert body["ok"] is True
    assert len(body["problems"]) == 2
    assert body["problems"][0]["severity_label"] == "disaster"


def test_monitoring_summary_404_when_not_configured(client):
    c, h = client
    cid = _make_client_with_zabbix(c, h, zabbix_url=None, zabbix_token=None)
    r = c.get(f"/api/clients/{cid}/monitoring/summary", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "zabbix_not_configured"
