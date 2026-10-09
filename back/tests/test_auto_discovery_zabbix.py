"""AUTO IPAM: sincroniza IPs observados no Zabbix para dentro dos blocos
declarados no phpIPAM (auto_discovery.sync_zabbix_ips_to_phpipam), com HTTP
mockado. Isolado dos testes de endpoint (TestClient) por causa do event-loop
async — mesmo padrão de test_auto_discovery_phpipam.py.
"""
import json

import httpx
import pytest
import pytest_asyncio
import respx
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import auto_discovery
import models
import retry

BASE = "https://8.8.8.8"       # phpIPAM
ZBX_BASE = "https://9.9.9.9"   # Zabbix

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


def _jsonrpc_router(request):
    body = json.loads(request.content)
    result = {"apiinfo.version": "6.0.15", "host.get": HOSTS}.get(body.get("method"), [])
    return httpx.Response(200, json={"jsonrpc": "2.0", "result": result, "id": 1})


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


@pytest.fixture(autouse=True)
def fast_retries(monkeypatch):
    async def no_sleep(*args, **kwargs):
        return None
    monkeypatch.setattr(retry.asyncio, "sleep", no_sleep)


async def _seed(session):
    client = models.Client(name="Prov AUTO IPAM", ip=BASE, token_name="app", token="stored-token",
                           section_id=7, zabbix_url=ZBX_BASE, zabbix_token="zbx-token",
                           zabbix_verify_tls=True)
    asset = models.Asset(hostname="SW", client=client, category="core", authority_level=10)
    session.add_all([client, asset])
    await session.flush()
    session.add(models.Subnet(network="10.10.10.0", mask=24, description="LAN",
                              client=client, asset=asset))
    await session.commit()
    return client.id


@pytest.mark.asyncio
@respx.mock
async def test_sync_zabbix_ips_grava_declarados_e_marca_orphans(session):
    cid = await _seed(session)
    posted = []

    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=_jsonrpc_router)
    respx.get(url__regex=r".*/subnets/cidr/10\.10\.10\.0/24/.*").mock(
        return_value=httpx.Response(200, json={"data": [{"id": 55}]}))
    respx.get(url__regex=r".*/subnets/55/addresses/.*").mock(
        return_value=httpx.Response(200, json={"data": []}))

    def _capture_post(request):
        posted.append(json.loads(request.content))
        return httpx.Response(201, json={"success": True})
    respx.post(url__regex=r".*/api/app/addresses/.*").mock(side_effect=_capture_post)

    result = await auto_discovery.sync_zabbix_ips_to_phpipam(cid, ZBX_BASE, "zbx-token", True, session)

    assert result["ok"] is True
    assert result["observed"] == 4
    assert result["created"] == 3
    assert {o["ip"] for o in result["orphans"]} == {"192.168.99.9"}
    assert {p["ip"] for p in posted} == {"10.10.10.1", "10.10.10.2", "10.10.10.3"}


@pytest.mark.asyncio
@respx.mock
async def test_sync_zabbix_ips_nao_grava_endereco_de_rede(session):
    """Zabbix real traz endereço de rede (.0) cadastrado como host — não pode
    virar registro de IP no phpIPAM (caso visto em produção: 198.51.100.0)."""
    cid = await _seed(session)

    hosts_com_network_addr = [
        {"hostid": "7", "host": "mik", "name": "MIK - Autenticador", "status": "0",
         "interfaces": [{"ip": "10.10.10.0", "dns": "", "type": "2", "main": "1", "available": "2"}]},
        {"hostid": "8", "host": "bcast", "name": "Broadcast", "status": "0",
         "interfaces": [{"ip": "10.10.10.255", "dns": "", "type": "2", "main": "1", "available": "0"}]},
        {"hostid": "9", "host": "ok", "name": "Host valido", "status": "0",
         "interfaces": [{"ip": "10.10.10.7", "dns": "", "type": "2", "main": "1", "available": "1"}]},
    ]

    def router(request):
        body = json.loads(request.content)
        result = {"apiinfo.version": "6.2.9", "host.get": hosts_com_network_addr}.get(body.get("method"), [])
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": result, "id": 1})

    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=router)
    respx.get(url__regex=r".*/subnets/cidr/10\.10\.10\.0/24/.*").mock(
        return_value=httpx.Response(200, json={"data": [{"id": 55}]}))
    respx.get(url__regex=r".*/subnets/55/addresses/.*").mock(
        return_value=httpx.Response(200, json={"data": []}))
    posted = []

    def _capture(request):
        posted.append(json.loads(request.content))
        return httpx.Response(201, json={"success": True})
    respx.post(url__regex=r".*/api/app/addresses/.*").mock(side_effect=_capture)

    result = await auto_discovery.sync_zabbix_ips_to_phpipam(cid, ZBX_BASE, "zbx-token", True, session)

    assert result["created"] == 1
    assert {p["ip"] for p in posted} == {"10.10.10.7"}
    motivos = {o["ip"]: o["reason"] for o in result["orphans"]}
    assert motivos["10.10.10.0"] == "endereco_de_rede_ou_broadcast"
    assert motivos["10.10.10.255"] == "endereco_de_rede_ou_broadcast"


@pytest.mark.asyncio
@respx.mock
async def test_sync_zabbix_ips_dedup_nao_recria(session):
    """IP que já existe na subnet do phpIPAM não é recriado (skipped)."""
    cid = await _seed(session)

    respx.post(url__regex=r".*api_jsonrpc\.php").mock(side_effect=_jsonrpc_router)
    respx.get(url__regex=r".*/subnets/cidr/10\.10\.10\.0/24/.*").mock(
        return_value=httpx.Response(200, json={"data": [{"id": 55}]}))
    # .1 e .2 já existem; .3 é novo.
    respx.get(url__regex=r".*/subnets/55/addresses/.*").mock(
        return_value=httpx.Response(200, json={"data": [{"ip": "10.10.10.1"}, {"ip": "10.10.10.2"}]}))
    respx.post(url__regex=r".*/api/app/addresses/.*").mock(
        return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.sync_zabbix_ips_to_phpipam(cid, ZBX_BASE, "zbx-token", True, session)
    assert result["created"] == 1   # só .3
    assert result["skipped"] == 2   # .1 e .2 já existiam
