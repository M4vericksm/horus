"""Cobertura dos fluxos NetBox em auto_discovery.py com HTTP mockado."""
import json

import httpx
import pytest
import pytest_asyncio
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import auto_discovery
import models
import retry


BASE = "https://9.9.9.9"


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


async def _seed_netbox_client(session, *, ignore_conflict=False, with_subnet=True, token="nbt_test"):
    client = models.Client(
        name="Cliente NetBox",
        netbox_url=BASE,
        netbox_token=token,
        netbox_vlan_group_id=1,
        netbox_site_id=7,
        l2_domain_id=1,
        section_id=7,
    )
    asset = models.Asset(
        hostname="SW-NB",
        client=client,
        vendor="Cisco",
        model="C9300",
        serial_number="SN-NB",
        category="core",
        authority_level=10,
        ip_address="198.51.100.10",
        is_edge_router=True,
        ignore_vlan_conflict=ignore_conflict,
    )
    vlan = models.Vlan(vid=10, name="USERS", description="Usuarios", client=client, asset=asset)
    session.add_all([client, asset, vlan])
    await session.flush()
    subnet = None
    if with_subnet:
        subnet = models.Subnet(
            network="10.20.30.0",
            mask=24,
            description="LAN Usuarios",
            vlan_id=vlan.id,
            client=client,
            asset=asset,
        )
        session.add(subnet)
    await session.commit()
    await session.refresh(client)
    await session.refresh(asset)
    await session.refresh(vlan)
    return client, asset, vlan, subnet


def test_nb_slug_normalizes_and_limits_text():
    assert auto_discovery._nb_slug("Cisco Catalyst 9300!") == "cisco-catalyst-9300"
    assert auto_discovery._nb_slug("!!!") == "unknown"
    assert len(auto_discovery._nb_slug("A" * 80)) == 50


def test_nb_clean_payload_omits_only_none_values():
    assert auto_discovery._nb_clean_payload({"name": "A", "site": None, "enabled": False, "count": 0}) == {
        "name": "A",
        "enabled": False,
        "count": 0,
    }


class FakeNetBoxClient:
    def __init__(self, *, get_response=None, post_response=None, fail=False):
        self.get_response = get_response
        self.post_response = post_response
        self.fail = fail
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if self.fail:
            raise httpx.ConnectError("offline")
        return self.get_response

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if self.fail:
            raise httpx.ConnectError("offline")
        return self.post_response


async def test_nb_get_or_create_returns_existing_id():
    client = FakeNetBoxClient(get_response=httpx.Response(200, json={"results": [{"id": 11}]}))

    result = await auto_discovery._nb_get_or_create(client, {}, BASE, "/api/dcim/manufacturers/", {"slug": "cisco"}, {})

    assert result == 11
    assert [call[0] for call in client.calls] == ["GET"]


async def test_nb_get_or_create_posts_when_missing():
    client = FakeNetBoxClient(
        get_response=httpx.Response(200, json={"results": []}),
        post_response=httpx.Response(201, json={"id": 22}),
    )

    result = await auto_discovery._nb_get_or_create(client, {}, BASE, "/api/dcim/manufacturers/", {}, {"name": "Cisco"})

    assert result == 22
    assert [call[0] for call in client.calls] == ["GET", "POST"]


async def test_nb_get_or_create_returns_none_on_post_500():
    client = FakeNetBoxClient(
        get_response=httpx.Response(200, json={"results": []}),
        post_response=httpx.Response(500, text="boom"),
    )

    assert await auto_discovery._nb_get_or_create(client, {}, BASE, "/api/dcim/manufacturers/", {}, {}) is None


async def test_nb_get_or_create_returns_none_on_exception():
    client = FakeNetBoxClient(fail=True)

    assert await auto_discovery._nb_get_or_create(client, {}, BASE, "/api/dcim/manufacturers/", {}, {}) is None


async def test_sync_netbox_returns_error_without_credentials(session):
    result = await auto_discovery.sync_data_to_netbox(999, session)
    assert result == {"error": "Credenciais NetBox não configuradas (URL e Token obrigatórios)"}


async def test_sync_netbox_rejects_blocked_url(session):
    client, *_ = await _seed_netbox_client(session)
    client.netbox_url = "http://127.0.0.1:8000"
    await session.commit()

    result = await auto_discovery.sync_data_to_netbox(client.id, session)

    assert "URL NetBox bloqueada" in result["error"]


@respx.mock
async def test_sync_netbox_creates_vlan_prefix_device_and_deletes_removed_vlan(session, monkeypatch):
    await _seed_netbox_client(session)

    async def fake_get_or_create(*args, **kwargs):
        return 10

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(
        return_value=httpx.Response(200, json={"results": [{"id": 20, "vid": 20, "name": "OLD"}]})
    )
    respx.post(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(201, json={"id": 101}))
    respx.get(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(201, json={"id": 201}))
    respx.delete(f"{BASE}/api/ipam/vlans/20/").mock(return_value=httpx.Response(204))
    respx.patch(f"{BASE}/api/dcim/devices/10/").mock(return_value=httpx.Response(200, json={"id": 10}))

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert "1 VLANs criadas" in result["message"]
    assert "1 VLANs removidas" in result["message"]
    assert "1 Prefixos criados" in result["message"]
    assert "1 Device(s) registrado(s)" in result["message"]
    assert "1 IP(s) registrado(s)" in result["message"]
    assert result["vlans_created"] == 1
    assert result["vlans_updated"] == 0
    assert result["prefixes_created"] == 1
    assert result["conflicts"] == []


@respx.mock
async def test_sync_netbox_updates_existing_vlan_and_prefix(session, monkeypatch):
    await _seed_netbox_client(session, ignore_conflict=True)

    async def fake_get_or_create(*args, **kwargs):
        return None

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(
        return_value=httpx.Response(200, json={"results": [{"id": 10, "vid": 10, "name": "REMOTE"}]})
    )
    respx.patch(f"{BASE}/api/ipam/vlans/10/").mock(return_value=httpx.Response(200, json={"id": 10}))
    respx.get(f"{BASE}/api/ipam/prefixes/").mock(
        return_value=httpx.Response(
            200,
            json={"results": [{"id": 55, "prefix": "10.20.30.0/24", "site": {"id": 7}, "description": "old"}]},
        )
    )
    respx.patch(f"{BASE}/api/ipam/prefixes/55/").mock(return_value=httpx.Response(200, json={"id": 55}))

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert "1 VLANs atualizadas" in result["message"]
    assert "1 Prefixos atualizados" in result["message"]
    assert result["vlans_updated"] == 1
    assert result["prefixes_updated"] == 1


@respx.mock
async def test_sync_netbox_reports_vlan_conflict(session, monkeypatch):
    await _seed_netbox_client(session, ignore_conflict=False, with_subnet=False)

    async def fake_get_or_create(*args, **kwargs):
        return None

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(
        return_value=httpx.Response(200, json={"results": [{"id": 10, "vid": 10, "name": "REMOTE"}]})
    )

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert result["has_conflicts"] is True
    assert result["conflicts"][0]["type"] == "name_conflict"

    logs = (await session.execute(select(models.ExecutionLog))).scalars().all()
    assert logs[-1].operation == "sync_netbox"
    assert logs[-1].status == "warning"


@respx.mock
async def test_sync_netbox_reports_permission_error_on_vlan_update(session, monkeypatch):
    await _seed_netbox_client(session, ignore_conflict=True, with_subnet=False)

    async def fake_get_or_create(*args, **kwargs):
        return None

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(
        return_value=httpx.Response(200, json={"results": [{"id": 10, "vid": 10, "name": "REMOTE"}]})
    )
    respx.patch(f"{BASE}/api/ipam/vlans/10/").mock(return_value=httpx.Response(403, text="forbidden"))

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert result["has_conflicts"] is True
    assert result["conflicts"][0]["type"] == "permission_error"


@respx.mock
async def test_sync_netbox_handles_vlan_lookup_timeout_and_post_500(session, monkeypatch):
    await _seed_netbox_client(session, with_subnet=False)

    async def fake_get_or_create(*args, **kwargs):
        return None

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(side_effect=httpx.TimeoutException("slow"))
    respx.post(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(500, text="boom"))

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert "0 VLANs criadas" in result["message"]


@respx.mock
async def test_sync_netbox_handles_prefix_lookup_500_and_post_500(session, monkeypatch):
    await _seed_netbox_client(session)

    async def fake_get_or_create(*args, **kwargs):
        return None

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(201, json={"id": 101}))
    respx.get(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(500, text="boom"))
    respx.post(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(500, text="boom"))

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert "0 Prefixos criados" in result["message"]


@respx.mock
async def test_sync_netbox_reports_prefix_overlap_conflict(session, monkeypatch):
    await _seed_netbox_client(session)

    async def fake_get_or_create(*args, **kwargs):
        return None

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(201, json={"id": 101}))
    respx.get(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/prefixes/").mock(
        return_value=httpx.Response(409, text="Prefix overlaps with 10.20.0.0/16")
    )

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert result["has_conflicts"] is True
    assert result["conflicts"][0]["type"] == "prefix_overlap"
    assert result["prefixes_created"] == 0


@respx.mock
async def test_sync_netbox_reports_invalid_vlan_payload(session, monkeypatch):
    await _seed_netbox_client(session, with_subnet=False)

    async def fake_get_or_create(*args, **kwargs):
        return None

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(400, text="Invalid VID"))

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert result["has_conflicts"] is True
    assert result["conflicts"][0]["type"] == "invalid_payload"


@respx.mock
async def test_sync_netbox_handles_primary_ip_patch_error(session, monkeypatch):
    await _seed_netbox_client(session, with_subnet=False)

    async def fake_get_or_create(*args, **kwargs):
        return 10

    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(201, json={"id": 101}))
    respx.patch(f"{BASE}/api/dcim/devices/10/").mock(side_effect=httpx.ConnectError("offline"))

    result = await auto_discovery.sync_data_to_netbox(1, session)

    assert "1 Device(s) registrado(s)" in result["message"]
    assert "1 IP(s) registrado(s)" in result["message"]


@respx.mock
async def test_create_vlan_group_netbox_success(session):
    client, *_ = await _seed_netbox_client(session, token="plain-token")
    respx.post(f"{BASE}/api/ipam/vlan-groups/").mock(return_value=httpx.Response(201, json={"id": 123}))

    result = await auto_discovery.create_vlan_group_netbox(client.id, "Grupo Novo!", session)

    assert result["id"] == 123
    assert result["name"] == "Grupo Novo!"


@respx.mock
async def test_create_vlan_group_netbox_permission_error(session):
    client, *_ = await _seed_netbox_client(session)
    respx.post(f"{BASE}/api/ipam/vlan-groups/").mock(return_value=httpx.Response(403, text="forbidden"))

    result = await auto_discovery.create_vlan_group_netbox(client.id, "Grupo Novo", session)

    assert "Sem permissão" in result["error"]


@respx.mock
async def test_create_vlan_group_netbox_500_error(session):
    client, *_ = await _seed_netbox_client(session)
    respx.post(f"{BASE}/api/ipam/vlan-groups/").mock(return_value=httpx.Response(500, text="boom"))

    result = await auto_discovery.create_vlan_group_netbox(client.id, "Grupo Novo", session)

    assert "HTTP 500" in result["error"]


async def test_create_vlan_group_netbox_returns_error_without_credentials(session):
    result = await auto_discovery.create_vlan_group_netbox(999, "Grupo Novo", session)
    assert result == {"error": "Credenciais NetBox não configuradas"}


@respx.mock
async def test_resolve_netbox_conflicts_updates_vlan_name(session):
    client, asset, vlan, _ = await _seed_netbox_client(session, with_subnet=False)
    respx.patch(f"{BASE}/api/ipam/vlans/55/").mock(return_value=httpx.Response(200, json={"id": 55}))

    result = await auto_discovery.resolve_netbox_conflicts(
        client.id,
        [{
            "vid": vlan.vid,
            "asset_id": asset.id,
            "domain_id": 1,
            "vlan_ipam_id": "55",
            "local_vlan_id": vlan.id,
            "action": "update_name",
            "new_name": vlan.name,
        }],
        session,
    )

    await session.refresh(asset)
    assert result["resolved"] == 1
    assert result["errors"] == []
    assert asset.ignore_vlan_conflict is True


@respx.mock
async def test_resolve_netbox_conflicts_creates_vlan_group_override(session):
    client, asset, vlan, _ = await _seed_netbox_client(session, with_subnet=False)
    respx.post(f"{BASE}/api/ipam/vlan-groups/").mock(return_value=httpx.Response(201, json={"id": 77}))

    result = await auto_discovery.resolve_netbox_conflicts(
        client.id,
        [{
            "vid": vlan.vid,
            "asset_id": asset.id,
            "domain_id": 1,
            "action": "create_l2",
            "new_l2_name": "Grupo Isolado",
        }],
        session,
    )

    await session.refresh(asset)
    assert result["resolved"] == 1
    assert asset.override_l2_domain_id == 77


# ──────────────────────────────────────────────────────────────────────────────
# Interfaces reais + VLAN por porta (envio completo ao NetBox)
# ──────────────────────────────────────────────────────────────────────────────
# Antes, apenas uma interface sintética "mgmt" era enviada, só para pendurar o IP
# de gerência — as interfaces reais e a associação VLAN↔porta (que já existiam no
# banco, via AssetInterface/VlanInterface) nunca chegavam ao NetBox.

async def _seed_client_com_interface(session, *, com_ip_na_interface=True, is_management=True):
    """Cliente com 1 ativo, 1 interface real e duas VLANs: uma em trunk (tagged),
    outra nativa. Sem VLAN em modo access — cobertos por outro teste."""
    client = models.Client(
        name=f"Cliente NB Iface {id(object())}",
        netbox_url=BASE, netbox_token="nbt_test",
        netbox_vlan_group_id=1, netbox_site_id=7, l2_domain_id=1, section_id=7,
    )
    asset = models.Asset(
        hostname="SW-IFACE", client=client, vendor="Huawei", model="S5720",
        category="acesso", authority_level=5,
    )
    v_tag = models.Vlan(vid=100, name="TAGGED100", client=client, asset=asset)
    v_native = models.Vlan(vid=10, name="NATIVE10", client=client, asset=asset)
    iface = models.AssetInterface(
        asset=asset, name="GigabitEthernet0/0/1", type="physical",
        description="uplink", is_management=is_management,
    )
    session.add_all([client, asset, v_tag, v_native, iface])
    await session.flush()
    session.add_all([
        models.VlanInterface(vlan=v_tag, interface=iface, mode="trunk"),
        models.VlanInterface(vlan=v_native, interface=iface, mode="native"),
    ])
    if com_ip_na_interface:
        session.add(models.Subnet(
            network="10.0.0.0", mask=24, host_ip="10.0.0.5",
            client=client, asset=asset, interface=iface,
        ))
    await session.commit()
    await session.refresh(client)
    return client, asset, iface


def _mock_vlan_creation_with_distinct_ids():
    """VLANs sempre criadas (nunca existem no NetBox); cada POST devolve um ID
    derivado do VID, para os testes distinguirem qual VLAN foi associada a quê."""
    def router(request):
        body = json.loads(request.content)
        return httpx.Response(201, json={"id": 1000 + body["vid"]})
    respx.get(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/vlans/").mock(side_effect=router)
    respx.get(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.post(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(201, json={"id": 5000}))


@respx.mock
async def test_sync_netbox_envia_interface_real_com_trunk_e_native(session, monkeypatch):
    client, asset, iface = await _seed_client_com_interface(session, com_ip_na_interface=False)

    async def fake_get_or_create(*a, **kw):
        return 10  # manufacturer/device-type/device-role/device
    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    _mock_vlan_creation_with_distinct_ids()

    respx.get(f"{BASE}/api/dcim/interfaces/").mock(return_value=httpx.Response(200, json={"results": []}))
    captured = {}
    def iface_router(request):
        captured["payload"] = json.loads(request.content)
        return httpx.Response(201, json={"id": 777})
    respx.post(f"{BASE}/api/dcim/interfaces/").mock(side_effect=iface_router)

    result = await auto_discovery.sync_data_to_netbox(client.id, session)

    assert "1 Interface(s) sincronizada(s)" in result["message"]
    p = captured["payload"]
    assert p["device"] == 10
    assert p["name"] == "GigabitEthernet0/0/1"
    assert p["type"] == "1000base-t"       # AssetInterface.type='physical' -> IFACE_TYPE_MAP
    assert p["description"] == "uplink"
    assert p["mode"] == "tagged"
    assert p["tagged_vlans"] == [1100]      # VLAN 100 em trunk
    assert p["untagged_vlan"] == 1010       # VLAN 10 nativa (PVID)


@respx.mock
async def test_sync_netbox_ip_vai_para_interface_real_nao_para_mgmt_sintetica(session, monkeypatch):
    """Com interface real de gerência, o IP tem que ir para ELA — a interface
    sintética "mgmt" (fallback antigo) não pode mais ser criada."""
    client, asset, iface = await _seed_client_com_interface(session, com_ip_na_interface=True, is_management=True)
    asset.ip_address = "10.0.0.5"
    await session.commit()

    async def fake_get_or_create(http_client, headers, base_url, endpoint, search, payload):
        if endpoint == "/api/ipam/ip-addresses/":
            return 900
        return 10
    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    _mock_vlan_creation_with_distinct_ids()

    respx.get(f"{BASE}/api/dcim/interfaces/").mock(return_value=httpx.Response(200, json={"results": []}))
    nomes_criados = []
    def iface_router(request):
        body = json.loads(request.content)
        nomes_criados.append(body["name"])
        return httpx.Response(201, json={"id": 777})
    respx.post(f"{BASE}/api/dcim/interfaces/").mock(side_effect=iface_router)
    patch_calls = []
    respx.patch(f"{BASE}/api/dcim/devices/10/").mock(
        side_effect=lambda r: (patch_calls.append(json.loads(r.content)), httpx.Response(200, json={"id": 10}))[1]
    )

    result = await auto_discovery.sync_data_to_netbox(client.id, session)

    assert nomes_criados == ["GigabitEthernet0/0/1"], "interface sintetica 'mgmt' nao pode ser criada"
    assert "mgmt" not in nomes_criados
    assert "1 IP(s) registrado(s)" in result["message"]
    assert patch_calls and patch_calls[0]["primary_ip4"] == 900


@respx.mock
async def test_sync_netbox_sem_dado_de_interface_cai_no_fallback_mgmt(session, monkeypatch):
    """Ativo sem nenhuma AssetInterface extraída (dado antigo/parque legado) tem
    que preservar o comportamento anterior: IP direto numa interface 'mgmt'."""
    client = models.Client(
        name="Cliente NB Sem Interface", netbox_url=BASE, netbox_token="nbt_test",
        netbox_vlan_group_id=1, netbox_site_id=7, l2_domain_id=1, section_id=7,
    )
    asset = models.Asset(
        hostname="SW-LEGADO", client=client, vendor="Cisco", model="C9200",
        category="acesso", ip_address="198.51.100.20",
    )
    session.add_all([client, asset])
    await session.commit()
    await session.refresh(client)

    async def fake_get_or_create(http_client, headers, base_url, endpoint, search, payload):
        if endpoint == "/api/ipam/ip-addresses/":
            return 901
        return 10
    monkeypatch.setattr(auto_discovery, "_nb_get_or_create", fake_get_or_create)
    respx.get(f"{BASE}/api/ipam/vlans/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.get(f"{BASE}/api/ipam/prefixes/").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.patch(f"{BASE}/api/dcim/devices/10/").mock(return_value=httpx.Response(200, json={"id": 10}))

    result = await auto_discovery.sync_data_to_netbox(client.id, session)

    assert "0 Interface(s) sincronizada(s)" in result["message"], "fallback nao passa pelo _nb_sync_interface"
    assert "1 IP(s) registrado(s)" in result["message"]


class FakePatchableClient:
    """Como FakeNetBoxClient, mas com PATCH — usado para testar _nb_sync_interface
    isoladamente (cria vs. atualiza)."""
    def __init__(self, *, get_response=None, post_response=None, patch_response=None):
        self.get_response = get_response
        self.post_response = post_response
        self.patch_response = patch_response
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.get_response

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.post_response

    async def patch(self, url, **kwargs):
        self.calls.append(("PATCH", url, kwargs))
        return self.patch_response


async def test_nb_sync_interface_cria_quando_nao_existe():
    client = FakePatchableClient(
        get_response=httpx.Response(200, json={"results": []}),
        post_response=httpx.Response(201, json={"id": 55}),
    )
    payload = {"device": 10, "name": "eth0", "type": "1000base-t", "description": "",
               "enabled": True, "mode": None, "untagged_vlan": None, "tagged_vlans": []}

    result = await auto_discovery._nb_sync_interface(client, {}, BASE, 10, payload)

    assert result == 55
    assert [c[0] for c in client.calls] == ["GET", "POST"]


async def test_nb_sync_interface_atualiza_quando_vlan_mudou():
    """Segunda sincronização: a porta que era access na VLAN 10 virou trunk com
    VLAN 20 tagged. _nb_get_or_create nao atualizaria isso — _nb_sync_interface
    tem que fazer o PATCH."""
    existente = {
        "id": 55, "type": {"value": "1000base-t"}, "description": "",
        "mode": {"value": "access"}, "enabled": True,
        "untagged_vlan": {"id": 10}, "tagged_vlans": [],
    }
    client = FakePatchableClient(
        get_response=httpx.Response(200, json={"results": [existente]}),
        patch_response=httpx.Response(200, json={"id": 55}),
    )
    payload = {"device": 10, "name": "eth0", "type": "1000base-t", "description": "",
               "enabled": True, "mode": "tagged", "untagged_vlan": None, "tagged_vlans": [20]}

    result = await auto_discovery._nb_sync_interface(client, {}, BASE, 10, payload)

    assert result == 55
    assert [c[0] for c in client.calls] == ["GET", "PATCH"]
    assert client.calls[1][2]["json"]["tagged_vlans"] == [20]


async def test_nb_sync_interface_nao_faz_patch_quando_ja_esta_igual():
    """Idempotência: rodar duas vezes sem mudança nenhuma não deve gerar PATCH."""
    existente = {
        "id": 55, "type": {"value": "1000base-t"}, "description": "uplink",
        "mode": {"value": "tagged"}, "enabled": True,
        "untagged_vlan": {"id": 10}, "tagged_vlans": [{"id": 20}],
    }
    client = FakePatchableClient(get_response=httpx.Response(200, json={"results": [existente]}))
    payload = {"device": 10, "name": "eth0", "type": "1000base-t", "description": "uplink",
               "enabled": True, "mode": "tagged", "untagged_vlan": 10, "tagged_vlans": [20]}

    result = await auto_discovery._nb_sync_interface(client, {}, BASE, 10, payload)

    assert result == 55
    assert [c[0] for c in client.calls] == ["GET"], "sem mudanca, nao pode chamar PATCH"


async def test_nb_sync_interface_retorna_none_em_falha_de_post():
    client = FakePatchableClient(
        get_response=httpx.Response(200, json={"results": []}),
        post_response=httpx.Response(500, text="boom"),
    )
    payload = {"device": 10, "name": "eth0", "type": "other", "description": "",
               "enabled": True, "mode": None, "untagged_vlan": None, "tagged_vlans": []}

    assert await auto_discovery._nb_sync_interface(client, {}, BASE, 10, payload) is None


@pytest.mark.parametrize("tipo_local,slug_esperado", [
    ("physical", "1000base-t"),
    ("lag", "lag"),
    ("bridge", "bridge"),
    ("loopback", "virtual"),
    ("tunnel", "virtual"),
    ("vlan", "virtual"),
    ("unknown", "other"),
    ("algo-nao-mapeado", "other"),  # fallback seguro para tipo desconhecido
])
def test_iface_type_map_cobre_todos_os_tipos_locais(tipo_local, slug_esperado):
    assert auto_discovery.IFACE_TYPE_MAP.get(tipo_local, "other") == slug_esperado
