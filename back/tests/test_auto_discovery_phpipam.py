"""Cobertura dos fluxos phpIPAM em auto_discovery.py com HTTP mockado."""
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


BASE = "https://8.8.8.8"


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


async def _seed_phpipam_client(session, *, ignore_conflict=False, with_subnet=True, host_ip=None):
    client = models.Client(
        name="Cliente phpIPAM",
        ip=BASE,
        token_name="app",
        token="stored-token",
        l2_domain_id=1,
        section_id=7,
        vlan_prefix="CLI",
    )
    asset = models.Asset(
        hostname="SW-IPAM",
        client=client,
        category="core",
        authority_level=10,
        is_edge_router=True,
        ignore_vlan_conflict=ignore_conflict,
    )
    vlan = models.Vlan(vid=10, name="USERS", description="Usuarios", client=client, asset=asset)
    session.add_all([client, asset, vlan])
    await session.flush()
    subnet = None
    if with_subnet:
        subnet = models.Subnet(
            network="10.10.10.0",
            mask=24,
            description="LAN Usuarios",
            host_ip=host_ip,
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


@respx.mock
async def test_get_phpipam_token_success():
    respx.post(f"{BASE}/api/app/user/").mock(
        return_value=httpx.Response(200, json={"success": True, "data": {"token": "fresh"}})
    )

    assert await auto_discovery._get_phpipam_token(BASE, "app", "user", "pass") == "fresh"


@respx.mock
async def test_get_phpipam_token_returns_none_on_401():
    respx.post(f"{BASE}/api/app/user/").mock(return_value=httpx.Response(401, json={"success": False}))

    assert await auto_discovery._get_phpipam_token(BASE, "app", "user", "bad") is None


@respx.mock
async def test_get_phpipam_token_returns_none_on_timeout():
    respx.post(f"{BASE}/api/app/user/").mock(side_effect=httpx.TimeoutException("timeout"))

    assert await auto_discovery._get_phpipam_token(BASE, "app", "user", "pass") is None


async def test_sync_phpipam_returns_error_without_credentials(session):
    result = await auto_discovery.sync_data_to_phpipam(999, session)
    assert result == {"error": "Sem API IPAM"}


@respx.mock
async def test_sync_phpipam_blocks_ssrf_target(session):
    """O sync real deve validar a URL (anti-SSRF) antes de qualquer HTTP.
    Um destino sempre-bloqueado (metadata AWS) precisa levantar ValueError
    sem disparar nenhuma request."""
    client, *_ = await _seed_phpipam_client(session)
    client.ip = "http://169.254.169.254"
    await session.commit()

    with pytest.raises(ValueError):
        await auto_discovery.sync_data_to_phpipam(client.id, session)

    assert respx.calls.call_count == 0


@respx.mock
async def test_sync_phpipam_creates_vlan_subnet_and_deletes_removed_vlan(session):
    await _seed_phpipam_client(session)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"vlanId": "20", "number": "20", "name": "OLD"}]},
        )
    )
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(return_value=httpx.Response(404))
    respx.post(f"{BASE}/api/app/subnets/").mock(return_value=httpx.Response(201, json={"success": True}))
    respx.delete(f"{BASE}/api/app/vlan/20/").mock(return_value=httpx.Response(204))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 VLANs criadas" in result["message"]
    assert "1 VLANs removidas" in result["message"]
    assert "1 Subnets criadas" in result["message"]


@respx.mock
async def test_sync_phpipam_updates_existing_vlan_and_subnet(session):
    await _seed_phpipam_client(session, ignore_conflict=True)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"vlanId": "10", "number": "10", "name": "REMOTE"}]},
        )
    )
    respx.patch(f"{BASE}/api/app/vlan/10/").mock(return_value=httpx.Response(200, json={"success": True}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "data": [{"id": "55", "sectionId": "7", "description": "old", "vlanId": "0"}],
            },
        )
    )
    respx.patch(f"{BASE}/api/app/subnets/55/").mock(return_value=httpx.Response(200, json={"success": True}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 VLANs atualizadas" in result["message"]
    assert "1 Subnets atualizadas" in result["message"]


@respx.mock
async def test_sync_phpipam_reports_vlan_name_conflict(session):
    await _seed_phpipam_client(session, ignore_conflict=False, with_subnet=False)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"vlanId": "10", "number": "10", "name": "REMOTE"}]},
        )
    )

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert result["has_conflicts"] is True
    assert result["conflicts"][0]["type"] == "name_conflict"


@respx.mock
async def test_sync_phpipam_reports_permission_error_on_auto_resolve(session):
    await _seed_phpipam_client(session, ignore_conflict=True, with_subnet=False)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"vlanId": "10", "number": "10", "name": "REMOTE"}]},
        )
    )
    respx.patch(f"{BASE}/api/app/vlan/10/").mock(return_value=httpx.Response(403, text="forbidden"))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert result["has_conflicts"] is True
    assert result["conflicts"][0]["type"] == "permission_error"


@respx.mock
async def test_sync_phpipam_handles_vlan_cache_500_and_creates_local_vlan(session):
    await _seed_phpipam_client(session, with_subnet=False)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(500, text="boom"))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"id": 101}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 VLANs criadas" in result["message"]


@respx.mock
async def test_sync_phpipam_handles_vlan_cache_timeout(session):
    await _seed_phpipam_client(session, with_subnet=False)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(side_effect=httpx.TimeoutException("slow"))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"id": 101}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 VLANs criadas" in result["message"]


@respx.mock
async def test_sync_phpipam_handles_subnet_lookup_401_and_creates_subnet(session):
    await _seed_phpipam_client(session)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(return_value=httpx.Response(401))
    respx.post(f"{BASE}/api/app/subnets/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 Subnets criadas" in result["message"]


@respx.mock
async def test_sync_phpipam_handles_subnet_lookup_500_and_create_failure(session):
    await _seed_phpipam_client(session)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(return_value=httpx.Response(500))
    respx.post(f"{BASE}/api/app/subnets/").mock(return_value=httpx.Response(500, text="boom"))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "0 Subnets criadas" in result["message"]


@respx.mock
async def test_sync_phpipam_handles_subnet_lookup_timeout(session):
    await _seed_phpipam_client(session)
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(side_effect=httpx.TimeoutException("slow"))
    respx.post(f"{BASE}/api/app/subnets/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 Subnets criadas" in result["message"]


@respx.mock
async def test_resolve_vlan_conflicts_update_name_success(session):
    client, asset, vlan, _subnet = await _seed_phpipam_client(session)
    respx.patch(f"{BASE}/api/app/vlan/123/").mock(return_value=httpx.Response(200, json={"success": True}))

    result = await auto_discovery.resolve_vlan_conflicts(
        client.id,
        [{"action": "update_name", "vid": 10, "asset_id": asset.id, "local_vlan_id": vlan.id, "vlan_ipam_id": 123}],
        session,
    )
    await session.refresh(asset)

    assert result["resolved"] == 1
    assert result["errors"] == []
    assert asset.ignore_vlan_conflict is True


@respx.mock
async def test_resolve_vlan_conflicts_update_name_permission_error(session):
    client, asset, vlan, _subnet = await _seed_phpipam_client(session)
    respx.patch(f"{BASE}/api/app/vlan/123/").mock(return_value=httpx.Response(403, text="forbidden"))

    result = await auto_discovery.resolve_vlan_conflicts(
        client.id,
        [{"action": "update_name", "vid": 10, "asset_id": asset.id, "local_vlan_id": vlan.id, "vlan_ipam_id": 123}],
        session,
    )

    assert result["resolved"] == 0
    assert "Sem permissão" in result["errors"][0]


@respx.mock
async def test_resolve_vlan_conflicts_create_l2_existing_id(session):
    client, asset, vlan, _subnet = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.resolve_vlan_conflicts(
        client.id,
        [{"action": "create_l2", "vid": 10, "asset_id": asset.id, "existing_l2_id": 77}],
        session,
    )
    await session.refresh(asset)

    assert result["resolved"] == 1
    assert asset.override_l2_domain_id == 77


@respx.mock
async def test_resolve_vlan_conflicts_create_l2_new_domain(session):
    client, asset, _vlan, _subnet = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/l2domains/").mock(return_value=httpx.Response(201, json={"data": {"id": 88}}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.resolve_vlan_conflicts(
        client.id,
        [{"action": "create_l2", "vid": 10, "asset_id": asset.id, "new_l2_name": "L2 Novo"}],
        session,
    )
    await session.refresh(asset)

    assert result["resolved"] == 1
    assert asset.override_l2_domain_id == 88


@respx.mock
async def test_resolve_vlan_conflicts_create_l2_permission_error(session):
    client, asset, _vlan, _subnet = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/l2domains/").mock(return_value=httpx.Response(403, text="forbidden"))

    result = await auto_discovery.resolve_vlan_conflicts(
        client.id,
        [{"action": "create_l2", "vid": 10, "asset_id": asset.id, "new_l2_name": "L2 Novo"}],
        session,
    )

    assert result["resolved"] == 0
    assert "Sem permissão" in result["errors"][0]


@respx.mock
async def test_resolve_vlan_conflicts_create_group_moves_asset_data(session):
    client, asset, vlan, subnet = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/l2domains/").mock(return_value=httpx.Response(201, json={"id": 99}))

    result = await auto_discovery.resolve_vlan_conflicts(
        client.id,
        [
            {
                "action": "create_group",
                "vid": 10,
                "asset_id": asset.id,
                "new_group_name": "Cliente Separado",
                "new_l2_name": "L2 Separado",
            }
        ],
        session,
    )
    await session.refresh(asset)
    await session.refresh(vlan)
    await session.refresh(subnet)
    new_client = (await session.execute(select(models.Client).where(models.Client.name == "Cliente Separado"))).scalar_one()

    assert result["resolved"] == 1
    assert new_client.l2_domain_id == 99
    assert asset.client_id == new_client.id
    assert vlan.client_id == new_client.id
    assert subnet.client_id == new_client.id


@respx.mock
async def test_resolve_vlan_conflicts_create_group_records_http_error(session):
    client, asset, _vlan, _subnet = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/l2domains/").mock(return_value=httpx.Response(500, text="boom"))

    result = await auto_discovery.resolve_vlan_conflicts(
        client.id,
        [{"action": "create_group", "vid": 10, "asset_id": asset.id, "new_group_name": "Falha"}],
        session,
    )

    assert result["resolved"] == 0
    assert "HTTP 500" in result["errors"][0]


async def test_resolve_vlan_conflicts_returns_error_without_credentials(session):
    result = await auto_discovery.resolve_vlan_conflicts(999, [], session)
    assert result == {"error": "Sem API IPAM"}


@respx.mock
async def test_create_l2_domain_phpipam_success(session):
    client, *_ = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/l2domains/").mock(return_value=httpx.Response(201, json={"data": {"id": 123}}))

    result = await auto_discovery.create_l2_domain_phpipam(client.id, "Novo L2", session)

    assert result["id"] == 123
    assert result["name"] == "Novo L2"


@respx.mock
async def test_create_l2_domain_phpipam_permission_error(session):
    client, *_ = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/l2domains/").mock(return_value=httpx.Response(403, text="forbidden"))

    result = await auto_discovery.create_l2_domain_phpipam(client.id, "Novo L2", session)

    assert "Sem permissão" in result["error"]


@respx.mock
async def test_create_l2_domain_phpipam_500_error(session):
    client, *_ = await _seed_phpipam_client(session)
    respx.post(f"{BASE}/api/app/l2domains/").mock(return_value=httpx.Response(500, text="boom"))

    result = await auto_discovery.create_l2_domain_phpipam(client.id, "Novo L2", session)

    assert "HTTP 500" in result["error"]


async def test_create_l2_domain_phpipam_returns_error_without_credentials(session):
    result = await auto_discovery.create_l2_domain_phpipam(999, "Novo L2", session)
    assert result == {"error": "Sem API IPAM"}


# ── Sync de IP host (address) por interface ──────────────────────────────────

@respx.mock
async def test_sync_phpipam_creates_address_for_new_subnet_host_ip(session):
    """Subnet nova com host_ip → cria o address (IP) no phpIPAM com hostname."""
    await _seed_phpipam_client(session, host_ip="10.10.10.5")
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(return_value=httpx.Response(404))
    respx.post(f"{BASE}/api/app/subnets/").mock(return_value=httpx.Response(201, json={"id": "55"}))
    respx.get(f"{BASE}/api/app/subnets/55/addresses/").mock(return_value=httpx.Response(200, json={"data": []}))
    addr_post = respx.post(f"{BASE}/api/app/addresses/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 Subnets criadas" in result["message"]
    assert "1 IPs criados" in result["message"]
    assert addr_post.called
    sent = addr_post.calls.last.request
    assert b'"ip":"10.10.10.5"' in sent.content
    assert b'"hostname":"SW-IPAM"' in sent.content


@respx.mock
async def test_sync_phpipam_skips_address_already_present(session):
    """Idempotente: se o IP já existe na subnet, não recria (sem 'IPs criados')."""
    await _seed_phpipam_client(session, host_ip="10.10.10.5")
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(return_value=httpx.Response(404))
    respx.post(f"{BASE}/api/app/subnets/").mock(return_value=httpx.Response(201, json={"id": "55"}))
    respx.get(f"{BASE}/api/app/subnets/55/addresses/").mock(
        return_value=httpx.Response(200, json={"data": [{"ip": "10.10.10.5"}]})
    )
    addr_post = respx.post(f"{BASE}/api/app/addresses/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "IPs criados" not in result["message"]
    assert not addr_post.called


@respx.mock
async def test_sync_phpipam_creates_address_on_existing_subnet(session):
    """Subnet já existente no phpIPAM + host_ip → cria o address mesmo assim."""
    await _seed_phpipam_client(session, ignore_conflict=True, host_ip="10.10.10.5")
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(
        return_value=httpx.Response(
            200,
            json={"success": True, "data": [{"id": "55", "sectionId": "7", "description": "LAN Usuarios", "vlanId": "0"}]},
        )
    )
    respx.patch(f"{BASE}/api/app/subnets/55/").mock(return_value=httpx.Response(200, json={"success": True}))
    respx.get(f"{BASE}/api/app/subnets/55/addresses/").mock(return_value=httpx.Response(200, json={"data": []}))
    addr_post = respx.post(f"{BASE}/api/app/addresses/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "1 IPs criados" in result["message"]
    assert addr_post.called


@respx.mock
async def test_sync_phpipam_no_address_when_host_ip_absent(session):
    """Sem host_ip (ex.: rota estática) → nenhuma chamada a /addresses/."""
    await _seed_phpipam_client(session)  # host_ip=None
    respx.get(f"{BASE}/api/app/l2domains/1/vlans/").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.post(f"{BASE}/api/app/vlan/").mock(return_value=httpx.Response(201, json={"data": "101"}))
    respx.get(url__regex=r".*/api/app/subnets/cidr/10\.10\.10\.0/24/").mock(return_value=httpx.Response(404))
    respx.post(f"{BASE}/api/app/subnets/").mock(return_value=httpx.Response(201, json={"id": "55"}))
    addr_post = respx.post(f"{BASE}/api/app/addresses/").mock(return_value=httpx.Response(201, json={"success": True}))

    result = await auto_discovery.sync_data_to_phpipam(1, session)

    assert "IPs criados" not in result["message"]
    assert not addr_post.called
