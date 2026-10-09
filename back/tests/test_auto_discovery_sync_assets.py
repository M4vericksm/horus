"""Testes da sincronizacao de ativos descobertos via Backup API."""
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import auto_discovery
import models
from exceptions import BCAPIError


LONG_CONFIG = "show running-config\nversion 15.\n" + ("interface vlan 10\n" * 5)


class FakeDriver:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def get_ssh_command_setup(self):
        return "terminal length 0"

    def get_config_command(self):
        return "show running-config"

    def parse_device_info(self, config_text):
        return {"model": "FakeOS", "serial_number": "SN123"}

    def parse_vlans(self, config_text):
        return [{"id": 10, "name": "USERS", "description": "Usuarios"}]

    def parse_subnets(self, config_text):
        return [{"network": "10.10.10.0", "mask": 24, "description": "LAN"}]


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


async def _seed_client_with_link(session):
    server = models.BCServer(name="BC", url="https://8.8.8.8", token="token")
    client = models.Client(name="Cliente", bc_server=server, external_group_id="legacy")
    link = models.ClientBCLink(
        client=client,
        bc_server=server,
        external_group_id="grupo-1",
        label="Principal",
    )
    session.add_all([server, client, link])
    await session.commit()
    await session.refresh(client)
    await session.refresh(link)
    link_ref = SimpleNamespace(id=link.id, bc_server=server, external_group_id=link.external_group_id)
    return client, link, link_ref


async def test_sync_from_link_adds_unique_assets_and_marks_edge_router(session, monkeypatch):
    client, _link, link_ref = await _seed_client_with_link(session)

    async def fake_iter_group_backups(http_client, server, external_group_id, timeout=20):
        yield {"device_name": "CCR-Borda-01", "id": 10, "device_id": "dev-1"}
        yield {"device_name": "CCR-Borda-01", "id": 10, "device_id": "dev-1"}
        yield {"device_name": "Switch-Acesso-01", "id": 11, "device_id": "dev-2"}

    monkeypatch.setattr(auto_discovery, "iter_group_backups", fake_iter_group_backups)

    added, restored = await auto_discovery._sync_from_link(
        client,
        link_ref,
        http_client=SimpleNamespace(),
        db=session,
    )
    await session.commit()

    assets = (await session.execute(select(models.Asset).order_by(models.Asset.hostname))).scalars().all()
    assert added == 2
    assert restored == 0
    assert [a.hostname for a in assets] == ["CCR-Borda-01", "Switch-Acesso-01"]
    assert assets[0].is_edge_router is True
    assert assets[0].category == "borda"
    assert assets[1].category == "acesso"


async def test_sync_from_link_updates_existing_asset_by_bc_device_id(session, monkeypatch):
    client, _link, link_ref = await _seed_client_with_link(session)
    existing = models.Asset(
        hostname="Nome-Antigo",
        backup_id="old",
        bc_device_id="stable-id",
        client_id=client.id,
        is_approved=True,
    )
    session.add(existing)
    await session.commit()

    async def fake_iter_group_backups(http_client, server, external_group_id, timeout=20):
        yield {"device_name": "Nome-Novo", "id": 99, "device_id": "stable-id"}

    monkeypatch.setattr(auto_discovery, "iter_group_backups", fake_iter_group_backups)

    added, _ = await auto_discovery._sync_from_link(client, link_ref, SimpleNamespace(), session)
    await session.commit()
    updated = await session.get(models.Asset, existing.id)

    assert added == 0
    assert updated.hostname == "Nome-Novo"
    assert updated.backup_id == "99"


async def test_sync_from_link_backfills_bc_device_id_by_hostname(session, monkeypatch):
    client, _link, link_ref = await _seed_client_with_link(session)
    existing = models.Asset(hostname="SW-01", backup_id="old", client_id=client.id, is_approved=True)
    session.add(existing)
    await session.commit()

    async def fake_iter_group_backups(http_client, server, external_group_id, timeout=20):
        yield {"device_name": "SW-01", "id": "new-backup", "device_id": "new-device-id"}

    monkeypatch.setattr(auto_discovery, "iter_group_backups", fake_iter_group_backups)

    added, _ = await auto_discovery._sync_from_link(client, link_ref, SimpleNamespace(), session)
    await session.commit()
    updated = await session.get(models.Asset, existing.id)

    assert added == 0
    assert updated.backup_id == "new-backup"
    assert updated.bc_device_id == "new-device-id"


async def test_sync_discovered_assets_returns_not_found_for_missing_client(session):
    result = await auto_discovery.sync_discovered_assets(404, session)
    assert result == {"error": "Cliente não encontrado."}


async def test_sync_discovered_assets_requires_link(session):
    client = models.Client(name="Sem BC")
    session.add(client)
    await session.commit()

    result = await auto_discovery.sync_discovered_assets(client.id, session)
    assert "vínculo" in result["error"]


async def test_sync_discovered_assets_rejects_missing_requested_link(session):
    client, _link, _link_ref = await _seed_client_with_link(session)

    result = await auto_discovery.sync_discovered_assets(client.id, session, link_id=999)
    assert result["status"] == "error"
    assert result["added"] == 0


async def test_sync_discovered_assets_accumulates_link_errors(session, monkeypatch):
    client, link, _link_ref = await _seed_client_with_link(session)

    async def boom(client, link, http_client, db):
        raise BCAPIError("fora do ar", "https://8.8.8.8/api/groups")

    monkeypatch.setattr(auto_discovery, "_sync_from_link", boom)

    result = await auto_discovery.sync_discovered_assets(client.id, session, link_id=link.id)
    assert result["status"] == "error"
    assert "fora do ar" in result["errors"][0]["message"]
    assert "token" not in (result["errors"][0]["url"] or "").lower()


async def test_sync_discovered_assets_success_uses_patched_link_sync(session, monkeypatch):
    client, link, _link_ref = await _seed_client_with_link(session)

    async def ok(client, link, http_client, db):
        return 3, 1

    monkeypatch.setattr(auto_discovery, "_sync_from_link", ok)

    result = await auto_discovery.sync_discovered_assets(client.id, session, link_id=link.id)
    assert result["status"] == "success"
    assert result["added"] == 3
    assert result["restored"] == 1
    assert "resgatados" in result["message"]


async def test_download_backup_wraps_timeout(monkeypatch):
    class TimeoutClient:
        async def get(self, *args, **kwargs):
            raise httpx.TimeoutException("slow")

    server = SimpleNamespace(url="https://8.8.8.8", token="token")

    with pytest.raises(BCAPIError, match="Timeout"):
        await auto_discovery._download_backup(TimeoutClient(), server, "backup-1")


async def test_download_backup_wraps_http_error(monkeypatch):
    class ErrorClient:
        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("offline")

    server = SimpleNamespace(url="https://8.8.8.8", token="token")

    with pytest.raises(BCAPIError, match="Falha ao baixar backup"):
        await auto_discovery._download_backup(ErrorClient(), server, "backup-1")


async def test_extract_client_configs_manual_returns_not_found(session):
    result = await auto_discovery.extract_client_configs_manual(999, session)
    assert result == {"error": "Cliente não encontrado."}


async def test_extract_client_configs_manual_handles_no_assets(session):
    client = models.Client(name="Sem ativos")
    session.add(client)
    await session.commit()

    result = await auto_discovery.extract_client_configs_manual(client.id, session)
    assert "Nenhum ativo manual" in result["message"]


async def test_extract_client_configs_manual_success_creates_vlan_and_subnet(session, monkeypatch):
    client = models.Client(name="Manual", vlan_prefix="CLI")
    asset = models.Asset(
        hostname="SW-Manual",
        client=client,
        ip_address="10.0.0.10",
        vendor="cisco",
        ssh_user="admin",
        ssh_pass="encrypted",
        is_approved=True,
        sync_mode="manual",
    )
    session.add_all([client, asset])
    await session.commit()

    async def fake_run_ssh_extract(**kwargs):
        assert kwargs["target_ip"] == "10.0.0.10"
        return LONG_CONFIG

    monkeypatch.setattr(auto_discovery, "decrypt_secret", lambda value: "secret" if value else None)
    monkeypatch.setattr(auto_discovery, "get_driver_class", lambda vendor: FakeDriver)
    monkeypatch.setattr(auto_discovery, "run_ssh_extract", fake_run_ssh_extract)

    result = await auto_discovery.extract_client_configs_manual(client.id, session)

    vlans = (await session.execute(select(models.Vlan))).scalars().all()
    subnets = (await session.execute(select(models.Subnet))).scalars().all()
    await session.refresh(asset)
    assert "1 equipamentos extraídos" in result["message"]
    assert vlans[0].vid == 10
    assert vlans[0].description == "CLI Usuarios"
    assert subnets[0].network == "10.10.10.0"
    assert asset.last_sync_status == "success"


async def test_extract_client_configs_manual_marks_error_for_unsupported_vendor(session, monkeypatch):
    client = models.Client(name="Manual erro")
    asset = models.Asset(
        hostname="SW-Erro",
        client=client,
        ip_address="10.0.0.11",
        vendor="unknown",
        ssh_user="admin",
        is_approved=True,
        sync_mode="manual",
    )
    session.add_all([client, asset])
    await session.commit()

    monkeypatch.setattr(auto_discovery, "get_driver_class", lambda vendor: None)

    result = await auto_discovery.extract_client_configs_manual(client.id, session)
    await session.refresh(asset)

    assert "1 falharam" in result["message"]
    assert asset.last_sync_status == "error"
    assert "Vendor sem driver" in asset.last_sync_error


async def test_extract_client_configs_manual_marks_error_on_short_output(session, monkeypatch):
    client = models.Client(name="Manual curto")
    asset = models.Asset(
        hostname="SW-Curto",
        client=client,
        ip_address="10.0.0.12",
        vendor="cisco",
        ssh_user="admin",
        is_approved=True,
        sync_mode="manual",
    )
    session.add_all([client, asset])
    await session.commit()

    async def fake_run_ssh_extract(**kwargs):
        return "curto"

    monkeypatch.setattr(auto_discovery, "decrypt_secret", lambda value: "")
    monkeypatch.setattr(auto_discovery, "get_driver_class", lambda vendor: FakeDriver)
    monkeypatch.setattr(auto_discovery, "run_ssh_extract", fake_run_ssh_extract)

    result = await auto_discovery.extract_client_configs_manual(client.id, session)
    await session.refresh(asset)

    assert "1 falharam" in result["message"]
    assert asset.last_sync_status == "error"
    assert "vazio" in asset.last_sync_error


async def test_extract_client_configs_bc_success_updates_asset_and_creates_data(session, monkeypatch):
    client, link, _link_ref = await _seed_client_with_link(session)
    client.vlan_prefix = "BC"
    asset = models.Asset(
        hostname="SW-BC",
        client_id=client.id,
        backup_id="backup-1",
        is_approved=True,
        sync_mode="auto",
    )
    session.add(asset)
    await session.commit()

    async def fake_download(http_client, server, backup_id, timeout=20):
        assert backup_id == "backup-1"
        return httpx.Response(200, content=LONG_CONFIG.encode(), request=httpx.Request("GET", "https://8.8.8.8/download"))

    monkeypatch.setattr(auto_discovery, "_download_backup", fake_download)
    monkeypatch.setattr(auto_discovery, "get_driver_class", lambda vendor: FakeDriver)

    result = await auto_discovery.extract_client_configs_bc(client.id, session)

    vlans = (await session.execute(select(models.Vlan))).scalars().all()
    subnets = (await session.execute(select(models.Subnet))).scalars().all()
    await session.refresh(asset)
    assert "BC: 1 extraídos" in result["message"]
    assert asset.vendor == "cisco"
    assert asset.model == "FakeOS"
    assert asset.serial_number == "SN123"
    assert vlans[0].description == "BC Usuarios"
    assert subnets[0].description == "BC LAN"
    assert asset.last_sync_status == "success"


async def test_extract_client_configs_bc_returns_error_without_link(session):
    client = models.Client(name="BC sem link")
    session.add(client)
    await session.commit()

    result = await auto_discovery.extract_client_configs_bc(client.id, session)
    assert result == {"error": "Sem servidor Backup API vinculado."}


async def test_extract_client_configs_combines_bc_and_manual_messages(session, monkeypatch):
    async def fake_bc(client_id, db):
        return {"message": "BC ok"}

    async def fake_manual(client_id, db):
        return {"message": "Manual ok"}

    monkeypatch.setattr(auto_discovery, "extract_client_configs_bc", fake_bc)
    monkeypatch.setattr(auto_discovery, "extract_client_configs_manual", fake_manual)

    result = await auto_discovery.extract_client_configs(1, session)
    assert result == {"message": "BC ok | Manual ok"}
