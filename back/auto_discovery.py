import os
import re
import asyncio
import httpx
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

import models
from bc_client import bc_headers, bc_url, iter_group_backups, mask_url
from crypto import decrypt_secret
from drivers.huawei import HuaweiDriver
from network_logic import get_driver_class, run_ssh_extract
from logger import logger
from log_exec import log_exec
from retry import RetryingAsyncClient
from security import validate_external_url
from exceptions import BCAPIError, BCConnectionError, BCParseError, IPAMSyncError, VendorNotSupportedError
# [TOPOLOGY] Parse de interfaces (asset_interfaces + vlan_interfaces) ATIVO.
import topology_parser

def sanitize_filename(name):
    return re.sub(r'[<>:"/\\|?*]', '_', str(name)).strip()

_SKIP_IP = re.compile(r'^(127\.|0\.|255\.|224\.|169\.254\.|0\.0\.0\.0)')

VENDOR_MARKERS: dict[str, list[str]] = {
    # huawei: VRP (roteador) + SmartAX OLT MA5600/MA5800 (formato com 'gem mapping'/'port vlan').
    "huawei": ["display current-configuration", "sysname", "gem mapping", "ma5800", "ma5600", "port vlan eth"],
    "datacom": ["aaa authentication-order", "tunnel-mac datacom"],
    "cisco": ["show running-config", "version 15."],
    "mikrotik": ["/interface vlan add", "/ip address add", "/system identity", "[admin@", "/interface bridge add"],
    "juniper": ["set system host-name", "set interfaces "],
    # Markers de assinaturas reais de produção (jun/2026):
    "vsol": ["switchport hybrid pvid vlan", "switchport hybrid vlan"],
    "fiberhome": ["wos system config file"],
    "zte": ["onu profile vlan", "tag-mode tag cvlan", "!<mim>", "vlan port eth_"],
    "intelbras": ["intelbras-olt", "meprof intelbras"],
    "hillstone": ['zone "untrust"', "stoneos", "hillstone"],
}

# Quando um config casa com mais de um vendor (ex.: o eco genérico 'show running-config'
# do cisco aparecendo num config Datacom/VSOL/ZTE/Intelbras), o de assinatura mais
# específica vence. Cisco tem prioridade mais baixa por usar markers genéricos.
VENDOR_PRIORITY = ["mikrotik", "juniper", "huawei", "fiberhome", "vsol", "zte", "intelbras", "hillstone", "datacom", "cisco"]


def _mikrotik_ssh_port(config_text: str) -> int:
    m = re.search(r'/ip service\s+set\s+ssh\s+port=(\d+)', config_text)
    if not m:
        m = re.search(r'name=ssh[^\n]*port=(\d+)|port=(\d+)[^\n]*name=ssh', config_text)
    if m:
        return int(m.group(1) or m.group(2))
    return 22


def _mikrotik_mgmt_ip(config_text: str) -> str | None:
    """
    RouterOS: várias linhas /ip address add — o primeiro da export nem sempre é gerência.
    Prioriza comentário/interface típicos de gerência/uplink.
    """
    rows = []
    pat = re.compile(
        r'/ip address add(?P<rest>[^#\n]*)',
        re.IGNORECASE,
    )
    for m in pat.finditer(config_text):
        rest = m.group('rest')
        am = re.search(r'\baddress=([\d.]+)/', rest)
        if not am:
            continue
        cand = am.group(1)
        if _SKIP_IP.match(cand):
            continue
        cm = re.search(r'\bcomment=("([^"]+)"|(\S+))', rest)
        comment = ((cm.group(2) or cm.group(3) or '').lower() if cm else '')
        im = re.search(r'\binterface=("([^"]+)"|(\S+))', rest)
        iface = ((im.group(2) or im.group(3) or '').lower() if im else '')
        rows.append((cand, comment, iface))

    if not rows:
        return None

    def score(item: tuple[str, str, str]) -> int:
        cand, comment, iface = item
        s = 0
        for kw in ('geren', 'mgmt', 'mngt', 'adm', 'loop', 'bord', 'core', 'principal'):
            if kw in comment:
                s += 50
        for kw in ('ether1', 'ether2', 'sfp', 'wan', 'uplink', 'mgmt', 'bridge-wan'):
            if kw in iface:
                s += 10
        if iface.startswith('vlan') and 'mgmt' in iface:
            s += 30
        return s

    rows.sort(key=score, reverse=True)
    best = score(rows[0])
    if best > 0:
        return rows[0][0]
    return rows[0][0]


def _huawei_mgmt(config_text: str) -> tuple[str | None, int]:
    port = 22
    m_port = re.search(r'ssh\s+server\s+port\s+(\d+)', config_text, re.IGNORECASE)
    if m_port:
        port = int(m_port.group(1))
    ip = None
    # Máscara decimal (255.255.255.0) ou comprimento (/24) — não só \d+
    for m in re.finditer(
        r'^\s*ip address ([\d.]+)\s+(\S+)\s*$',
        config_text,
        re.MULTILINE,
    ):
        candidate = m.group(1)
        if _SKIP_IP.match(candidate):
            continue
        ip = candidate
        break
    return ip, port


def _cisco_family_mgmt(config_text: str) -> tuple[str | None, int]:
    port = 22
    m_port = re.search(r'ip ssh port\s+(\d+)', config_text, re.IGNORECASE)
    if m_port:
        port = int(m_port.group(1))
    ip = None
    # Ignora endereços "secondary" (gerência costuma ser primário)
    for m in re.finditer(
        r'^\s*ip address ([\d.]+)\s+([\d.]+)\s*(secondary)?\s*$',
        config_text,
        re.MULTILINE | re.IGNORECASE,
    ):
        if m.group(3):
            continue
        candidate = m.group(1)
        if _SKIP_IP.match(candidate):
            continue
        ip = candidate
        break
    return ip, port


def extract_connection_info(config_text: str, vendor: str | None = None) -> tuple[str | None, int]:
    """
    Extrai IP de gerência e porta SSH do texto de configuração.
    Com `vendor` conhecido, aplica só as regras daquele fabricante (evita misturar
    padrões MikroTik com IOS/VRP e vice-versa).
    """
    v = (vendor or "").strip().lower()

    if v == "mikrotik":
        return _mikrotik_mgmt_ip(config_text), _mikrotik_ssh_port(config_text)
    if v == "huawei":
        return _huawei_mgmt(config_text)
    if v in ("cisco", "datacom"):
        return _cisco_family_mgmt(config_text)

    # Vendor desconhecido: tenta na ordem do mais específico ao mais genérico
    ip, port = _mikrotik_mgmt_ip(config_text), _mikrotik_ssh_port(config_text)
    if ip:
        return ip, port
    ip, port = _huawei_mgmt(config_text)
    if ip:
        return ip, port
    return _cisco_family_mgmt(config_text)


def identify_vendor(config_text: str) -> str:
    text_lower = config_text.lower()
    matched = [
        vendor for vendor, markers in VENDOR_MARKERS.items()
        if any(marker in text_lower for marker in markers)
    ]
    if not matched:
        return "unknown"
    if len(matched) == 1:
        logger.debug("[identify_vendor] vendor=%s", matched[0])
        return matched[0]
    # Múltiplos candidatos: resolve por prioridade (assinatura específica > genérica).
    for vendor in VENDOR_PRIORITY:
        if vendor in matched:
            logger.debug("[identify_vendor] candidatos=%s -> %s (prioridade)", matched, vendor)
            return vendor
    logger.debug("[identify_vendor] candidatos=%s sem prioridade -> unknown", matched)
    return "unknown"

def detect_edge_router(hostname: str) -> bool:
    keywords = ['borda', 'router', 'aut', 'gw', 'gateway', 'ne8000', 'ccr']
    return any(keyword in hostname.lower() for keyword in keywords)


def _is_monitoring_host(hostname: str) -> bool:
    """Servidores de monitoração (Zabbix/Grafana) não são equipamentos de rede:
    seus 'backups' são dumps binários enormes (até dezenas de MB) sem VLAN. São
    rotulados como vendor='monitoramento' e pulados na extração (não viram unknown)."""
    h = (hostname or "").lower()
    return ('zabbix' in h) or ('grafana' in h) or ('linux' in h)

def _mark_asset_sync(asset, status: str, error: str | None = None):
    asset.last_sync_status = status
    asset.last_sync_at = datetime.now(timezone.utc).replace(tzinfo=None)
    asset.last_sync_error = error[:500] if error else None

async def discover_all_clients(db: AsyncSession):
    return {"message": "A descoberta global agora é feita via main.py (multi-servers)"}


# ─────────────────────────────────────────────────────────────────────────────
# [TOPOLOGY - DESABILITADO]
# A função _persist_interfaces salva interfaces físicas nas tabelas asset_interfaces
# e vlan_interfaces geradas pela migration 011_topology_tables.
#
# Para ativar:
#   1. Execute: alembic upgrade head
#   2. Descomente 'import topology_parser' no topo deste arquivo
#   3. Descomente os blocos [TOPOLOGY CALL] nas funções de extração abaixo
#   4. Descomente esta função inteira
# ─────────────────────────────────────────────────────────────────────────────
async def _persist_interfaces(
    ativo: models.Asset,
    interfaces: list[dict],
    db: AsyncSession,
) -> None:
    """
    Persiste as interfaces extraídas pelo topology_parser no banco.
    Upsert em asset_interfaces (asset_id + name) e vlan_interfaces (vlan_id + interface_id).
    Falhas são logadas e nunca propagadas — o fluxo de extração continua normalmente.
    """
    if not interfaces:
        return
    try:
        res_vlans = await db.execute(
            select(models.Vlan).where(models.Vlan.asset_id == ativo.id)
        )
        db_vlans = {v.vid: v for v in res_vlans.scalars().all()}

        res_subs = await db.execute(
            select(models.Subnet).where(models.Subnet.asset_id == ativo.id)
        )
        db_subs = res_subs.scalars().all()
        mgmt_ip = ativo.ip_address

        for iface_data in interfaces:
            name = iface_data.get('name', '').strip()
            if not name:
                continue

            res_if = await db.execute(
                select(models.AssetInterface).where(
                    models.AssetInterface.asset_id == ativo.id,
                    models.AssetInterface.name == name,
                )
            )
            db_iface = res_if.scalar_one_or_none()
            if db_iface:
                db_iface.type = iface_data.get('type', db_iface.type)
                db_iface.description = iface_data.get('description') or db_iface.description
                db_iface.is_management = (mgmt_ip is not None and iface_data.get('ip_address') == mgmt_ip)
            else:
                db_iface = models.AssetInterface(
                    asset_id=ativo.id,
                    name=name,
                    type=iface_data.get('type', 'physical'),
                    description=iface_data.get('description'),
                    is_management=(mgmt_ip is not None and iface_data.get('ip_address') == mgmt_ip),
                )
                db.add(db_iface)
                await db.flush()  # garante db_iface.id antes de usar como FK

            for vlan_entry in iface_data.get('vlans', []):
                vid = vlan_entry.get('vid')
                mode = vlan_entry.get('mode', 'trunk')
                db_vlan = db_vlans.get(vid)
                if db_vlan is None:
                    continue
                res_vi = await db.execute(
                    select(models.VlanInterface).where(
                        models.VlanInterface.vlan_id == db_vlan.id,
                        models.VlanInterface.interface_id == db_iface.id,
                    )
                )
                existing_vi = res_vi.scalar_one_or_none()
                if existing_vi:
                    existing_vi.mode = mode
                else:
                    db.add(models.VlanInterface(
                        vlan_id=db_vlan.id,
                        interface_id=db_iface.id,
                        mode=mode,
                    ))

            # NOTA: Vinculo subnet<->interface por correspondência exata de IP de rede
            # (sub.network == iface_ip). A heurística por prefixo foi removida pois
            # gerava falsos positivos (ex: 192.168.1.x coincidia com 192.168.10.x).
            iface_ip = iface_data.get('ip_address')
            if iface_ip:
                for sub in db_subs:
                    if sub.network and sub.interface_id is None and sub.network == iface_ip:
                        sub.interface_id = db_iface.id

        logger.info(f'[topology] Interfaces persistidas para ativo {ativo.hostname} ({len(interfaces)} IFs).')
    except Exception as e:
        logger.warning(f'[topology] Falha ao persistir interfaces para {ativo.hostname}: {e}')

async def _sync_from_link(client, link, http_client, db) -> tuple[int, int]:
    """Sincroniza ativos de um único vínculo BC. Retorna (added, restored)."""
    server = link.bc_server
    added_count = 0
    restored_count = 0
    seen_devices = set()

    async for ativo in iter_group_backups(http_client, server, link.external_group_id, timeout=20):
        device_name = ativo.get('device_name', 'Desconhecido')
        backup_id = str(ativo.get('id'))
        bc_device_id = ativo.get('device_id')  # UUID imutável do equipamento no BC
        device_key = bc_device_id or f"name:{device_name}"
        if device_key in seen_devices:
            continue
        seen_devices.add(device_key)

        # Lookup primário: bc_device_id (estável mesmo após renomear o equipamento)
        existing_asset = None
        if bc_device_id:
            check = await db.execute(
                select(models.Asset).where(
                    models.Asset.bc_device_id == bc_device_id,
                    models.Asset.client_id == client.id,
                )
            )
            existing_asset = check.scalar_one_or_none()

        # Fallback legado: hostname (para assets sem bc_device_id ainda)
        if not existing_asset:
            check_hn = await db.execute(
                select(models.Asset).where(
                    models.Asset.hostname == device_name,
                    models.Asset.client_id == client.id,
                )
            )
            existing_asset = check_hn.scalar_one_or_none()

        if existing_asset:
            # Atualiza campos que podem ter mudado
            existing_asset.backup_id = backup_id
            if bc_device_id and not existing_asset.bc_device_id:
                existing_asset.bc_device_id = bc_device_id
            if existing_asset.hostname != device_name:
                existing_asset.hostname = device_name
        else:
            is_edge = detect_edge_router(device_name)
            db.add(models.Asset(
                hostname=device_name,
                backup_id=backup_id,
                bc_device_id=bc_device_id,
                client_id=client.id,
                is_edge_router=is_edge,
                category="borda" if is_edge else "acesso",
                authority_level=5 if is_edge else 1,
                is_approved=True,
                sync_mode="auto",
                ignore_vlan_conflict=True,
            ))
            added_count += 1

    return added_count, restored_count


async def _download_backup(http_client, server, backup_id: str, timeout: float = 20):
    url = bc_url(server, "backups", backup_id, "download")
    try:
        return await http_client.get(url, headers=bc_headers(server), timeout=timeout)
    except httpx.TimeoutException as exc:
        raise BCAPIError("Timeout ao baixar backup da Backup API", url) from exc
    except httpx.HTTPError as exc:
        raise BCAPIError(f"Falha ao baixar backup da Backup API: {exc}", url) from exc


async def sync_discovered_assets(client_id: int, db: AsyncSession, link_id: int | None = None):
    """
    Sincroniza ativos de todos os vínculos BC do cliente (ou de um link específico).
    Prioridade: ClientBCLink (nova tabela) > campo legado bc_server_id/external_group_id.
    """
    res = await db.execute(
        select(models.Client)
        .options(
            selectinload(models.Client.bc_server),
            selectinload(models.Client.bc_links).selectinload(models.ClientBCLink.bc_server)
        )
        .where(models.Client.id == client_id)
    )
    client = res.scalar_one_or_none()
    if not client:
        return {"error": "Cliente não encontrado."}

    # Determina quais links processar
    if link_id:
        links = [lnk for lnk in client.bc_links if lnk.id == link_id]
        if not links:
            return {"status": "error", "message": "Vinculo Backup API nao encontrado.", "added": 0, "restored": 0, "errors": []}
    elif client.bc_links:
        links = list(client.bc_links)
    elif client.bc_server and client.external_group_id:
        # Compatibilidade retroativa com campo legado
        from types import SimpleNamespace
        fake_link = SimpleNamespace(
            id=0,
            bc_server=client.bc_server,
            external_group_id=client.external_group_id
        )
        links = [fake_link]
    else:
        return {"error": "Cliente não possui vínculo com servidor Backup API."}

    total_added = 0
    total_restored = 0
    errors = []

    async with log_exec(db, client_id=client_id, operation="sync_assets") as ctx:
        async with httpx.AsyncClient(timeout=20) as http_client:
            http_client = RetryingAsyncClient(http_client)
            for lnk in links:
                try:
                    added, restored = await _sync_from_link(client, lnk, http_client, db)
                    total_added += added
                    total_restored += restored
                except BCAPIError as e:
                    logger.warning(f"[sync_assets] Link {lnk.id} erro de API Backup API: {e}")
                    errors.append({
                        "link_id": lnk.id,
                        "bc_server_id": getattr(lnk.bc_server, "id", None),
                        "status_code": e.status_code,
                        "url": mask_url(e.url),
                        "message": str(e),
                    })
                except Exception as e:
                    logger.warning(f"[sync_assets] Link {lnk.id} erro inesperado: {e}")
                    errors.append({
                        "link_id": lnk.id,
                        "bc_server_id": getattr(lnk.bc_server, "id", None),
                        "status_code": None,
                        "url": None,
                        "message": f"Falha ao contatar Backup API: {e}",
                    })

        await db.commit()
        if errors:
            msg = "Falha ao contatar a Backup API."
            ctx["status"] = "error"
            ctx["message"] = msg
            ctx["detail"] = "; ".join(err["message"] for err in errors)
            return {
                "status": "error",
                "message": msg,
                "added": total_added,
                "restored": total_restored,
                "errors": errors,
            }

        msg = f"{total_added} novos equipamentos inseridos."
        if total_restored > 0:
            msg += f" {total_restored} resgatados da quarentena!"
        elif total_added == 0:
            msg = "Todos os equipamentos já estão visíveis no painel."
        ctx["message"] = msg
        return {
            "status": "success",
            "message": msg,
            "added": total_added,
            "restored": total_restored,
            "errors": [],
        }

async def extract_client_configs_bc(client_id: int, db: AsyncSession):
    res_client = await db.execute(
        select(models.Client)
        .options(
            selectinload(models.Client.bc_server),
            selectinload(models.Client.bc_links).selectinload(models.ClientBCLink.bc_server)
        )
        .where(models.Client.id == client_id)
    )
    client = res_client.scalar_one_or_none()
    if not client:
        return {"error": "Cliente não encontrado."}

    # Monta lista de (server, group_id) — prioriza nova tabela, cai no legado
    server_group_pairs = []
    if client.bc_links:
        for lnk in client.bc_links:
            if lnk.bc_server:
                server_group_pairs.append((lnk.bc_server, lnk.external_group_id))
    elif client.bc_server and client.external_group_id:
        server_group_pairs.append((client.bc_server, client.external_group_id))

    if not server_group_pairs:
        return {"error": "Sem servidor Backup API vinculado."}

    # Monta lista de todos os servidores para tentar downloads
    all_servers = [srv for srv, _ in server_group_pairs]

    res_assets = await db.execute(select(models.Asset).where(models.Asset.client_id == client_id, models.Asset.is_approved == True, models.Asset.sync_mode == "auto", models.Asset.backup_id.isnot(None)))
    ativos = res_assets.scalars().all()

    vlans_found = 0
    subnets_found = 0
    bc_ok = 0
    ssh_fallback_ok = 0
    failed = []
    MAX_BC_RETRIES = 3

    async with log_exec(db, client_id=client_id, operation="extract_bc") as ctx:
        async with httpx.AsyncClient(timeout=20) as http_client:
            http_client = RetryingAsyncClient(http_client)
            for ativo in ativos:
                config_text = None
                _mark_asset_sync(ativo, "pending")

                # Servidores de monitoração (Zabbix/Grafana) não são equipamentos de
                # rede — rotula e pula (evita baixar dumps binários enormes e não
                # polui o inventário com 'unknown').
                if _is_monitoring_host(ativo.hostname):
                    ativo.vendor = "monitoramento"
                    _mark_asset_sync(ativo, "success")
                    continue

                # ── Tenta BC com até 3 tentativas ──
                for attempt in range(1, MAX_BC_RETRIES + 1):
                    for server in all_servers:
                        try:
                            down_res = await _download_backup(http_client, server, ativo.backup_id)
                            if down_res.status_code == 200:
                                raw = down_res.content
                                if raw[:4] == b"PK\x03\x04":
                                    config_text = HuaweiDriver.extract_zip_config(raw)
                                else:
                                    config_text = raw.decode('utf-8', errors='ignore')
                                break
                            logger.warning(
                                "[%s] Tentativa %s/3 - servidor %s retornou HTTP %s em %s",
                                ativo.hostname,
                                attempt,
                                server.name,
                                down_res.status_code,
                                mask_url(str(down_res.url)),
                            )
                        except BCAPIError as e:
                            logger.warning(f"[{ativo.hostname}] Tentativa {attempt}/3 - servidor {server.name}: {e}")
                            continue
                        except Exception as e:
                            logger.warning(f"[{ativo.hostname}] Tentativa {attempt}/3 - servidor {server.name}: {e}")
                            continue
                    if config_text:
                        break  # Conseguiu em algum servidor, sai do loop de tentativas
                    if attempt < MAX_BC_RETRIES:
                        await asyncio.sleep(1)  # Aguarda 1s entre tentativas

                # ── Fallback: backup_id stale → usa a listagem do grupo ──
                # O passo de discover pode ter avançado o backup_id para um backup
                # "mais recente" ainda indisponível para download (404). Aqui
                # iteramos os backups do device no grupo e baixamos o mais recente
                # que realmente responde 200 (mesma lógica que recupera os OLTs).
                if not config_text and ativo.bc_device_id:
                    for server, gid in server_group_pairs:
                        if config_text:
                            break
                        try:
                            tried = 0
                            async for item in iter_group_backups(http_client, server, gid, timeout=20):
                                if item.get("device_id") != ativo.bc_device_id:
                                    continue
                                bid = str(item.get("id"))
                                if bid == str(ativo.backup_id):
                                    continue  # já tentado no loop acima
                                tried += 1
                                try:
                                    dr = await _download_backup(http_client, server, bid)
                                    if dr.status_code == 200:
                                        raw = dr.content
                                        config_text = (HuaweiDriver.extract_zip_config(raw)
                                                       if raw[:4] == b"PK\x03\x04"
                                                       else raw.decode("utf-8", errors="ignore"))
                                        ativo.backup_id = bid
                                        logger.info(f"[{ativo.hostname}] backup_id stale; recuperado via listagem do grupo ({bid}).")
                                        break
                                except Exception:
                                    pass
                                if tried >= 12:
                                    break
                        except Exception as e:
                            logger.warning(f"[{ativo.hostname}] fallback listagem do grupo falhou: {e}")

                # ── Fallback SSH se BC falhou e ativo tem credenciais SSH ──
                if not config_text:
                    if ativo.ip_address and ativo.ssh_user and ativo.vendor:
                        logger.info(f"[{ativo.hostname}] BC falhou após {MAX_BC_RETRIES} tentativas. Tentando SSH direto...")
                        DriverClass = get_driver_class(ativo.vendor)
                        if DriverClass:
                            ssh_pass = decrypt_secret(ativo.ssh_pass) or ""
                            proxy_pass = decrypt_secret(ativo.override_vpn_pass) or decrypt_secret(client.vpn_pass)
                            driver_fb = DriverClass(hostname=ativo.hostname, ip=ativo.ip_address,
                                                     user=ativo.ssh_user, password=ssh_pass)
                            proxy_ip = ativo.override_vpn_host or client.vpn_host
                            proxy_port = ativo.override_vpn_port or client.vpn_port or 22
                            proxy_user = ativo.override_vpn_user or client.vpn_user
                            try:
                                config_text = await run_ssh_extract(
                                    target_ip=ativo.ip_address,
                                    target_port=ativo.port or 22,
                                    target_user=ativo.ssh_user,
                                    target_pass=ssh_pass,
                                    setup_cmd=driver_fb.get_ssh_command_setup(),
                                    config_cmd=driver_fb.get_config_command(),
                                    proxy_ip=proxy_ip, proxy_port=proxy_port,
                                    proxy_user=proxy_user, proxy_pass=proxy_pass,
                                )
                                if config_text and len(config_text.strip()) >= 50:
                                    ssh_fallback_ok += 1
                                    logger.info(f"[{ativo.hostname}] Fallback SSH bem-sucedido!")
                                else:
                                    config_text = None
                            except Exception as e:
                                logger.warning(f"[{ativo.hostname}] Fallback SSH também falhou: {e}")
                                config_text = None

                    if not config_text:
                        failed.append(ativo.hostname)
                        err = f"Backup {ativo.backup_id} indisponível após {MAX_BC_RETRIES} tentativas BC + fallback SSH."
                        _mark_asset_sync(ativo, "error", err)
                        logger.warning(f"[{ativo.hostname}] {err}")
                        continue
                else:
                    bc_ok += 1

                # ── Parse do config_text (obtido via BC ou fallback SSH) ──
                vendor = identify_vendor(config_text)
                ativo.vendor = vendor

                # Extrai e salva IP + porta de gerência (regras por fabricante)
                mgmt_ip, mgmt_port = extract_connection_info(config_text, vendor)
                if mgmt_ip:
                    ativo.ip_address = mgmt_ip
                    ativo.port = mgmt_port

                DriverClass = get_driver_class(vendor)
                if not DriverClass:
                    _mark_asset_sync(ativo, "error", f"Fabricante não suportado: {vendor}")
                    continue

                driver = DriverClass(hostname=ativo.hostname, ip="", user="", password="")

                # Extrai model e serial do config
                device_info = driver.parse_device_info(config_text)
                if device_info.get("model"):
                    ativo.model = device_info["model"]
                if device_info.get("serial_number"):
                    ativo.serial_number = device_info["serial_number"]
                prefix = client.vlan_prefix + " " if client.vlan_prefix else ""

                for vlan_data in driver.parse_vlans(config_text):
                    vid = vlan_data.get('id') or vlan_data.get('number')
                    name = vlan_data['name']
                    desc = f"{prefix}{vlan_data['description']}".strip()
                    vlan_type = vlan_data.get('type')
                    vlan_cfg = vlan_data.get('config')
                    check = await db.execute(select(models.Vlan).where(
                        models.Vlan.asset_id == ativo.id, models.Vlan.vid == vid
                    ))
                    existing_vlan = check.scalar_one_or_none()
                    if existing_vlan:
                        existing_vlan.name = name
                        existing_vlan.description = desc
                        existing_vlan.vlan_type = vlan_type
                        existing_vlan.config = vlan_cfg
                    else:
                        db.add(models.Vlan(vid=vid, name=name, description=desc, vlan_type=vlan_type,
                                           config=vlan_cfg, client_id=client.id, asset_id=ativo.id))
                        vlans_found += 1

                for sub_data in driver.parse_subnets(config_text):
                    net = sub_data['network']
                    mask = sub_data['mask']
                    desc = f"{prefix}{sub_data['description']}".strip()
                    host_ip = sub_data.get('host_ip')
                    check_sub = await db.execute(select(models.Subnet).where(
                        models.Subnet.asset_id == ativo.id,
                        models.Subnet.network == net,
                        models.Subnet.mask == mask
                    ))
                    existing_sub = check_sub.scalar_one_or_none()
                    if existing_sub:
                        existing_sub.description = desc
                        existing_sub.host_ip = host_ip
                    else:
                        db.add(models.Subnet(network=net, mask=mask, description=desc,
                                             host_ip=host_ip,
                                             client_id=client.id, asset_id=ativo.id))
                        subnets_found += 1
                _mark_asset_sync(ativo, "success")

                # [TOPOLOGY] Preenche asset_interfaces + vlan_interfaces (mapeamento VLAN↔interface).
                ifaces = topology_parser.parse_interfaces(
                    config_text, vendor, mgmt_ip=ativo.ip_address
                )
                await _persist_interfaces(ativo, ifaces, db)

        await db.commit()
        parts = [f"BC: {bc_ok} extraídos ({vlans_found} VLANs, {subnets_found} Subnets)"]
        if ssh_fallback_ok:
            parts.append(f"{ssh_fallback_ok} via fallback SSH")
        if failed:
            parts.append(f"{len(failed)} falharam: {', '.join(failed[:5])}")
        msg = " | ".join(parts)
        if failed:
            ctx["status"] = "error"
            ctx["detail"] = f"Backups indisponiveis: {', '.join(failed)}"
        ctx["message"] = msg
        return {"message": msg}

async def extract_client_configs_manual(client_id: int, db: AsyncSession):
    """
    Extração SSH direta: conecta nos equipamentos via Paramiko/SSH
    (direto ou via jump host/proxy) e extrai VLANs/subnets.
    Processa apenas ativos com sync_mode == 'manual', is_approved == True,
    que tenham ip_address, ssh_user e vendor configurados.
    """
    res_client = await db.execute(
        select(models.Client).where(models.Client.id == client_id)
    )
    client = res_client.scalar_one_or_none()
    if not client:
        return {"error": "Cliente não encontrado."}

    # Buscar ativos manuais aprovados com IP e credenciais
    res_assets = await db.execute(
        select(models.Asset).where(
            models.Asset.client_id == client_id,
            models.Asset.is_approved == True,
            models.Asset.sync_mode == "manual",
            models.Asset.ip_address.isnot(None),
            models.Asset.ssh_user.isnot(None),
        )
    )
    ativos = res_assets.scalars().all()

    if not ativos:
        return {"message": "Nenhum ativo manual com IP e credenciais SSH configurados."}

    vlans_found = 0
    subnets_found = 0
    success_count = 0
    error_count = 0

    async with log_exec(db, client_id=client_id, operation="extract_ssh") as ctx:
        for ativo in ativos:
            vendor = ativo.vendor or "unknown"
            DriverClass = get_driver_class(vendor)
            if not DriverClass:
                logger.warning(f"[SSH Manual] {ativo.hostname}: vendor '{vendor}' sem driver.")
                _mark_asset_sync(ativo, "error", f"Vendor sem driver: {vendor}")
                error_count += 1
                continue

            driver = DriverClass(
                hostname=ativo.hostname,
                ip=ativo.ip_address,
                user=ativo.ssh_user,
                password=decrypt_secret(ativo.ssh_pass) or ""
            )
            setup_cmd = driver.get_ssh_command_setup()
            config_cmd = driver.get_config_command()

            # Resolver VPN: override do ativo > global do grupo > direto
            proxy_ip = ativo.override_vpn_host or client.vpn_host
            proxy_port = ativo.override_vpn_port or client.vpn_port or 22
            proxy_user = ativo.override_vpn_user or client.vpn_user
            proxy_pass = decrypt_secret(ativo.override_vpn_pass) or decrypt_secret(client.vpn_pass)
            ssh_pass = decrypt_secret(ativo.ssh_pass) or ""

            try:
                config_text = await run_ssh_extract(
                    target_ip=ativo.ip_address,
                    target_port=ativo.port or 22,
                    target_user=ativo.ssh_user,
                    target_pass=ssh_pass,
                    setup_cmd=setup_cmd,
                    config_cmd=config_cmd,
                    proxy_ip=proxy_ip,
                    proxy_port=proxy_port,
                    proxy_user=proxy_user,
                    proxy_pass=proxy_pass,
                )
            except Exception as e:
                logger.warning(f"[SSH Manual] {ativo.hostname} ({ativo.ip_address}): {e}")
                _mark_asset_sync(ativo, "error", str(e))
                error_count += 1
                continue

            if not config_text or len(config_text.strip()) < 50:
                logger.warning(f"[SSH Manual] {ativo.hostname}: output vazio ou muito curto.")
                _mark_asset_sync(ativo, "error", "Output SSH vazio ou muito curto.")
                error_count += 1
                continue

            # Atualiza vendor caso tenha sido detectado como unknown
            detected_vendor = identify_vendor(config_text)
            if detected_vendor != "unknown":
                ativo.vendor = detected_vendor

            prefix = client.vlan_prefix + " " if client.vlan_prefix else ""

            for vlan_data in driver.parse_vlans(config_text):
                vid = vlan_data.get('id') or vlan_data.get('number')
                name = vlan_data['name']
                desc = f"{prefix}{vlan_data['description']}".strip()
                vlan_type = vlan_data.get('type')
                vlan_cfg = vlan_data.get('config')
                check = await db.execute(select(models.Vlan).where(
                    models.Vlan.asset_id == ativo.id, models.Vlan.vid == vid
                ))
                existing_vlan = check.scalar_one_or_none()
                if existing_vlan:
                    existing_vlan.name = name
                    existing_vlan.description = desc
                    existing_vlan.vlan_type = vlan_type
                    existing_vlan.config = vlan_cfg
                else:
                    db.add(models.Vlan(vid=vid, name=name, description=desc, vlan_type=vlan_type,
                                       config=vlan_cfg, client_id=client.id, asset_id=ativo.id))
                    vlans_found += 1

            for sub_data in driver.parse_subnets(config_text):
                net = sub_data['network']
                mask = sub_data['mask']
                desc = f"{prefix}{sub_data['description']}".strip()
                host_ip = sub_data.get('host_ip')
                check_sub = await db.execute(select(models.Subnet).where(
                    models.Subnet.asset_id == ativo.id,
                    models.Subnet.network == net,
                    models.Subnet.mask == mask
                ))
                existing_sub = check_sub.scalar_one_or_none()
                if existing_sub:
                    existing_sub.description = desc
                    existing_sub.host_ip = host_ip
                else:
                    db.add(models.Subnet(network=net, mask=mask, description=desc,
                                         host_ip=host_ip,
                                         client_id=client.id, asset_id=ativo.id))
                    subnets_found += 1

            success_count += 1
            _mark_asset_sync(ativo, "success")

            # [TOPOLOGY] Preenche asset_interfaces + vlan_interfaces (mapeamento VLAN↔interface).
            ifaces = topology_parser.parse_interfaces(
                config_text, detected_vendor if detected_vendor != 'unknown' else vendor,
                mgmt_ip=ativo.ip_address
            )
            await _persist_interfaces(ativo, ifaces, db)

        await db.commit()
        msg = f"SSH Manual: {success_count} equipamentos extraídos ({vlans_found} VLANs, {subnets_found} Subnets)."
        if error_count > 0:
            msg += f" {error_count} falharam."
        ctx["message"] = msg
        return {"message": msg}

async def extract_client_configs(client_id: int, db: AsyncSession):
    """
    Extração inteligente por sync_mode:
    - auto: BC (3 tentativas) → fallback SSH → erro
    - manual: SSH direto
    """
    res_bc = await extract_client_configs_bc(client_id, db)
    res_manual = await extract_client_configs_manual(client_id, db)
    bc_msg = res_bc.get('message', res_bc.get('error', ''))
    manual_msg = res_manual.get('message', '')
    parts = [p for p in [bc_msg, manual_msg] if p]
    return {"message": " | ".join(parts) if parts else "Nenhum ativo para extrair."}

def get_category_weight(category: str) -> int:
    weights = {"borda": 10000, "autenticador": 8000, "core": 6000, "olt": 4000, "acesso": 2000}
    return weights.get(category.lower(), 1000)

def _normalize_phpipam_url(url: str) -> str:
    """Normaliza a base URL do phpIPAM e valida contra SSRF.
    Preserva o scheme original (http ou https); usa http:// como fallback neutro
    quando nenhum scheme estiver presente. Bloqueia destinos internos/metadata
    via validate_external_url."""
    base_ip = url.rstrip("/")
    if "://" not in base_ip:
        base_ip = f"http://{base_ip}"
    validate_external_url(base_ip)
    return base_ip


async def _get_phpipam_token(base_ip: str, app_id: str, user: str, password: str) -> Optional[str]:
    import base64
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            res = await c.post(
                f"{base_ip}/api/{app_id}/user/",
                headers={"Authorization": f"Basic {creds}"},
            )
            if res.status_code == 200 and res.json().get("success"):
                return res.json()["data"]["token"]
    except Exception as e:
        logger.warning(f"[_get_phpipam_token] Falha ao renovar token do App ID '{app_id}' em {base_ip}: {e}")
    return None

async def _sync_phpipam_address(http_client, base_ip: str, app_id: str, headers: dict,
                                subnet_id, host_ip: str, hostname: Optional[str]) -> int:
    """Cria o IP host (address) dentro da subnet no phpIPAM, com descrição = hostname.
    Idempotente: pula se o IP já existir na subnet. Retorna 1 se criou, 0 caso contrário."""
    if not subnet_id or not host_ip:
        return 0
    try:
        # Evita duplicar: lista os addresses da subnet e checa se o IP já está lá
        res_list = await http_client.get(
            f"{base_ip}/api/{app_id}/subnets/{subnet_id}/addresses/",
            headers=headers, timeout=10,
        )
        if res_list.status_code == 200:
            for a in (res_list.json().get("data") or []):
                if a.get("ip") == host_ip:
                    return 0
        payload = {
            "subnetId": subnet_id,
            "ip": host_ip,
            "description": hostname or "",
            "hostname": hostname or "",
        }
        res_post = await http_client.post(
            f"{base_ip}/api/{app_id}/addresses/",
            headers=headers, json=payload,
        )
        if res_post.status_code in (200, 201):
            return 1
        logger.warning(f"[phpIPAM] Falha ao criar IP {host_ip} na subnet {subnet_id} "
                       f"(HTTP {res_post.status_code}): {res_post.text}")
    except Exception as e:
        logger.warning(f"[phpIPAM] Erro ao sincronizar IP {host_ip}: {e}")
    return 0


async def _resolve_phpipam_subnet_id(http_client, base_ip: str, app_id: str, headers: dict,
                                     network: str, mask) -> Optional[int]:
    """Resolve o subnetId do phpIPAM para um CIDR declarado (network/mask).
    Retorna None se a subnet ainda não existir no phpIPAM."""
    try:
        res = await http_client.get(
            f"{base_ip}/api/{app_id}/subnets/cidr/{network}/{mask}/",
            headers=headers, timeout=10,
        )
        if res.status_code == 200:
            data = res.json().get("data") or []
            if isinstance(data, dict):
                data = [data]
            for match in data:
                sid = match.get("id")
                if sid:
                    return sid
    except Exception as e:
        logger.warning(f"[phpIPAM] Falha ao resolver subnet {network}/{mask}: {e}")
    return None


async def sync_zabbix_ips_to_phpipam(client_id: int, zabbix_url: str, zabbix_token: str,
                                     zabbix_verify: bool, db: AsyncSession) -> dict:
    """AUTO IPAM (fonte observada = Zabbix): cria no phpIPAM os IPs vivos que caem
    dentro de blocos já declarados (extraídos das configs). Idempotente.

    - `created`  : IPs novos gravados no phpIPAM.
    - `skipped`  : IPs que já existiam (dedup do `_sync_phpipam_address`).
    - `orphans`  : IPs vivos fora de qualquer bloco declarado, ou cuja subnet
                   ainda não existe no phpIPAM — sinal de rede não documentada;
                   NUNCA são gravados às cegas (viram alerta na tela)."""
    import ipaddress
    import zabbix_client as zbx

    client = await db.get(models.Client, client_id)
    if not client:
        return {"ok": False, "error": "Cliente não encontrado."}
    if not client.ip or not client.token:
        return {"ok": False, "error": "phpIPAM não configurado para este cliente."}

    # 1. IPs observados no Zabbix.
    async with zbx.ZabbixClient(zabbix_url, zabbix_token, verify_tls=zabbix_verify) as z:
        hosts = await z.get_hosts()
    observed = zbx.extract_host_ips(hosts)
    if not observed:
        return {"ok": True, "observed": 0, "created": 0, "skipped": 0, "orphans": [],
                "message": "Nenhum IP observado no Zabbix."}

    # 2. Blocos declarados do cliente (Subnets extraídas das configs).
    subs = (await db.execute(
        select(models.Subnet).where(models.Subnet.client_id == client_id)
    )).scalars().all()
    networks: list[tuple[Any, models.Subnet]] = []
    for s in subs:
        if not s.network or s.mask is None:
            continue
        try:
            net = ipaddress.ip_network(f"{s.network}/{s.mask}", strict=False)
        except ValueError:
            continue
        networks.append((net, s))

    # 3. phpIPAM: base + re-auth (mesmo padrão de sync_data_to_phpipam).
    base_ip = _normalize_phpipam_url(client.ip)
    auth_token = decrypt_secret(client.token) or ""
    if client.phpipam_user and client.phpipam_pass:
        fresh = await _get_phpipam_token(base_ip, client.token_name, client.phpipam_user,
                                         decrypt_secret(client.phpipam_pass))
        if fresh:
            auth_token = fresh
    json_headers = {"token": auth_token, "Content-Type": "application/json"}

    created = skipped = 0
    orphans: list[dict] = []
    subnet_id_cache: dict[tuple, Optional[int]] = {}

    async with log_exec(db, client_id=client_id, operation="sync_zabbix_ips"):
        async with httpx.AsyncClient(timeout=25) as raw:
            http_client = RetryingAsyncClient(raw)
            for obs in observed:
                try:
                    ip_obj = ipaddress.ip_address(obs["ip"])
                except ValueError:
                    continue
                # Bloco declarado mais específico que contém o IP (maior prefixlen).
                match = None
                for net, s in networks:
                    if ip_obj in net and (match is None or net.prefixlen > match[0].prefixlen):
                        match = (net, s)
                if not match:
                    orphans.append({"ip": obs["ip"], "hostname": obs["hostname"],
                                    "reason": "sem_bloco_declarado"})
                    continue
                net, sub = match
                # Endereço de rede/broadcast do bloco não é host documentável —
                # só dá para saber isso conhecendo a máscara, por isso a checagem
                # mora aqui (Zabbix real traz coisas como 198.51.100.0 como "host").
                if net.prefixlen < 31 and ip_obj in (net.network_address, net.broadcast_address):
                    orphans.append({"ip": obs["ip"], "hostname": obs["hostname"],
                                    "reason": "endereco_de_rede_ou_broadcast"})
                    continue
                key = (sub.network, sub.mask)
                if key not in subnet_id_cache:
                    subnet_id_cache[key] = await _resolve_phpipam_subnet_id(
                        http_client, base_ip, client.token_name, json_headers,
                        sub.network, sub.mask)
                sid = subnet_id_cache[key]
                if not sid:
                    orphans.append({"ip": obs["ip"], "hostname": obs["hostname"],
                                    "reason": "subnet_ausente_no_phpipam"})
                    continue
                n = await _sync_phpipam_address(
                    http_client, base_ip, client.token_name, json_headers,
                    sid, obs["ip"], obs["hostname"])
                created += n
                skipped += (1 - n)

    return {"ok": True, "observed": len(observed), "created": created,
            "skipped": skipped, "orphans": orphans}


async def sync_data_to_phpipam(client_id: int, db: AsyncSession):
    client = await db.get(models.Client, client_id)
    if not client or not client.ip or not client.token:
        return {"error": "Sem API IPAM"}

    base_ip = _normalize_phpipam_url(client.ip)

    # Auto-reauth: obtém token fresco se credenciais estiverem configuradas
    # Bug fix: decrypt sempre antes de tentar reauth, garantindo token limpo como base
    auth_token = decrypt_secret(client.token) or ""
    if client.phpipam_user and client.phpipam_pass:
        fresh = await _get_phpipam_token(base_ip, client.token_name, client.phpipam_user, decrypt_secret(client.phpipam_pass))
        if fresh:
            auth_token = fresh
        else:
            logger.warning("[phpIPAM] Falha na re-autenticação; usando token armazenado.")

    # Bug fix: separar headers para GETs (sem Content-Type) e POST/PATCH (com Content-Type)
    # O phpIPAM rejeita GETs com Content-Type: application/json em algumas versões
    base_headers = {"token": auth_token}
    json_headers = {"token": auth_token, "Content-Type": "application/json"}

    synced_vlans = 0
    synced_subnets = 0
    updated_vlans = 0
    updated_subnets = 0
    deleted_vlans = 0
    synced_ips = 0
    conflicts = []      # Lista de conflitos pendentes para o frontend
    renamed_vlans = []  # VLANs renomeadas com auto-resolve (para feedback)
    l2_vlan_cache: dict = {}  # domain_id → {vid: {id, name, number}} — populado no bloco VLAN

    async with log_exec(db, client_id=client_id, operation="sync_phpipam") as ctx:
        async with httpx.AsyncClient(timeout=25) as http_client:
            http_client = RetryingAsyncClient(http_client)
            vlan_pairs = (await db.execute(select(models.Vlan, models.Asset).join(models.Asset).where(models.Vlan.client_id == client.id))).all()
            if vlan_pairs:
                vlan_pairs.sort(key=lambda x: (get_category_weight(x[1].category) + x[1].authority_level, x[1].is_edge_router), reverse=True)

                # Cache de VLANs existentes por L2 Domain para evitar requests repetidos
                l2_vlan_cache = {}  # domain_id -> {vid: {id, name, number}}

                for vlan, asset in vlan_pairs:
                    domain_id = asset.override_l2_domain_id if asset.override_l2_domain_id else client.l2_domain_id

                    # Popula cache se necessário
                    if domain_id not in l2_vlan_cache:
                        l2_vlan_cache[domain_id] = {}
                        try:
                            # Bug fix: usar base_headers (sem Content-Type) nos GETs
                            res_check = await http_client.get(
                                f"{base_ip}/api/{client.token_name}/l2domains/{domain_id}/vlans/",
                                headers=base_headers
                            )
                            if res_check.status_code == 200:
                                for v in res_check.json().get("data", []):
                                    vid = int(v.get("number", 0))
                                    # Bug fix: phpIPAM retorna o ID da VLAN em "vlanId" neste endpoint
                                    l2_vlan_cache[domain_id][vid] = {
                                        "id": v.get("vlanId") or v.get("id"),
                                        "name": v.get("name", ""),
                                        "number": vid
                                    }
                        except Exception as e:
                            logger.warning(f"[phpIPAM] Falha ao buscar VLANs do L2 domain {domain_id}: {e}")

                    existing = l2_vlan_cache[domain_id].get(vlan.vid)

                    if existing:
                        # VLAN VID já existe neste L2 Domain
                        existing_name = (existing.get("name") or "").strip()
                        new_name = (vlan.name or "").strip()

                        if existing_name.lower() == new_name.lower():
                            # Mesmo nome → sem conflito, skip
                            continue

                        # Nome diferente → CONFLITO
                        if asset.ignore_vlan_conflict:
                            # Auto-resolve: atualizar nome da VLAN existente no phpIPAM
                            vlan_ipam_id = existing.get("id")
                            if vlan_ipam_id:
                                try:
                                    # Bug fix: usar json_headers (com Content-Type) nos PATCHes
                                    res_patch = await http_client.patch(
                                        f"{base_ip}/api/{client.token_name}/vlan/{vlan_ipam_id}/",
                                        headers=json_headers,
                                        json={"name": new_name, "description": vlan.description}
                                    )
                                    if res_patch.status_code in (200, 201):
                                        updated_vlans += 1
                                        # Atualiza cache
                                        l2_vlan_cache[domain_id][vlan.vid]["name"] = new_name
                                        # Registra renomeação para feedback no frontend
                                        renamed_vlans.append({
                                            "vid": vlan.vid,
                                            "old_name": existing_name,
                                            "new_name": new_name,
                                            "asset_hostname": asset.hostname,
                                            "domain_id": domain_id,
                                        })
                                        logger.info(
                                            f"[phpIPAM] VLAN {vlan.vid} atualizada no L2#{domain_id}: "
                                            f"'{existing_name}' → '{new_name}' (ativo: {asset.hostname}, auto-resolve)"
                                        )
                                    elif res_patch.status_code in (401, 403):
                                        logger.warning(
                                            f"[phpIPAM] Sem permissão para atualizar VLAN {vlan.vid}. "
                                            f"Verifique as autorizações do token da API."
                                        )
                                        conflicts.append({
                                            "type": "permission_error",
                                            "vid": vlan.vid,
                                            "existing_name": existing_name,
                                            "new_name": new_name,
                                            "asset_id": asset.id,
                                            "asset_hostname": asset.hostname,
                                            "domain_id": domain_id,
                                            "vlan_ipam_id": vlan_ipam_id,
                                            "message": f"Token sem permissão de escrita para VLANs. Verifique as autorizações do App ID '{client.token_name}' no phpIPAM."
                                        })
                                    else:
                                        logger.warning(
                                            f"[phpIPAM] Falha ao atualizar VLAN {vlan.vid} "
                                            f"(status {res_patch.status_code}): {res_patch.text}"
                                        )
                                except Exception as e:
                                    logger.warning(f"[phpIPAM] Erro ao atualizar VLAN {vlan.vid}: {e}")
                        else:
                            # Precisa aprovação do usuário
                            conflicts.append({
                                "type": "name_conflict",
                                "vid": vlan.vid,
                                "existing_name": existing_name,
                                "new_name": new_name,
                                "asset_id": asset.id,
                                "asset_hostname": asset.hostname,
                                "domain_id": domain_id,
                                "vlan_ipam_id": existing.get("id"),
                                "local_vlan_id": vlan.id,
                                "message": (
                                    f"VLAN {vlan.vid} já existe no L2 Domain #{domain_id} com nome "
                                    f"'{existing_name}', mas o ativo '{asset.hostname}' a envia como '{new_name}'."
                                )
                            })
                            logger.warning(
                                f"[phpIPAM] CONFLITO: VLAN {vlan.vid} no L2#{domain_id} — "
                                f"'{existing_name}' vs '{new_name}' (ativo: {asset.hostname})"
                            )
                    else:
                        # VLAN nova — criar normalmente
                        try:
                            # Bug fix: usar json_headers (com Content-Type) no POST
                            res_post = await http_client.post(
                                f"{base_ip}/api/{client.token_name}/vlan/",
                                headers=json_headers,
                                json={"number": vlan.vid, "name": vlan.name,
                                      "description": vlan.description, "domainId": domain_id}
                            )
                            if res_post.status_code in (200, 201):
                                synced_vlans += 1
                                # Bug fix: phpIPAM retorna o novo ID em "data" (inteiro)
                                _rj = res_post.json()
                                resp_data = _rj.get("data")
                                new_id = resp_data if isinstance(resp_data, (int, str)) else (_rj.get("id") or None)
                                l2_vlan_cache[domain_id][vlan.vid] = {
                                    "id": new_id, "name": vlan.name, "number": vlan.vid
                                }
                        except Exception as e:
                            logger.warning(f"[phpIPAM] Falha ao sincronizar VLAN {vlan.vid}: {e}")

            # ── SUBNETS ──
            sub_pairs = (await db.execute(
                select(models.Subnet, models.Asset)
                .join(models.Asset)
                .where(models.Subnet.client_id == client.id)
            )).all()
            if sub_pairs:
                sub_pairs.sort(key=lambda x: (get_category_weight(x[1].category) + x[1].authority_level, x[1].is_edge_router), reverse=True)

                # Mapa local vlan.id → vid para resolver vlanId no phpIPAM
                vlan_rows = (await db.execute(
                    select(models.Vlan.id, models.Vlan.vid)
                    .where(models.Vlan.client_id == client.id)
                )).all()
                local_vlan_to_vid = {row.id: row.vid for row in vlan_rows}

                for sub, asset in sub_pairs:
                    domain_id = asset.override_l2_domain_id if asset.override_l2_domain_id else client.l2_domain_id

                    # Resolve vlanId no phpIPAM quando subnet está vinculada a VLAN local
                    phpipam_vlan_id = None
                    if sub.vlan_id:
                        vid = local_vlan_to_vid.get(sub.vlan_id)
                        if vid is not None:
                            phpipam_vlan_id = l2_vlan_cache.get(domain_id, {}).get(vid, {}).get("id")

                    cidr = f"{sub.network}/{sub.mask}"
                    ipam_subnet_found = False
                    try:
                        # Busca pontual por CIDR — evita trazer todas as subnets globalmente
                        res_cidr = await http_client.get(
                            f"{base_ip}/api/{client.token_name}/subnets/cidr/{sub.network}/{sub.mask}/",
                            headers=base_headers,
                            timeout=10,
                        )
                        if res_cidr.status_code == 200:
                            resp = res_cidr.json()
                            data = resp.get("data") if resp.get("success") else None
                            if data and isinstance(data, list):
                                target_section = str(client.section_id or 1)
                                match = next(
                                    (s for s in data if str(s.get("sectionId")) == target_section),
                                    data[0],
                                )
                                ipam_subnet_id = match.get("id")
                                ipam_subnet_found = True
                                # Atualiza description e vlanId se mudaram
                                ipam_desc = (match.get("description") or "").strip()
                                local_desc = (sub.description or "").strip()
                                if ipam_desc != local_desc or (phpipam_vlan_id and str(match.get("vlanId", "0")) == "0"):
                                    patch_payload: dict = {"description": local_desc}
                                    if phpipam_vlan_id:
                                        patch_payload["vlanId"] = phpipam_vlan_id
                                    try:
                                        await http_client.patch(
                                            f"{base_ip}/api/{client.token_name}/subnets/{ipam_subnet_id}/",
                                            headers=json_headers,
                                            json=patch_payload,
                                        )
                                        updated_subnets += 1
                                    except Exception as e:
                                        logger.warning(f"[phpIPAM] Falha ao atualizar subnet {cidr}: {e}")
                    except Exception as e:
                        logger.warning(f"[phpIPAM] Falha ao verificar subnet {cidr}: {e}")

                    if ipam_subnet_found:
                        synced_ips += await _sync_phpipam_address(
                            http_client, base_ip, client.token_name, json_headers,
                            ipam_subnet_id, sub.host_ip, asset.hostname)
                        continue

                    # Subnet não existe no phpIPAM → criar
                    try:
                        payload: dict = {
                            "subnet": sub.network,
                            "mask": sub.mask,
                            "description": sub.description or "",
                            "sectionId": client.section_id or 1,
                        }
                        if phpipam_vlan_id:
                            payload["vlanId"] = phpipam_vlan_id
                        res_post_sub = await http_client.post(
                            f"{base_ip}/api/{client.token_name}/subnets/",
                            headers=json_headers,
                            json=payload,
                        )
                        if res_post_sub.status_code in (200, 201):
                            synced_subnets += 1
                            new_sub_id = None
                            try:
                                _rj = res_post_sub.json()
                                new_sub_id = _rj.get("id") or _rj.get("data")
                                if isinstance(new_sub_id, dict):
                                    new_sub_id = new_sub_id.get("id")
                            except Exception:
                                new_sub_id = None
                            synced_ips += await _sync_phpipam_address(
                                http_client, base_ip, client.token_name, json_headers,
                                new_sub_id, sub.host_ip, asset.hostname)
                    except Exception as e:
                        logger.warning(f"[phpIPAM] Falha ao criar subnet {cidr}: {e}")

            # ── DELETE VLANs removidas do backup ──
            if l2_vlan_cache and vlan_pairs:
                local_vids = {v.vid for v, _ in vlan_pairs}
                for dom_key, remote_cache in l2_vlan_cache.items():
                    for vid_key, info in list(remote_cache.items()):
                        if vid_key not in local_vids:
                            try:
                                res_del = await http_client.delete(
                                    f"{base_ip}/api/{client.token_name}/vlan/{info['id']}/",
                                    headers=base_headers
                                )
                                if res_del.status_code in (200, 204):
                                    deleted_vlans += 1
                                    logger.info(f"[phpIPAM] VLAN {vid_key} removida do domain {dom_key}")
                            except Exception as e:
                                logger.warning(f"[phpIPAM] Falha ao remover VLAN {vid_key}: {e}")

        # ── Resultado ──
        parts = [f"{synced_vlans} VLANs criadas"]
        if updated_vlans:
            parts.append(f"{updated_vlans} VLANs atualizadas (nome)")
        if deleted_vlans:
            parts.append(f"{deleted_vlans} VLANs removidas")
        parts.append(f"{synced_subnets} Subnets criadas")
        if updated_subnets:
            parts.append(f"{updated_subnets} Subnets atualizadas")
        if synced_ips:
            parts.append(f"{synced_ips} IPs criados")
        if renamed_vlans:
            parts.append(f"{len(renamed_vlans)} VLANs renomeadas")
        if conflicts:
            parts.append(f"{len(conflicts)} conflito(s) pendente(s)")
        msg = "Sincronizado! " + ", ".join(parts) + "."
        ctx["message"] = msg

        result = {"message": msg}
        if conflicts:
            result["conflicts"] = conflicts
            result["has_conflicts"] = True
        if renamed_vlans:
            result["renamed_vlans"] = renamed_vlans
        return result


async def resolve_vlan_conflicts(client_id: int, resolutions: list, db: AsyncSession):
    """
    Resolve conflitos de VLAN pendentes.
    
    Cada item em resolutions:
    {
        "vid": int,
        "asset_id": int,
        "domain_id": int,
        "vlan_ipam_id": str/int,
        "action": "update_name" | "create_l2" | "create_group",
        "new_l2_name": str (opcional, para create_l2),
        "existing_l2_id": int (opcional, para vincular a L2 existente),
        "new_group_name": str (opcional, para create_group)
    }
    """
    client = await db.get(models.Client, client_id)
    if not client or not client.ip or not client.token:
        return {"error": "Sem API IPAM"}

    base_ip = _normalize_phpipam_url(client.ip)
    headers = {"token": decrypt_secret(client.token), "Content-Type": "application/json"}

    resolved = 0
    errors = []

    async with log_exec(db, client_id=client_id, operation="resolve_conflicts") as ctx:
        async with httpx.AsyncClient(timeout=25) as http_client:
            http_client = RetryingAsyncClient(http_client)
            for item in resolutions:
                action = item.get("action")
                vid = item.get("vid")
                asset_id = item.get("asset_id")
                vlan_ipam_id = item.get("vlan_ipam_id")
                local_vlan_id = item.get("local_vlan_id")

                asset = await db.get(models.Asset, asset_id) if asset_id else None

                try:
                    if action == "update_name":
                        # Atualizar nome da VLAN existente no phpIPAM
                        if vlan_ipam_id:
                            # Busca VLAN local para pegar o novo nome
                            local_vlan = await db.get(models.Vlan, local_vlan_id) if local_vlan_id else None
                            new_name = local_vlan.name if local_vlan else item.get("new_name", "")
                            new_desc = local_vlan.description if local_vlan else ""

                            res_patch = await http_client.patch(
                                f"{base_ip}/api/{client.token_name}/vlan/{vlan_ipam_id}/",
                                headers=headers,
                                json={"name": new_name, "description": new_desc}
                            )
                            if res_patch.status_code in (200, 201):
                                resolved += 1
                                if asset:
                                    asset.ignore_vlan_conflict = True
                                logger.info(f"[Resolve] VLAN {vid}: nome atualizado para '{new_name}'")
                            elif res_patch.status_code in (401, 403):
                                errors.append(
                                    f"VLAN {vid}: Sem permissão para atualizar. "
                                    f"Verifique as autorizações do token '{client.token_name}' no phpIPAM."
                                )
                            else:
                                errors.append(f"VLAN {vid}: Falha ao atualizar (HTTP {res_patch.status_code})")

                    elif action == "create_l2":
                        existing_l2_id = item.get("existing_l2_id")

                        if existing_l2_id:
                            # Vincular ativo a L2 Domain existente
                            target_l2_id = int(existing_l2_id)
                        else:
                            # Criar novo L2 Domain no phpIPAM
                            l2_name = item.get("new_l2_name") or f"{client.name} - {asset.hostname if asset else 'Auto'}"
                            res_l2 = await http_client.post(
                                f"{base_ip}/api/{client.token_name}/l2domains/",
                                headers=headers,
                                json={"name": l2_name, "description": f"Criado automaticamente pelo Horus para resolver conflito de VLAN {vid}"}
                            )
                            if res_l2.status_code in (200, 201):
                                resp_json = res_l2.json()
                                target_l2_id = resp_json.get("id") or resp_json.get("data")
                                if isinstance(target_l2_id, dict):
                                    target_l2_id = target_l2_id.get("id")
                                target_l2_id = int(target_l2_id) if target_l2_id else None
                                logger.info(f"[Resolve] Novo L2 Domain criado: '{l2_name}' (ID: {target_l2_id})")
                            elif res_l2.status_code in (401, 403):
                                errors.append(
                                    f"VLAN {vid}: Sem permissão para criar L2 Domain. "
                                    f"Verifique as autorizações do token '{client.token_name}' no phpIPAM."
                                )
                                continue
                            else:
                                errors.append(f"VLAN {vid}: Falha ao criar L2 Domain (HTTP {res_l2.status_code})")
                                continue

                        # Associar override do ativo ao novo/existente L2 Domain
                        if asset and target_l2_id:
                            asset.override_l2_domain_id = target_l2_id
                            resolved += 1
                            logger.info(
                                f"[Resolve] Ativo '{asset.hostname}' associado ao L2 Domain #{target_l2_id} "
                                f"para resolver conflito da VLAN {vid}"
                            )

                            # Re-sincronizar as VLANs deste ativo no novo L2 Domain
                            asset_vlans = (await db.execute(
                                select(models.Vlan).where(models.Vlan.asset_id == asset.id)
                            )).scalars().all()
                            for av in asset_vlans:
                                try:
                                    await http_client.post(
                                        f"{base_ip}/api/{client.token_name}/vlan/",
                                        headers=headers,
                                        json={"number": av.vid, "name": av.name,
                                              "description": av.description, "domainId": target_l2_id}
                                    )
                                except Exception as e:
                                    logger.warning(
                                        f"[resolve_conflicts] Falha ao recriar VLAN {av.vid} "
                                        f"no L2 Domain {target_l2_id} para asset {asset.id}: {e}"
                                    )

                    elif action == "create_group":
                        # Criar novo grupo Horus + L2 Domain
                        new_group_name = item.get("new_group_name", f"{client.name} - Separado")
                        l2_name = item.get("new_l2_name") or new_group_name

                        # Criar L2 Domain no phpIPAM
                        res_l2 = await http_client.post(
                            f"{base_ip}/api/{client.token_name}/l2domains/",
                            headers=headers,
                            json={"name": l2_name, "description": f"Grupo Horus: {new_group_name}"}
                        )
                        if res_l2.status_code not in (200, 201):
                            if res_l2.status_code in (401, 403):
                                errors.append(
                                    f"VLAN {vid}: Sem permissão para criar L2 Domain. "
                                    f"Verifique as autorizações do token no phpIPAM."
                                )
                            else:
                                errors.append(f"VLAN {vid}: Falha ao criar L2 Domain (HTTP {res_l2.status_code})")
                            continue

                        resp_json = res_l2.json()
                        target_l2_id = resp_json.get("id") or resp_json.get("data")
                        if isinstance(target_l2_id, dict):
                            target_l2_id = target_l2_id.get("id")
                        target_l2_id = int(target_l2_id) if target_l2_id else None

                        # Criar novo grupo Horus
                        new_client = models.Client(
                            name=new_group_name,
                            system=client.system,
                            ip=client.ip,
                            token_name=client.token_name,
                            token=decrypt_secret(client.token),
                            l2_domain_id=target_l2_id or 1,
                            section_id=client.section_id,
                            vlan_prefix=client.vlan_prefix,
                        )
                        db.add(new_client)
                        await db.flush()

                        # Mover ativo para o novo grupo
                        if asset:
                            asset.client_id = new_client.id
                            asset.override_l2_domain_id = None  # Usa o L2 do novo grupo

                            # Mover VLANs e Subnets do ativo para o novo grupo
                            await db.execute(
                                models.Vlan.__table__.update()
                                .where(models.Vlan.asset_id == asset.id)
                                .values(client_id=new_client.id)
                            )
                            await db.execute(
                                models.Subnet.__table__.update()
                                .where(models.Subnet.asset_id == asset.id)
                                .values(client_id=new_client.id)
                            )

                        resolved += 1
                        logger.info(
                            f"[Resolve] Novo grupo Horus '{new_group_name}' criado com L2 Domain #{target_l2_id}. "
                            f"Ativo '{asset.hostname if asset else '?'}' movido."
                        )

                except Exception as e:
                    errors.append(f"VLAN {vid}: Erro inesperado — {e}")
                    logger.warning(f"[Resolve] Erro ao resolver conflito VLAN {vid}: {e}")

        await db.commit()

        parts = [f"{resolved} conflito(s) resolvido(s)"]
        if errors:
            parts.append(f"{len(errors)} erro(s)")
        msg = "Resolução: " + ", ".join(parts) + "."
        if errors:
            msg += " Erros: " + "; ".join(errors[:5])
        ctx["message"] = msg
        return {"message": msg, "resolved": resolved, "errors": errors}


async def create_l2_domain_phpipam(client_id: int, l2_name: str, db: AsyncSession):
    """Cria um novo L2 Domain no phpIPAM e retorna o ID."""
    client = await db.get(models.Client, client_id)
    if not client or not client.ip or not client.token:
        return {"error": "Sem API IPAM"}

    base_ip = _normalize_phpipam_url(client.ip)
    headers = {"token": decrypt_secret(client.token), "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=15) as http_client:
        http_client = RetryingAsyncClient(http_client)
        res = await http_client.post(
            f"{base_ip}/api/{client.token_name}/l2domains/",
            headers=headers,
            json={"name": l2_name, "description": f"Criado pelo Horus"}
        )
        if res.status_code in (401, 403):
            return {
                "error": f"Sem permissão para criar L2 Domain. "
                         f"Verifique as autorizações do token '{client.token_name}' no phpIPAM."
            }
        if res.status_code not in (200, 201):
            return {"error": f"Falha ao criar L2 Domain (HTTP {res.status_code}): {res.text}"}

        resp_json = res.json()
        new_id = resp_json.get("id") or resp_json.get("data")
        if isinstance(new_id, dict):
            new_id = new_id.get("id")
        return {"id": int(new_id) if new_id else None, "name": l2_name, "message": f"L2 Domain '{l2_name}' criado com sucesso."}


# ==========================================
# NETBOX INTEGRATION
# ==========================================

def _nb_slug(s: str) -> str:
    """Slug compatível com NetBox: lowercase, alfanumérico + hífens, max 50 chars."""
    s = re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
    return s[:50] or "unknown"


def _nb_clean_payload(payload: dict) -> dict:
    """Remove campos nulos antes de enviar payloads ao NetBox."""
    return {key: value for key, value in payload.items() if value is not None}


def _normalize_netbox_url(url: str) -> str:
    base_url = url.rstrip("/")
    # Default seguro: sem scheme assume https:// (evita vazar token em http claro).
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
    validate_external_url(base_url)
    return base_url


async def _nb_get_or_create(http_client, headers, base_url: str, endpoint: str, search: dict, payload: dict) -> Optional[int]:
    """Busca por `search` params; cria com `payload` se não encontrado. Retorna ID ou None."""
    try:
        res = await http_client.get(f"{base_url}{endpoint}", headers=headers, params=search)
        if res.status_code == 200:
            results = res.json().get("results", [])
            if results:
                return results[0]["id"]
        res_post = await http_client.post(f"{base_url}{endpoint}", headers=headers, json=_nb_clean_payload(payload))
        if res_post.status_code in (200, 201):
            return res_post.json()["id"]
        logger.warning(f"[NetBox] POST {endpoint} → {res_post.status_code}: {res_post.text[:200]}")
    except Exception as e:
        logger.warning(f"[NetBox] get_or_create {endpoint}: {e}")
    return None


# Tipo local (asset_interfaces.type) -> slug de tipo aceito pelo NetBox.
# 'other'/'virtual' são os fallbacks universais (sempre válidos, qualquer versão);
# os demais são os mais comuns numa instalação real. Não tentamos adivinhar a
# velocidade real da porta (não temos esse dado) — "1000base-t" é só um valor
# concreto aceito pelo NetBox para "física genérica", não uma alegação de fato.
IFACE_TYPE_MAP = {
    "physical": "1000base-t",
    "lag": "lag",
    "bridge": "bridge",
    "loopback": "virtual",
    "tunnel": "virtual",
    "vlan": "virtual",
    "unknown": "other",
}


async def _nb_sync_interface(http_client, headers, base_url: str, dev_id: int, payload: dict) -> Optional[int]:
    """Cria OU ATUALIZA uma interface no NetBox — ao contrário de `_nb_get_or_create`,
    que só cria na ausência. O mapeamento VLAN↔porta muda com a rede (VLAN entra/sai
    do trunk); se a sincronização só criasse na primeira vez, o NetBox ficaria
    desatualizado silenciosamente a partir da segunda extração.

    `payload` já deve trazer `mode`/`untagged_vlan`/`tagged_vlans` explícitos
    (None/[] quando não há associação) — são enviados como estão, sem passar por
    `_nb_clean_payload`, porque aqui `null` tem significado (limpa a associação
    anterior), diferente de "campo ausente"."""
    name = payload.get("name")
    try:
        res = await http_client.get(
            f"{base_url}/api/dcim/interfaces/", headers=headers,
            params={"device_id": dev_id, "name": name},
        )
        if res.status_code == 200:
            results = res.json().get("results", [])
            if results:
                existing = results[0]
                iface_id = existing["id"]
                precisa_patch = False
                for campo in ("type", "description", "mode", "enabled"):
                    novo = payload.get(campo)
                    atual = existing.get(campo)
                    if isinstance(atual, dict):  # campos de choice vêm como {"value": "..."}
                        atual = atual.get("value")
                    if novo != atual:
                        precisa_patch = True
                        break
                if not precisa_patch:
                    atual_tagged = sorted(v["id"] for v in (existing.get("tagged_vlans") or []))
                    novo_tagged = sorted(payload.get("tagged_vlans") or [])
                    if atual_tagged != novo_tagged:
                        precisa_patch = True
                if not precisa_patch:
                    atual_untagged = existing.get("untagged_vlan")
                    atual_untagged_id = atual_untagged.get("id") if isinstance(atual_untagged, dict) else None
                    if atual_untagged_id != payload.get("untagged_vlan"):
                        precisa_patch = True
                if precisa_patch:
                    res_patch = await http_client.patch(
                        f"{base_url}/api/dcim/interfaces/{iface_id}/", headers=headers, json=payload,
                    )
                    if res_patch.status_code not in (200, 201):
                        logger.warning(f"[NetBox] PATCH interface '{name}' (device {dev_id}) → "
                                       f"{res_patch.status_code}: {res_patch.text[:200]}")
                return iface_id
        res_post = await http_client.post(
            f"{base_url}/api/dcim/interfaces/", headers=headers, json=payload,
        )
        if res_post.status_code in (200, 201):
            return res_post.json()["id"]
        logger.warning(f"[NetBox] POST interface '{name}' (device {dev_id}) → "
                       f"{res_post.status_code}: {res_post.text[:200]}")
    except Exception as e:
        logger.warning(f"[NetBox] sync_interface '{name}' (device {dev_id}): {e}")
    return None


async def sync_data_to_netbox(client_id: int, db: AsyncSession):
    client = await db.get(models.Client, client_id)
    if not client or not client.netbox_url or not client.netbox_token:
        return {"error": "Credenciais NetBox não configuradas (URL e Token obrigatórios)"}

    try:
        base_url = _normalize_netbox_url(client.netbox_url)
    except ValueError as e:
        return {"error": f"URL NetBox bloqueada por política de segurança: {e}"}

    token = decrypt_secret(client.netbox_token) or ""
    auth_scheme = "Bearer" if token.startswith("nbt_") else "Token"
    headers = {
        "Authorization": f"{auth_scheme} {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    synced_vlans = 0
    synced_subnets = 0
    updated_vlans = 0
    updated_subnets = 0
    deleted_vlans = 0
    synced_devices = 0
    synced_ips = 0
    conflicts = []
    vlan_group_cache: dict = {}  # group_id → {vid: {id, name, vid}}

    async with log_exec(db, client_id=client_id, operation="sync_netbox") as ctx:
        async with httpx.AsyncClient(timeout=25) as http_client:
            http_client = RetryingAsyncClient(http_client)

            # ── VLANs ──
            vlan_pairs = (await db.execute(
                select(models.Vlan, models.Asset).join(models.Asset)
                .where(models.Vlan.client_id == client.id)
            )).all()

            if vlan_pairs:
                vlan_pairs.sort(
                    key=lambda x: (get_category_weight(x[1].category) + x[1].authority_level, x[1].is_edge_router),
                    reverse=True,
                )

                for vlan, asset in vlan_pairs:
                    group_id = asset.override_l2_domain_id if asset.override_l2_domain_id else (client.netbox_vlan_group_id or client.l2_domain_id)

                    if group_id not in vlan_group_cache:
                        vlan_group_cache[group_id] = {}
                        try:
                            res = await http_client.get(
                                f"{base_url}/api/ipam/vlans/",
                                headers=headers,
                                params={"group_id": group_id, "limit": 1000},
                            )
                            if res.status_code == 200:
                                for v in res.json().get("results", []):
                                    vid = int(v.get("vid", 0))
                                    vlan_group_cache[group_id][vid] = {
                                        "id": v["id"],
                                        "name": v.get("name", ""),
                                        "vid": vid,
                                    }
                        except Exception as e:
                            logger.warning(f"[NetBox] Falha ao buscar VLANs do grupo {group_id}: {e}")

                    existing = vlan_group_cache[group_id].get(vlan.vid)

                    if existing:
                        existing_name = (existing.get("name") or "").strip()
                        new_name = (vlan.name or "").strip()

                        if existing_name.lower() == new_name.lower():
                            continue

                        if asset.ignore_vlan_conflict:
                            try:
                                res_patch = await http_client.patch(
                                    f"{base_url}/api/ipam/vlans/{existing['id']}/",
                                    headers=headers,
                                    json={"name": new_name, "description": vlan.description or ""},
                                )
                                if res_patch.status_code in (200, 201):
                                    updated_vlans += 1
                                    vlan_group_cache[group_id][vlan.vid]["name"] = new_name
                                    logger.info(f"[NetBox] VLAN {vlan.vid} atualizada: '{existing_name}' → '{new_name}'")
                                elif res_patch.status_code in (401, 403):
                                    conflicts.append({
                                        "type": "permission_error",
                                        "vid": vlan.vid,
                                        "existing_name": existing_name,
                                        "new_name": new_name,
                                        "asset_id": asset.id,
                                        "asset_hostname": asset.hostname,
                                        "domain_id": group_id,
                                        "vlan_ipam_id": existing["id"],
                                        "message": "Token sem permissão de escrita para VLANs no NetBox.",
                                    })
                            except Exception as e:
                                logger.warning(f"[NetBox] Erro ao atualizar VLAN {vlan.vid}: {e}")
                        else:
                            conflicts.append({
                                "type": "name_conflict",
                                "vid": vlan.vid,
                                "existing_name": existing_name,
                                "new_name": new_name,
                                "asset_id": asset.id,
                                "asset_hostname": asset.hostname,
                                "domain_id": group_id,
                                "vlan_ipam_id": existing["id"],
                                "local_vlan_id": vlan.id,
                                "message": (
                                    f"VLAN {vlan.vid} já existe no grupo #{group_id} com nome "
                                    f"'{existing_name}', mas o ativo '{asset.hostname}' a envia como '{new_name}'."
                                ),
                            })
                    else:
                        try:
                            payload: dict = {
                                "vid": vlan.vid,
                                "name": vlan.name or f"VLAN{vlan.vid}",
                                "description": vlan.description or "",
                            }
                            if group_id:
                                payload["group"] = group_id
                            res_post = await http_client.post(
                                f"{base_url}/api/ipam/vlans/",
                                headers=headers,
                                json=_nb_clean_payload(payload),
                            )
                            if res_post.status_code in (200, 201):
                                synced_vlans += 1
                                new_id = res_post.json().get("id")
                                vlan_group_cache[group_id][vlan.vid] = {
                                    "id": new_id, "name": vlan.name, "vid": vlan.vid,
                                }
                            elif res_post.status_code in (400, 409):
                                detail = res_post.text[:500]
                                conflicts.append({
                                    "type": "invalid_payload" if res_post.status_code == 400 else "vlan_conflict",
                                    "vid": vlan.vid,
                                    "new_name": vlan.name or f"VLAN{vlan.vid}",
                                    "asset_id": asset.id,
                                    "asset_hostname": asset.hostname,
                                    "domain_id": group_id,
                                    "message": f"NetBox recusou a VLAN {vlan.vid} (HTTP {res_post.status_code}): {detail}",
                                })
                        except Exception as e:
                            logger.warning(f"[NetBox] Falha ao criar VLAN {vlan.vid}: {e}")

            # ── PREFIXES (Subnets) ──
            sub_pairs = (await db.execute(
                select(models.Subnet, models.Asset)
                .join(models.Asset)
                .where(models.Subnet.client_id == client.id)
            )).all()

            if sub_pairs:
                sub_pairs.sort(
                    key=lambda x: (get_category_weight(x[1].category) + x[1].authority_level, x[1].is_edge_router),
                    reverse=True,
                )

                vlan_rows = (await db.execute(
                    select(models.Vlan.id, models.Vlan.vid).where(models.Vlan.client_id == client.id)
                )).all()
                local_vlan_to_vid = {row.id: row.vid for row in vlan_rows}

                for sub, asset in sub_pairs:
                    group_id = asset.override_l2_domain_id if asset.override_l2_domain_id else (client.netbox_vlan_group_id or client.l2_domain_id)

                    netbox_vlan_id = None
                    if sub.vlan_id:
                        vid = local_vlan_to_vid.get(sub.vlan_id)
                        if vid is not None:
                            netbox_vlan_id = vlan_group_cache.get(group_id, {}).get(vid, {}).get("id")

                    cidr = f"{sub.network}/{sub.mask}"
                    prefix_found = False

                    try:
                        res_search = await http_client.get(
                            f"{base_url}/api/ipam/prefixes/",
                            headers=headers,
                            params={"prefix": cidr, "limit": 10},
                        )
                        if res_search.status_code == 200:
                            results = res_search.json().get("results", [])
                            if results:
                                target_site = client.netbox_site_id or client.section_id
                                match = next(
                                    (p for p in results if target_site and p.get("site") and str(p["site"].get("id")) == str(target_site)),
                                    results[0],
                                )
                                prefix_id = match["id"]
                                prefix_found = True
                                ipam_desc = (match.get("description") or "").strip()
                                local_desc = (sub.description or "").strip()
                                current_vlan_id = (match.get("vlan") or {}).get("id")
                                if ipam_desc != local_desc or (netbox_vlan_id and not current_vlan_id):
                                    patch_payload: dict = {"description": local_desc}
                                    if netbox_vlan_id:
                                        patch_payload["vlan"] = netbox_vlan_id
                                    try:
                                        await http_client.patch(
                                            f"{base_url}/api/ipam/prefixes/{prefix_id}/",
                                            headers=headers,
                                            json=patch_payload,
                                        )
                                        updated_subnets += 1
                                    except Exception as e:
                                        logger.warning(f"[NetBox] Falha ao atualizar prefix {cidr}: {e}")
                    except Exception as e:
                        logger.warning(f"[NetBox] Falha ao verificar prefix {cidr}: {e}")

                    if prefix_found:
                        continue

                    try:
                        payload2: dict = {
                            "prefix": cidr,
                            "description": sub.description or "",
                        }
                        site_id = client.netbox_site_id or client.section_id
                        if site_id:
                            payload2["site"] = site_id
                        if netbox_vlan_id:
                            payload2["vlan"] = netbox_vlan_id
                        res_post_sub = await http_client.post(
                            f"{base_url}/api/ipam/prefixes/",
                            headers=headers,
                            json=_nb_clean_payload(payload2),
                        )
                        if res_post_sub.status_code in (200, 201):
                            synced_subnets += 1
                        elif res_post_sub.status_code in (400, 409):
                            detail = res_post_sub.text[:500]
                            conflict_type = "prefix_overlap" if "overlap" in detail.lower() else "invalid_payload"
                            conflicts.append({
                                "type": conflict_type,
                                "prefix": cidr,
                                "asset_id": asset.id,
                                "asset_hostname": asset.hostname,
                                "domain_id": group_id,
                                "message": f"NetBox recusou o prefixo {cidr} (HTTP {res_post_sub.status_code}): {detail}",
                            })
                    except Exception as e:
                        logger.warning(f"[NetBox] Falha ao criar prefix {cidr}: {e}")

            # ── DELETE VLANs removidas do backup ──
            if vlan_group_cache and vlan_pairs:
                local_vids = {v.vid for v, _ in vlan_pairs}
                for grp_key, remote_cache in vlan_group_cache.items():
                    for vid_key, info in list(remote_cache.items()):
                        if vid_key not in local_vids:
                            try:
                                res_del = await http_client.delete(
                                    f"{base_url}/api/ipam/vlans/{info['id']}/",
                                    headers=headers
                                )
                                if res_del.status_code in (200, 204):
                                    deleted_vlans += 1
                                    logger.info(f"[NetBox] VLAN {vid_key} removida do grupo {grp_key}")
                            except Exception as e:
                                logger.warning(f"[NetBox] Falha ao remover VLAN {vid_key}: {e}")

            # ── DEVICES, INTERFACES, VLAN↔PORTA E IPs ──
            approved_assets = (await db.execute(
                select(models.Asset).where(
                    models.Asset.client_id == client.id,
                )
            )).scalars().all()

            # Carregado uma vez para o cliente inteiro (evita N+1 por ativo) e em
            # tabelas simples — nunca em atributo de relacionamento ORM fora do
            # greenlet, que dispararia lazy-load síncrono numa sessão async.
            iface_rows = (await db.execute(
                select(models.AssetInterface)
                .join(models.Asset, models.AssetInterface.asset_id == models.Asset.id)
                .where(models.Asset.client_id == client.id)
            )).scalars().all()
            ifaces_by_asset: dict[int, list] = {}
            for ifc in iface_rows:
                ifaces_by_asset.setdefault(ifc.asset_id, []).append(ifc)

            vi_rows = (await db.execute(
                select(models.VlanInterface.interface_id, models.VlanInterface.mode, models.Vlan.vid)
                .join(models.Vlan, models.VlanInterface.vlan_id == models.Vlan.id)
                .join(models.AssetInterface, models.VlanInterface.interface_id == models.AssetInterface.id)
                .join(models.Asset, models.AssetInterface.asset_id == models.Asset.id)
                .where(models.Asset.client_id == client.id)
            )).all()
            vlans_by_iface: dict[int, list] = {}
            for iface_id, mode, vid in vi_rows:
                vlans_by_iface.setdefault(iface_id, []).append(((mode or "trunk").lower(), vid))

            ip_rows = (await db.execute(
                select(models.Subnet.interface_id, models.Subnet.host_ip, models.Subnet.mask)
                .where(
                    models.Subnet.client_id == client.id,
                    models.Subnet.interface_id.isnot(None),
                    models.Subnet.host_ip.isnot(None),
                )
            )).all()
            ip_by_iface: dict[int, tuple] = {}
            for iface_id, host_ip, mask in ip_rows:
                if iface_id not in ip_by_iface:  # primeira ocorrência basta
                    ip_by_iface[iface_id] = (host_ip, mask)

            synced_devices = 0
            synced_interfaces = 0
            synced_ips = 0
            site_id = client.netbox_site_id
            _role_colors = {"core": "aa1409", "borda": "e65100", "acesso": "1565c0"}

            for asset in approved_assets:
                try:
                    vendor   = (asset.vendor or "Unknown").strip() or "Unknown"
                    model    = (asset.model or f"{vendor} Generic").strip() or f"{vendor} Generic"
                    category = (asset.category or "acesso").strip().lower()
                    hostname = asset.hostname.strip()
                    ip_str   = (asset.ip_address or "").strip()

                    # 1. Manufacturer
                    mfr_id = await _nb_get_or_create(
                        http_client, headers, base_url, "/api/dcim/manufacturers/",
                        search={"slug": _nb_slug(vendor)},
                        payload={"name": vendor, "slug": _nb_slug(vendor)},
                    )
                    if not mfr_id:
                        continue

                    # 2. DeviceType
                    dt_id = await _nb_get_or_create(
                        http_client, headers, base_url, "/api/dcim/device-types/",
                        search={"slug": _nb_slug(model)},
                        payload={"manufacturer": mfr_id, "model": model, "slug": _nb_slug(model)},
                    )
                    if not dt_id:
                        continue

                    # 3. DeviceRole
                    role_id = await _nb_get_or_create(
                        http_client, headers, base_url, "/api/dcim/device-roles/",
                        search={"slug": _nb_slug(category)},
                        payload={
                            "name": category.capitalize(),
                            "slug": _nb_slug(category),
                            "color": _role_colors.get(category, "607d8b"),
                        },
                    )
                    if not role_id:
                        continue

                    # 4. Device
                    dev_payload: dict = {
                        "name": hostname,
                        "device_type": dt_id,
                        "role": role_id,
                        "status": "active",
                    }
                    if site_id:
                        dev_payload["site"] = site_id
                    if asset.serial_number:
                        dev_payload["serial"] = asset.serial_number

                    dev_id = await _nb_get_or_create(
                        http_client, headers, base_url, "/api/dcim/devices/",
                        search={"name": hostname},
                        payload=dev_payload,
                    )
                    if dev_id:
                        synced_devices += 1

                    # 5. Interfaces reais + VLAN por porta (access/trunk/native) + IP.
                    # `group_id` é a mesma fórmula usada na sincronização de VLANs
                    # acima — precisa bater para resolver o ID da VLAN no NetBox.
                    mgmt_iface_id_nb = None
                    if dev_id:
                        group_id = asset.override_l2_domain_id if asset.override_l2_domain_id else (client.netbox_vlan_group_id or client.l2_domain_id)
                        vlan_id_lookup = vlan_group_cache.get(group_id, {})

                        for ifc in ifaces_by_asset.get(asset.id, []):
                            rows = vlans_by_iface.get(ifc.id, [])
                            access_vids = [v for m, v in rows if m == "access"]
                            native_vid = next((v for m, v in rows if m == "native"), None)
                            trunk_vids = [v for m, v in rows if m in ("trunk", "tagged")]

                            payload_if: dict = {
                                "device": dev_id,
                                "name": ifc.name,
                                "type": IFACE_TYPE_MAP.get(ifc.type, "other"),
                                "description": ifc.description or "",
                                "enabled": True,
                                "mode": None, "untagged_vlan": None, "tagged_vlans": [],
                            }
                            if access_vids:
                                uvid = vlan_id_lookup.get(access_vids[0], {}).get("id")
                                if len(access_vids) > 1:
                                    logger.debug(f"[NetBox] Interface '{ifc.name}' de '{hostname}' tem "
                                                 f"{len(access_vids)} VLANs em modo access; usando a primeira ({access_vids[0]}).")
                                if uvid:
                                    payload_if["mode"] = "access"
                                    payload_if["untagged_vlan"] = uvid
                            elif trunk_vids or native_vid is not None:
                                tagged_ids = [vlan_id_lookup[v]["id"] for v in trunk_vids if v in vlan_id_lookup]
                                if tagged_ids or native_vid is not None:
                                    payload_if["mode"] = "tagged"
                                payload_if["tagged_vlans"] = tagged_ids
                                if native_vid is not None:
                                    nuvid = vlan_id_lookup.get(native_vid, {}).get("id")
                                    if nuvid:
                                        payload_if["untagged_vlan"] = nuvid

                            nb_iface_id = await _nb_sync_interface(http_client, headers, base_url, dev_id, payload_if)
                            if not nb_iface_id:
                                continue
                            synced_interfaces += 1
                            if ifc.is_management:
                                mgmt_iface_id_nb = nb_iface_id

                            ip_info = ip_by_iface.get(ifc.id)
                            if ip_info:
                                host_ip, mask = ip_info
                                ip_cidr = f"{host_ip}/{mask}" if mask is not None else f"{host_ip}{'/128' if ':' in host_ip else '/32'}"
                                ip_id = await _nb_get_or_create(
                                    http_client, headers, base_url, "/api/ipam/ip-addresses/",
                                    search={"address": ip_cidr},
                                    payload={
                                        "address": ip_cidr,
                                        "status": "active",
                                        "assigned_object_type": "dcim.interface",
                                        "assigned_object_id": nb_iface_id,
                                    },
                                )
                                if ip_id:
                                    synced_ips += 1
                                    if ifc.is_management:
                                        try:
                                            await http_client.patch(
                                                f"{base_url}/api/dcim/devices/{dev_id}/",
                                                headers=headers,
                                                json={"primary_ip4": ip_id},
                                            )
                                        except Exception as e:
                                            logger.warning(
                                                f"[NetBox] Falha ao definir primary_ip4 do device {dev_id} "
                                                f"para IP {ip_id}: {e}"
                                            )

                    # Fallback: nenhuma interface real foi extraída para este ativo
                    # (comum em dados extraídos antes da persistência de interfaces)
                    # ou nenhuma delas é a de gerência. Preserva o
                    # comportamento anterior: cria uma interface sintética "mgmt"
                    # só para o IP não ficar de fora do NetBox.
                    if not mgmt_iface_id_nb and ip_str and dev_id:
                        intf_id = await _nb_get_or_create(
                            http_client, headers, base_url, "/api/dcim/interfaces/",
                            search={"device_id": dev_id, "name": "mgmt"},
                            payload={"device": dev_id, "name": "mgmt", "type": "1000base-t"},
                        )
                        if intf_id:
                            if "/" in ip_str:
                                ip_cidr = ip_str
                            else:
                                mask = "/128" if ":" in ip_str else "/32"
                                ip_cidr = f"{ip_str}{mask}"
                            ip_id = await _nb_get_or_create(
                                http_client, headers, base_url, "/api/ipam/ip-addresses/",
                                search={"address": ip_cidr},
                                payload={
                                    "address": ip_cidr,
                                    "status": "active",
                                    "assigned_object_type": "dcim.interface",
                                    "assigned_object_id": intf_id,
                                },
                            )
                            if ip_id:
                                synced_ips += 1
                                try:
                                    await http_client.patch(
                                        f"{base_url}/api/dcim/devices/{dev_id}/",
                                        headers=headers,
                                        json={"primary_ip4": ip_id},
                                    )
                                except Exception as e:
                                    logger.warning(
                                        f"[NetBox] Falha ao definir primary_ip4 do device {dev_id} "
                                        f"para IP {ip_id}: {e}"
                                    )

                except Exception as e:
                    logger.warning(f"[NetBox] Falha ao sincronizar device '{asset.hostname}': {e}")

        parts = [f"{synced_vlans} VLANs criadas"]
        if updated_vlans:
            parts.append(f"{updated_vlans} VLANs atualizadas")
        if deleted_vlans:
            parts.append(f"{deleted_vlans} VLANs removidas")
        parts.append(f"{synced_subnets} Prefixos criados")
        if updated_subnets:
            parts.append(f"{updated_subnets} Prefixos atualizados")
        parts.append(f"{synced_devices} Device(s) registrado(s)")
        parts.append(f"{synced_interfaces} Interface(s) sincronizada(s)")
        parts.append(f"{synced_ips} IP(s) registrado(s)")
        if conflicts:
            parts.append(f"{len(conflicts)} conflito(s) pendente(s)")
        msg = "Sincronizado! " + ", ".join(parts) + "."
        ctx["message"] = msg
        if conflicts:
            ctx["status"] = "warning"
            ctx["detail"] = str(conflicts)

        result = {
            "message": msg,
            "vlans_created": synced_vlans,
            "vlans_updated": updated_vlans,
            "vlans_deleted": deleted_vlans,
            "prefixes_created": synced_subnets,
            "prefixes_updated": updated_subnets,
            "devices_synced": synced_devices,
            "ips_synced": synced_ips,
            "conflicts": conflicts,
            "has_conflicts": bool(conflicts),
        }
        return result


async def resolve_netbox_conflicts(client_id: int, resolutions: list, db: AsyncSession):
    """Resolve conflitos de VLAN do NetBox usando as mesmas ações do modal phpIPAM."""
    client = await db.get(models.Client, client_id)
    if not client or not client.netbox_url or not client.netbox_token:
        return {"error": "Credenciais NetBox não configuradas"}

    try:
        base_url = _normalize_netbox_url(client.netbox_url)
    except ValueError as e:
        return {"error": f"URL NetBox bloqueada por política de segurança: {e}"}

    token = decrypt_secret(client.netbox_token) or ""
    auth_scheme = "Bearer" if token.startswith("nbt_") else "Token"
    headers = {
        "Authorization": f"{auth_scheme} {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    resolved = 0
    errors = []

    async with log_exec(db, client_id=client_id, operation="resolve_netbox_conflicts") as ctx:
        async with httpx.AsyncClient(timeout=25) as http_client:
            http_client = RetryingAsyncClient(http_client)
            for item in resolutions:
                action = item.get("action")
                vid = item.get("vid")
                asset_id = item.get("asset_id")
                vlan_ipam_id = item.get("vlan_ipam_id")
                local_vlan_id = item.get("local_vlan_id")
                asset = await db.get(models.Asset, asset_id) if asset_id else None

                try:
                    if action == "update_name":
                        if not vlan_ipam_id:
                            errors.append(f"VLAN {vid}: ID remoto NetBox ausente.")
                            continue
                        local_vlan = await db.get(models.Vlan, local_vlan_id) if local_vlan_id else None
                        new_name = item.get("new_name") or (local_vlan.name if local_vlan else "")
                        new_desc = local_vlan.description if local_vlan else ""
                        res_patch = await http_client.patch(
                            f"{base_url}/api/ipam/vlans/{vlan_ipam_id}/",
                            headers=headers,
                            json=_nb_clean_payload({"name": new_name, "description": new_desc}),
                        )
                        if res_patch.status_code in (200, 201):
                            resolved += 1
                            if asset:
                                asset.ignore_vlan_conflict = True
                            logger.info(f"[NetBox Resolve] VLAN {vid}: nome atualizado para '{new_name}'")
                        elif res_patch.status_code in (401, 403):
                            errors.append(f"VLAN {vid}: token sem permissão para atualizar VLAN no NetBox.")
                        else:
                            errors.append(f"VLAN {vid}: falha ao atualizar no NetBox (HTTP {res_patch.status_code})")

                    elif action == "create_l2":
                        existing_l2_id = item.get("existing_l2_id")
                        target_group_id = int(existing_l2_id) if existing_l2_id else None
                        if not target_group_id:
                            group_name = item.get("new_l2_name") or (asset.hostname if asset else f"VLAN {vid}")
                            res_group = await http_client.post(
                                f"{base_url}/api/ipam/vlan-groups/",
                                headers=headers,
                                json=_nb_clean_payload({
                                    "name": group_name,
                                    "slug": _nb_slug(group_name),
                                    "description": f"Criado pelo Horus para resolver conflito de VLAN {vid}",
                                }),
                            )
                            if res_group.status_code not in (200, 201):
                                errors.append(
                                    f"VLAN {vid}: falha ao criar VLAN Group no NetBox "
                                    f"(HTTP {res_group.status_code})"
                                )
                                continue
                            target_group_id = int(res_group.json().get("id"))

                        if asset and target_group_id:
                            asset.override_l2_domain_id = target_group_id
                            resolved += 1
                            logger.info(
                                f"[NetBox Resolve] Ativo '{asset.hostname}' vinculado ao VLAN Group #{target_group_id}"
                            )
                        else:
                            errors.append(f"VLAN {vid}: ativo ou VLAN Group de destino ausente.")

                    else:
                        errors.append(f"VLAN {vid}: ação '{action}' não suportada para NetBox.")
                except Exception as e:
                    errors.append(f"VLAN {vid}: erro inesperado - {e}")
                    logger.warning(f"[NetBox Resolve] Erro ao resolver conflito VLAN {vid}: {e}")

        await db.commit()

        parts = [f"{resolved} conflito(s) resolvido(s)"]
        if errors:
            parts.append(f"{len(errors)} erro(s)")
            ctx["status"] = "warning"
            ctx["detail"] = "; ".join(errors[:10])
        msg = "Resolução NetBox: " + ", ".join(parts) + "."
        ctx["message"] = msg
        return {"message": msg, "resolved": resolved, "errors": errors}


async def create_vlan_group_netbox(client_id: int, group_name: str, db: AsyncSession):
    """Cria um novo VLAN Group no NetBox e retorna o ID."""
    import re as _re
    client = await db.get(models.Client, client_id)
    if not client or not client.netbox_url or not client.netbox_token:
        return {"error": "Credenciais NetBox não configuradas"}

    try:
        base_url = _normalize_netbox_url(client.netbox_url)
    except ValueError as e:
        return {"error": f"URL NetBox bloqueada por política de segurança: {e}"}

    token = decrypt_secret(client.netbox_token) or ""
    auth_scheme = "Bearer" if token.startswith("nbt_") else "Token"
    headers = {
        "Authorization": f"{auth_scheme} {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    slug = _re.sub(r'[^a-z0-9_-]', '-', group_name.lower().strip())[:50].strip('-')

    async with httpx.AsyncClient(timeout=15) as http_client:
        http_client = RetryingAsyncClient(http_client)
        res = await http_client.post(
            f"{base_url}/api/ipam/vlan-groups/",
            headers=headers,
            json=_nb_clean_payload({"name": group_name, "slug": slug, "description": "Criado pelo Horus"}),
        )
        if res.status_code in (401, 403):
            return {"error": "Sem permissão para criar VLAN Group no NetBox."}
        if res.status_code not in (200, 201):
            return {"error": f"Falha ao criar VLAN Group (HTTP {res.status_code}): {res.text}"}

        resp_json = res.json()
        new_id = resp_json.get("id")
        return {"id": int(new_id) if new_id else None, "name": group_name, "message": f"VLAN Group '{group_name}' criado com sucesso."}
