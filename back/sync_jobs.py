"""Orquestracao dos jobs globais de Backup API e do scheduler diario."""

import asyncio
from datetime import datetime, timezone
from typing import Awaitable, Callable

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

import auto_discovery
import models
from bc_client import bc_headers, bc_url
from logger import logger


GLOBAL_JOBS: dict[str, dict] = {}


async def unique_client_name(db: AsyncSession, desired: str, *, exclude_id: int | None = None) -> str:
    base = (desired or "Grupo Backup API").strip() or "Grupo Backup API"
    candidate = base
    suffix = 2
    while True:
        query = select(models.Client).where(models.Client.name == candidate)
        if exclude_id is not None:
            query = query.where(models.Client.id != exclude_id)
        res = await db.execute(query)
        if not res.scalars().first():
            return candidate
        candidate = f"{base} ({suffix})"
        suffix += 1


def _progress(stats: dict) -> dict:
    return {
        "groups_seen": stats["groups_seen"],
        "clients_created": stats["clients_created"],
        "clients_synced": stats["clients_synced"],
        "assets_added": stats["assets_added"],
        "assets_restored": stats["assets_restored"],
        "extracted": stats["extracted"],
        "ipam_synced": stats["ipam_synced"],
        "errors": len(stats["errors"]),
    }


async def sync_bc_groups_and_assets(
    db: AsyncSession,
    *,
    extract_configs: bool = False,
    job: dict | None = None,
    http_client_factory=httpx.AsyncClient,
    unique_name_fn=unique_client_name,
) -> dict:
    """Sincroniza grupos, ativos, configuracoes e, opcionalmente, IPAM."""
    res = await db.execute(select(models.BCServer))
    servers = res.scalars().all()
    if not servers:
        return {
            "status": "warning",
            "message": "Nenhum servidor Backup API cadastrado.",
            "servers": 0,
            "groups_seen": 0,
            "clients_created": 0,
            "clients_synced": 0,
            "assets_added": 0,
            "assets_restored": 0,
            "extracted": 0,
            "ipam_synced": 0,
            "errors": [],
        }

    stats = {
        "status": "success",
        "servers": len(servers),
        "groups_seen": 0,
        "clients_created": 0,
        "clients_synced": 0,
        "assets_added": 0,
        "assets_restored": 0,
        "extracted": 0,
        "ipam_synced": 0,
        "errors": [],
    }

    async with http_client_factory() as client_http:
        for srv in servers:
            srv_id = srv.id
            srv_name = srv.name
            try:
                res_api = await client_http.get(bc_url(srv, "groups"), headers=bc_headers(srv), timeout=20)
                if res_api.status_code != 200:
                    # Antes esta falha so virava um contador no resumo ("N erro(s)"),
                    # sem status nem corpo em lugar nenhum: o sync diario podia ficar
                    # quebrado em silencio por semanas (foi o caso do HTTP 429 do
                    # Backup API). Agora loga o suficiente para diagnosticar na hora
                    # (status + inicio do corpo). O token vai no header, nunca no corpo.
                    body_snippet = (res_api.text or "")[:300].replace("\n", " ")
                    logger.warning(
                        "[Backup API] Falha ao listar grupos no servidor %s (%s): HTTP %s — %s",
                        srv_id, srv_name, res_api.status_code, body_snippet,
                    )
                    stats["errors"].append({
                        "server_id": srv_id,
                        "server_name": srv_name,
                        "message": f"Backup API respondeu HTTP {res_api.status_code} ao listar grupos.",
                        "detail": body_snippet,
                    })
                    continue

                for group in res_api.json().get("groups", []):
                    group_name = group.get("name")
                    ext_id = str(group.get("id"))
                    if not group_name or not ext_id:
                        continue

                    stats["groups_seen"] += 1
                    check = await db.execute(select(models.Client).where(models.Client.external_group_id == ext_id))
                    client = check.scalars().first()
                    if not client:
                        client_name = await unique_name_fn(db, group_name)
                        client = models.Client(
                            name=client_name,
                            bc_server_id=srv_id,
                            external_group_id=ext_id,
                            vlan_prefix=f"[{client_name}]",
                            system="phpIPAM",
                        )
                        db.add(client)
                        await db.commit()
                        await db.refresh(client)
                        stats["clients_created"] += 1
                    else:
                        changed = False
                        if not client.bc_server_id:
                            client.bc_server_id = srv_id
                            changed = True
                        if client.name != group_name:
                            safe_name = await unique_name_fn(db, group_name, exclude_id=client.id)
                            if safe_name == group_name:
                                client.name = group_name
                                changed = True
                        if not client.vlan_prefix:
                            client.vlan_prefix = f"[{client.name}]"
                            changed = True
                        if changed:
                            await db.commit()

                    if job is not None:
                        job.update({
                            "phase": "sync_assets",
                            "message": f"Sincronizando ativos: {client.name} ({stats['groups_seen']} grupos verificados)...",
                            "progress": _progress(stats),
                        })

                    sync_result = await auto_discovery.sync_discovered_assets(client.id, db)
                    if sync_result.get("status") == "error" or sync_result.get("error"):
                        stats["errors"].append({
                            "client_id": client.id,
                            "client_name": client.name,
                            "message": sync_result.get("message") or sync_result.get("error"),
                            "errors": sync_result.get("errors", []),
                        })
                    else:
                        stats["clients_synced"] += 1
                        stats["assets_added"] += sync_result.get("added", 0) or 0
                        stats["assets_restored"] += sync_result.get("restored", 0) or 0

                    if extract_configs:
                        if job is not None:
                            job.update({
                                "phase": "extract_configs",
                                "message": f"Extraindo VLANs/Subnets: {client.name} ({stats['groups_seen']} grupos verificados)...",
                                "progress": _progress(stats),
                            })
                        extract_result = await auto_discovery.extract_client_configs_bc(client.id, db)
                        if extract_result.get("error"):
                            stats["errors"].append({
                                "client_id": client.id,
                                "client_name": client.name,
                                "message": extract_result["error"],
                            })
                        else:
                            stats["extracted"] += 1

                        system = (client.system or "phpIPAM").lower()
                        ipam_ready = (
                            bool(client.netbox_url and client.netbox_token)
                            if system == "netbox"
                            else bool(client.ip and client.token)
                        )
                        if ipam_ready:
                            try:
                                if system == "netbox":
                                    ipam_result = await auto_discovery.sync_data_to_netbox(client.id, db)
                                else:
                                    ipam_result = await auto_discovery.sync_data_to_phpipam(client.id, db)
                                if ipam_result.get("error"):
                                    stats["errors"].append({
                                        "client_id": client.id,
                                        "client_name": client.name,
                                        "message": f"Push IPAM: {ipam_result['error']}",
                                    })
                                else:
                                    stats["ipam_synced"] += 1
                            except Exception as exc:
                                logger.warning("[Discover All] Push IPAM falhou para cliente %s: %s", client.id, exc)
                                stats["errors"].append({
                                    "client_id": client.id,
                                    "client_name": client.name,
                                    "message": f"Push IPAM falhou: {exc}",
                                })
            except Exception as exc:
                await db.rollback()
                logger.warning("[Discover All] Erro ao processar servidor %s: %s", srv_id, exc)
                stats["errors"].append({
                    "server_id": srv_id,
                    "server_name": srv_name,
                    "message": str(exc),
                })

    if stats["errors"]:
        stats["status"] = "partial" if stats["clients_synced"] or stats["clients_created"] else "error"
    stats["message"] = (
        f"Sincronização concluída: {stats['groups_seen']} grupos verificados, "
        f"{stats['clients_created']} novos grupos, {stats['clients_synced']} grupos com ativos sincronizados, "
        f"{stats['assets_added']} ativos novos, {stats['assets_restored']} resgatados"
        + (f", {stats['extracted']} grupos extraídos" if extract_configs else "")
        + (f", {stats['ipam_synced']} push(es) ao IPAM" if extract_configs else "")
        + (f", {len(stats['errors'])} erro(s)." if stats["errors"] else ".")
    )
    if job is not None:
        job["progress"] = _progress(stats)
    return stats


async def run_global_extract_job(
    job_id: str,
    *,
    jobs: dict[str, dict],
    session_factory,
    sync_fn: Callable[..., Awaitable[dict]],
) -> None:
    job = jobs[job_id]
    job.update({
        "status": "running",
        "phase": "sync_groups_assets",
        "message": "Sincronizando grupos e ativos da Backup API...",
        "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    })
    try:
        async with session_factory() as db:
            result = await sync_fn(db, extract_configs=True, job=job)
        job.update({
            "status": "completed" if result.get("status") in ("success", "warning") else result.get("status", "completed"),
            "phase": "completed",
            "message": result.get("message", "Extração global concluída."),
            "result": result,
            "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        })
    except Exception as exc:
        logger.warning("[global_extract] Falha no job %s: %s", job_id, exc)
        job.update({
            "status": "error",
            "phase": "failed",
            "message": f"Falha na extração global: {exc}",
            "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        })


async def run_daily_sync(*, session_factory, sync_fn: Callable[..., Awaitable[dict]]) -> None:
    """Executa o mesmo pipeline completo acionado pelo botao Extrair tudo."""
    logger.info("[scheduler] Iniciando sync diário automático...")
    try:
        async with session_factory() as db:
            result = await sync_fn(db, extract_configs=True)
        logger.info("[scheduler] Sync diário concluído: %s", result.get("message", "sem detalhes"))
    except Exception as exc:
        logger.warning("[scheduler] Sync diário falhou: %s", exc)


async def daily_sync_loop(*, run_sync: Callable[[], Awaitable[None]]) -> None:
    """Aguarda ate as 8h (horario local) e executa o sync diario em loop."""
    import datetime as dt

    while True:
        now = dt.datetime.now()
        target = now.replace(hour=8, minute=0, second=0, microsecond=0)
        if now >= target:
            target += dt.timedelta(days=1)
        wait_secs = (target - now).total_seconds()
        logger.info(
            "[scheduler] Próximo sync diário às %s (em %.1fh)",
            target.strftime("%Y-%m-%d %H:%M"),
            wait_secs / 3600,
        )
        await asyncio.sleep(wait_secs)
        await run_sync()
