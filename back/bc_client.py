"""Helpers para chamadas à Backup API.

Contrato: ``BCServer.url`` deve ser a URL base completa da API externa,
incluindo o prefixo ``/api/v1/external``.
"""

from __future__ import annotations

from typing import Any

import httpx

from crypto import decrypt_secret
from exceptions import BCAPIError
from logger import logger

BC_API_PREFIX = "/api/v1/external"


def bc_url(server: Any, *parts: str) -> str:
    """Monta URLs da Backup API a partir da base persistida em ``BCServer.url``."""
    base = (server.url or "").rstrip("/")
    if not base.endswith(BC_API_PREFIX):
        logger.warning(
            "[Backup API] Configuracao suspeita para servidor %s: "
            "BCServer.url deve terminar com %s. URL atual: %s",
            getattr(server, "id", "?"),
            BC_API_PREFIX,
            mask_url(base),
        )
    path = "/".join(str(part).strip("/") for part in parts if str(part).strip("/"))
    return f"{base}/{path}" if path else base


def mask_url(url: str) -> str:
    """Remove credenciais acidentais embutidas na URL antes de logar."""
    try:
        parsed = httpx.URL(url)
    except Exception:
        return url.replace("@", "***@")
    if parsed.username or parsed.password:
        return str(parsed.copy_with(username="***", password="***"))
    return str(parsed)


def bc_headers(server: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {decrypt_secret(server.token)}", "Accept": "application/json"}


async def get_json(
    http_client: httpx.AsyncClient,
    server: Any,
    *parts: str,
    params: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    url = bc_url(server, *parts)
    try:
        res = await http_client.get(
            url,
            headers=bc_headers(server),
            params=params,
            timeout=timeout,
        )
    except httpx.TimeoutException as exc:
        raise BCAPIError("Timeout ao contatar Backup API", url) from exc
    except httpx.HTTPError as exc:
        raise BCAPIError(f"Falha ao contatar Backup API: {exc}", url) from exc

    if res.status_code != 200:
        raise BCAPIError(
            "Backup API respondeu com erro",
            str(res.url),
            status_code=res.status_code,
            response_text=res.text,
        )
    return res.json()


async def iter_group_backups(
    http_client: httpx.AsyncClient,
    server: Any,
    external_group_id: str,
    *,
    timeout: float | None = None,
    per_page: int = 100,
):
    """Itera por todos os backups bem-sucedidos de um grupo, respeitando paginas."""
    page = 1
    pages = 1
    while page <= pages:
        payload = await get_json(
            http_client,
            server,
            "groups",
            external_group_id,
            "backups",
            params={"status": "success", "page": page, "per_page": per_page},
            timeout=timeout,
        )
        for item in payload.get("items", []):
            yield item
        pages = int(payload.get("pages") or pages or 1)
        page += 1
