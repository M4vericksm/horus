"""Cliente da API JSON-RPC do Zabbix (integração de monitoramento por provedor).

Modelo A do plano (docs/PLANO_ZABBIX_PORTAL_PROVEDOR.md): o Atlas consulta, em
modo leitura, o Zabbix que cada provedor já opera. Nada é instalado no provedor.

Autenticação: Zabbix >= 5.4 usa token de API via header `Authorization: Bearer`.
Versões anteriores usam o campo `auth` no corpo da requisição. Este cliente tenta
Bearer primeiro e, diante de erro de autorização, reenvia com `auth` no corpo —
cobrindo ambos os regimes sem o operador precisar informar a versão.

Somente leitura: expõe apiinfo.version, host.get, trigger.get e interface.get.
Nenhum método de escrita (create/update/delete) é implementado de propósito.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Optional

import httpx

from logger import logger
from security import validate_external_url

# Severidades do Zabbix (trigger/problem priority) → rótulo legível.
SEVERITY_LABELS = {
    0: "not_classified",
    1: "information",
    2: "warning",
    3: "average",
    4: "high",
    5: "disaster",
}

# interface.available: 0 = desconhecido, 1 = disponível, 2 = indisponível.
IFACE_AVAILABLE = 1
IFACE_UNAVAILABLE = 2


class ZabbixError(Exception):
    """Erro lógico devolvido pela API do Zabbix (campo `error` do JSON-RPC)."""

    def __init__(self, message: str, *, auth: bool = False):
        super().__init__(message)
        self.auth = auth


def _normalize_endpoint(url: str) -> str:
    """Deriva a URL do endpoint JSON-RPC e valida contra SSRF.

    Aceita tanto a base do frontend (`https://zbx.prov.com`) quanto a URL já
    apontando para `api_jsonrpc.php`. Preserva o scheme; assume https quando
    ausente (não vaza token em http claro por engano)."""
    base = (url or "").strip().rstrip("/")
    if not base:
        raise ValueError("URL do Zabbix vazia.")
    if "://" not in base:
        base = f"https://{base}"
    if not base.endswith("api_jsonrpc.php"):
        base = f"{base}/api_jsonrpc.php"
    # Valida o host (bloqueia loopback/metadata; privados dependem de ALLOW_PRIVATE_TARGETS).
    validate_external_url(base)
    return base


class ZabbixClient:
    """Cliente async de leitura. Use como context manager para reaproveitar a
    conexão httpx entre chamadas do mesmo ciclo (summary + problems + hosts)."""

    def __init__(self, url: str, token: str, *, verify_tls: bool = True, timeout: float = 12.0):
        self.endpoint = _normalize_endpoint(url)
        self.token = token or ""
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._http: Optional[httpx.AsyncClient] = None
        # None = ainda não decidido; True = Bearer; False = campo auth no corpo.
        self._use_bearer: Optional[bool] = None

    async def __aenter__(self) -> "ZabbixClient":
        self._http = httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _raw_post(self, body: dict, headers: dict) -> dict:
        assert self._http is not None, "ZabbixClient deve ser usado como context manager."
        res = await self._http.post(self.endpoint, json=body, headers=headers)
        res.raise_for_status()
        return res.json()

    async def _call(self, method: str, params: Any, *, needs_auth: bool = True) -> Any:
        """Executa um método JSON-RPC. Faz fallback Bearer→auth-no-corpo uma vez
        quando o token é rejeitado, cobrindo Zabbix antigo e novo."""
        base_body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}

        if not needs_auth or not self.token:
            data = await self._raw_post(base_body, {"Content-Type": "application/json-rpc"})
            return self._unwrap(data)

        # Ordem de tentativa: respeita o modo já descoberto; senão Bearer primeiro.
        modes = [self._use_bearer] if self._use_bearer is not None else [True, False]
        last_err: Optional[ZabbixError] = None
        for use_bearer in modes:
            headers = {"Content-Type": "application/json-rpc"}
            body = dict(base_body)
            if use_bearer:
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                body["auth"] = self.token
            try:
                data = await self._raw_post(body, headers)
                result = self._unwrap(data)
                self._use_bearer = use_bearer  # memoiza o modo que funcionou
                return result
            except ZabbixError as e:
                last_err = e
                if not e.auth:
                    raise  # erro que não é de auth: não adianta trocar o modo
                continue
        assert last_err is not None
        raise last_err

    @staticmethod
    def _unwrap(data: dict) -> Any:
        if "error" in data:
            err = data["error"] or {}
            msg = err.get("data") or err.get("message") or "Erro desconhecido do Zabbix."
            low = str(msg).lower()
            is_auth = any(k in low for k in (
                "auth", "not authori", "re-login", "session terminated", "permission deni",
            ))
            raise ZabbixError(str(msg), auth=is_auth)
        return data.get("result")

    # ---- Métodos de leitura ------------------------------------------------

    async def get_version(self) -> str:
        """apiinfo.version — não requer autenticação. Bom teste de conectividade."""
        return await self._call("apiinfo.version", {}, needs_auth=False)

    async def get_hosts(self) -> list[dict]:
        """Hosts monitorados com interfaces (IP/DNS/disponibilidade) e grupos."""
        return await self._call("host.get", {
            "output": ["hostid", "host", "name", "status"],
            "selectInterfaces": ["ip", "dns", "type", "main", "available"],
            "selectHostGroups": ["name"],
            "filter": {"status": 0},  # 0 = monitorado (ignora hosts desabilitados)
        }) or []

    async def get_active_problems(self) -> list[dict]:
        """Problemas ativos via trigger.get (traz host + severidade + descrição),
        útil para correlacionar alarme→ativo→VLAN no Atlas."""
        rows = await self._call("trigger.get", {
            "output": ["triggerid", "description", "priority", "lastchange"],
            "selectHosts": ["hostid", "host", "name"],
            "filter": {"value": 1},   # 1 = em estado de problema
            "only_true": True,
            "monitored": True,
            "active": True,
            "sortfield": "priority",
            "sortorder": "DESC",
        }) or []
        problems = []
        for t in rows:
            hosts = t.get("hosts") or []
            problems.append({
                "triggerid": t.get("triggerid"),
                "description": t.get("description"),
                "severity": int(t.get("priority", 0)),
                "severity_label": SEVERITY_LABELS.get(int(t.get("priority", 0)), "unknown"),
                "lastchange": int(t.get("lastchange", 0)) if t.get("lastchange") else None,
                "hosts": [{"hostid": h.get("hostid"), "host": h.get("host"),
                           "name": h.get("name")} for h in hosts],
            })
        return problems


def summarize_hosts(hosts: list[dict]) -> dict:
    """Agrega estado de disponibilidade a partir das interfaces dos hosts.

    Um host conta como 'down' se todas as suas interfaces estão indisponíveis;
    'up' se ao menos uma está disponível; 'unknown' caso o Zabbix ainda não
    tenha polido (available=0)."""
    up = down = unknown = 0
    for h in hosts:
        states = [int(i.get("available", 0)) for i in (h.get("interfaces") or [])]
        if not states:
            unknown += 1
        elif any(s == IFACE_AVAILABLE for s in states):
            up += 1
        elif all(s == IFACE_UNAVAILABLE for s in states):
            down += 1
        else:
            unknown += 1
    return {"total": len(hosts), "up": up, "down": down, "unknown": unknown}


def summarize_problems(problems: list[dict]) -> dict:
    """Contagem de problemas ativos por severidade (rótulo → quantidade)."""
    by_sev: dict[str, int] = {label: 0 for label in SEVERITY_LABELS.values()}
    for p in problems:
        by_sev[p.get("severity_label", "unknown")] = by_sev.get(p.get("severity_label", "unknown"), 0) + 1
    return {"total": len(problems), "by_severity": by_sev}


def is_documentable_ip(ip: str) -> bool:
    """Um IP só entra no IPAM se for endereço de host documentável.

    Descarta o que polui inventário e apareceu em Zabbix real de ISP: loopback
    (127.0.0.1 do próprio Zabbix server), link-local/APIPA, multicast, reservado
    e não-especificado. IPs públicos usados como placeholder (ex.: 8.8.8.8 /
    9.9.9.9 em hosts desativados) não dá para detectar por heurística — ficam
    barrados naturalmente por não pertencerem a nenhum bloco declarado."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified or addr.is_reserved)


def extract_host_ips(hosts: list[dict]) -> list[dict]:
    """IPs 'observados' — um registro por (host, IP) das interfaces com IP válido.

    Marca `available` (o IP responde no Zabbix) para o AUTO IPAM diferenciar
    endereço vivo de documentado sem resposta."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for h in hosts:
        display = h.get("name") or h.get("host") or ""
        for iface in (h.get("interfaces") or []):
            ip = (iface.get("ip") or "").strip()
            if not ip or not is_documentable_ip(ip):
                continue
            key = (display, ip)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "ip": ip,
                "hostname": display,
                "dns": (iface.get("dns") or "").strip() or None,
                "available": int(iface.get("available", 0)) == IFACE_AVAILABLE,
            })
    return out
