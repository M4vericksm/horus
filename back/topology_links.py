"""
topology_links.py — Inferência de adjacência física entre equipamentos
======================================================================
Função pura (sem I/O, sem banco) que recebe a lista de "endpoints" de uma
VLAN — cada interface de cada equipamento por onde ela trafega — e infere
por quais pares de equipamentos a VLAN fecha enlace.

IMPORTANTE: o sistema extrai apenas o CONFIG dos equipamentos, não o estado
operacional (LLDP/CDP estão fora por decisão de segurança). Portanto a
adjacência aqui é SEMPRE inferida, nunca determinística. Cada enlace carrega
um nível de confiança e o motivo, para a UI deixar isso explícito:

    confiança "alta"  → ponto-a-ponto por subnet /30 ou /31 compartilhada
                        (típico de uplinks L3 / fechamento de MPLS)
    confiança "media" → descrição da interface cita o hostname do vizinho
                        (operador rotula o trunk, ex: "LINK-PARA-SW-CORE")

Formato de cada endpoint (dict):
    {
        "asset_id": int,
        "hostname": str,
        "interface": str,
        "mode": str,                 # access | trunk | tagged | native | routed
        "description": str | None,
        "host_ip": str | None,       # IP real configurado na interface
        "network": str | None,       # endereço de rede da subnet
        "mask": int | None,          # prefixo (CIDR)
        "type": str,                 # physical | vlan | ...
    }

Retorno de infer_links(): lista de dicts, um por par de equipamentos:
    {
        "a_asset_id": int, "a_hostname": str, "a_interface": str,
        "b_asset_id": int, "b_hostname": str, "b_interface": str | None,
        "confidence": "alta" | "media",
        "reason": "p2p_subnet" | "descricao",
        "detail": str,
    }
"""
from __future__ import annotations

import re

# Pesos para escolher o melhor sinal quando há mais de um para o mesmo par.
_SCORE = {"alta": 3, "media": 2, "baixa": 1}


def _host_labels(hostname: str | None) -> list[str]:
    """Variações normalizadas de um hostname para casar dentro de descrições.

    Ex.: "SW-CORE-01.rede.local" → ["sw-core-01.rede.local", "sw-core-01"].
    Só retorna labels com >= 3 caracteres (evita falso-positivo com siglas curtas).
    """
    if not hostname:
        return []
    full = hostname.strip().lower()
    labels = {full}
    # primeiro rótulo antes do domínio
    labels.add(full.split(".")[0])
    return [lb for lb in labels if len(lb) >= 3]


def _desc_norm(description: str | None) -> str:
    """Descrição em minúsculas, com separadores normalizados para espaço."""
    if not description:
        return ""
    return re.sub(r"[_/]+", "-", description.strip().lower())


def _pair_key(a_id: int, b_id: int) -> frozenset:
    return frozenset((a_id, b_id))


def infer_links(endpoints: list[dict]) -> list[dict]:
    """Infere enlaces entre equipamentos a partir dos endpoints de uma VLAN.

    Devolve no máximo um enlace por par de equipamentos, sempre o de maior
    confiança. Nunca lança exceção.
    """
    try:
        candidates: list[tuple] = []

        # ── 1. Ponto-a-ponto por subnet /30 ou /31 (confiança alta) ──────────
        by_net: dict[tuple, list[dict]] = {}
        for e in endpoints:
            net, mask = e.get("network"), e.get("mask")
            if net and mask in (30, 31):
                by_net.setdefault((net, mask), []).append(e)
        for (net, mask), group in by_net.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a, b = group[i], group[j]
                    if a["asset_id"] == b["asset_id"]:
                        continue
                    candidates.append((
                        _SCORE["alta"], "alta", "p2p_subnet",
                        a, b, a["interface"], b["interface"],
                        f"Enlace ponto-a-ponto {net}/{mask}",
                    ))

        # ── 2. Descrição da interface cita o vizinho (confiança média) ───────
        for a in endpoints:
            dn = _desc_norm(a.get("description"))
            if not dn:
                continue
            for b in endpoints:
                if b["asset_id"] == a["asset_id"]:
                    continue
                if not any(lb in dn for lb in _host_labels(b.get("hostname"))):
                    continue
                # interface do lado B: a que, por sua vez, cita o hostname de A
                b_iface = None
                a_labels = _host_labels(a.get("hostname"))
                for c in endpoints:
                    if c["asset_id"] != b["asset_id"]:
                        continue
                    cd = _desc_norm(c.get("description"))
                    if cd and any(lb in cd for lb in a_labels):
                        b_iface = c["interface"]
                        break
                candidates.append((
                    _SCORE["media"], "media", "descricao",
                    a, b, a["interface"], b_iface,
                    f'Descrição de {a["hostname"]} {a["interface"]} cita {b["hostname"]}',
                ))

        # ── 3. Escolhe o melhor sinal por par de equipamentos ────────────────
        best: dict[frozenset, tuple] = {}
        for cand in candidates:
            score, a, b = cand[0], cand[3], cand[4]
            key = _pair_key(a["asset_id"], b["asset_id"])
            if key not in best or score > best[key][0]:
                best[key] = cand

        links: list[dict] = []
        for score, conf, reason, a, b, ai, bi, detail in best.values():
            links.append({
                "a_asset_id": a["asset_id"], "a_hostname": a["hostname"], "a_interface": ai,
                "b_asset_id": b["asset_id"], "b_hostname": b["hostname"], "b_interface": bi,
                "confidence": conf, "reason": reason, "detail": detail,
            })
        # ordena por confiança desc, depois por hostname para estabilidade
        links.sort(key=lambda l: (-_SCORE.get(l["confidence"], 0), l["a_hostname"], l["b_hostname"]))
        return links

    except Exception:
        # Inferência é best-effort; nunca derruba o endpoint.
        return []
