"""Cobertura dos endpoints enriquecidos (/vlans-enriched e /subnets-enriched).

O ponto central destes testes é a **contagem de consultas**: os dois endpoints
faziam um `db.get` por linha (uma ida ao banco por associação VLAN↔interface e
uma por VLAN para buscar subnets). No maior cliente da base isso eram dezenas de
milhares de round-trips numa requisição só. Os testes de N+1 abaixo travam a
regressão: o número de consultas tem que ficar **constante** quando o volume de
dados dobra, não proporcional a ele.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

import database
import models
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


def _run(coro):
    return asyncio.run(coro)


class _QueryCounter:
    """Conta os SELECT emitidos no engine durante o bloco `with`."""

    def __init__(self):
        self.statements = []

    def __enter__(self):
        self._sync_engine = database.engine.sync_engine
        event.listen(self._sync_engine, "before_cursor_execute", self._on_exec)
        return self

    def __exit__(self, *exc):
        event.remove(self._sync_engine, "before_cursor_execute", self._on_exec)
        return False

    def _on_exec(self, conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            self.statements.append(statement)

    def __len__(self):
        return len(self.statements)


async def _seed(n_vlans: int, name: str):
    """Um ativo com `n_vlans` VLANs, cada uma com 1 interface e 1 subnet.

    Montado num commit só, via relacionamentos — acessar `.id` entre commits
    dispara IO síncrono fora do greenlet no engine async.
    """
    async with database.AsyncSessionLocal() as db:
        g = models.Client(name=name)
        a = models.Asset(hostname=f"SW-{name}", vendor="huawei", category="core",
                         client=g, is_approved=True)
        objs = [g, a]
        pares = []  # (subnet, vlan) — o vínculo é por FK crua, resolvido após o flush
        for i in range(n_vlans):
            vid = 100 + i
            v = models.Vlan(vid=vid, name=f"VLAN_{vid}", description="cliente",
                            client=g, asset=a)
            iface = models.AssetInterface(asset=a, name=f"GE0/0/{i}", type="physical",
                                          description=f"porta {i}", is_management=False)
            vi = models.VlanInterface(vlan=v, interface=iface, mode="trunk")
            s = models.Subnet(network=f"10.{i}.0.0", mask=24, host_ip=f"10.{i}.0.1",
                              description=f"bloco {i}", client=g, asset=a,
                              interface=iface)
            pares.append((s, v))
            objs += [v, iface, vi, s]

        db.add_all(objs)
        # Subnet.vlan_id é FK sem relationship (models.py:161) — só dá para ligar
        # depois que o flush atribui os ids das VLANs.
        await db.flush()
        for s, v in pares:
            s.vlan_id = v.id
        await db.commit()
        await db.refresh(g)
        return g.id


# ─────────────────────────────────────────────────────────────────────────────
# 1. Contrato — o que cada endpoint devolve
# ─────────────────────────────────────────────────────────────────────────────

def test_vlans_enriched_404_for_unknown_client(client):
    c, h = client
    r = c.get("/api/clients/99999/vlans-enriched", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "client_not_found"


def test_subnets_enriched_404_for_unknown_client(client):
    c, h = client
    r = c.get("/api/clients/99999/subnets-enriched", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "client_not_found"


def test_vlans_enriched_traz_interface_e_subnet(client):
    c, h = client
    gid = _run(_seed(3, "contrato-vlans"))

    r = c.get(f"/api/clients/{gid}/vlans-enriched", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 3

    v = next(x for x in data if x["vid"] == 100)
    assert v["name"] == "VLAN_100"
    assert v["asset_hostname"] == "SW-contrato-vlans"
    # interface veio do eager load, não de um db.get por linha
    assert [i["name"] for i in v["interfaces"]] == ["GE0/0/0"]
    assert v["interfaces"][0]["mode"] == "trunk"
    assert v["interfaces"][0]["description"] == "porta 0"
    # subnet veio do lote agrupado por (vlan_id, asset_id)
    assert [(s["network"], s["mask"]) for s in v["subnets"]] == [("10.0.0.0", 24)]


def test_subnets_enriched_traz_vlan_e_interface(client):
    c, h = client
    gid = _run(_seed(3, "contrato-subnets"))

    r = c.get(f"/api/clients/{gid}/subnets-enriched", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 3

    s = next(x for x in data if x["network"] == "10.0.0.0")
    assert s["mask"] == 24
    assert s["host_ip"] == "10.0.0.1"
    assert s["asset_hostname"] == "SW-contrato-subnets"
    assert s["vlan_vid"] == 100
    assert s["vlan_name"] == "VLAN_100"
    assert s["interface_name"] == "GE0/0/0"
    assert s["interface_type"] == "physical"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Paginação — opcional, e o padrão continua devolvendo tudo
# ─────────────────────────────────────────────────────────────────────────────

def test_vlans_enriched_limit_e_offset(client):
    c, h = client
    gid = _run(_seed(5, "pag-vlans"))

    todas = c.get(f"/api/clients/{gid}/vlans-enriched", headers=h).json()
    assert len(todas) == 5, "sem limit o padrão tem que devolver o conjunto inteiro"

    pag1 = c.get(f"/api/clients/{gid}/vlans-enriched?limit=2", headers=h).json()
    pag2 = c.get(f"/api/clients/{gid}/vlans-enriched?limit=2&offset=2", headers=h).json()
    assert [v["vid"] for v in pag1] == [v["vid"] for v in todas[:2]]
    assert [v["vid"] for v in pag2] == [v["vid"] for v in todas[2:4]]
    # paginar não pode perder o enriquecimento
    assert pag2[0]["subnets"] and pag2[0]["interfaces"]


def test_subnets_enriched_limit_e_offset(client):
    c, h = client
    gid = _run(_seed(5, "pag-subnets"))

    todas = c.get(f"/api/clients/{gid}/subnets-enriched", headers=h).json()
    assert len(todas) == 5

    pag2 = c.get(f"/api/clients/{gid}/subnets-enriched?limit=2&offset=2", headers=h).json()
    assert [s["network"] for s in pag2] == [s["network"] for s in todas[2:4]]
    assert pag2[0]["vlan_vid"] is not None


def test_vlan_orfa_nao_encurta_a_pagina(client):
    """VLAN sem ativo é descartada na resposta; o descarte tem que ser ANTES do LIMIT.

    Se o filtro ficar no laço Python (depois do LIMIT), `limit=3` num conjunto com
    órfãs devolve menos de 3 linhas e quem chama não distingue página curta de fim
    de lista — a paginação vira adivinhação.
    """
    async def _seed_orfas_primeiro():
        """Órfãs com os ids MAIS BAIXOS, em dois commits.

        Adicionar tudo num `add_all` não intercala: o unit-of-work agrupa os
        inserts e as órfãs caem no fim, fora da primeira página — aí o teste
        passa mesmo com o bug. Dois commits garantem que as órfãs venham antes
        no `ORDER BY id`, que é justamente onde o LIMIT as encontra.
        """
        async with database.AsyncSessionLocal() as db:
            g = models.Client(name="orfas-primeiro")
            db.add(g)
            # asset=None é permitido: models.py:146 não declara nullable=False
            db.add_all([
                models.Vlan(vid=900 + i, name=f"ORFA_{i}", client=g, asset=None)
                for i in range(4)
            ])
            await db.commit()
            await db.refresh(g)
            gid = g.id

        async with database.AsyncSessionLocal() as db:
            g = await db.get(models.Client, gid)
            a = models.Asset(hostname="SW-orfas", vendor="huawei", category="core",
                             client=g, is_approved=True)
            db.add(a)
            db.add_all([
                models.Vlan(vid=100 + i, name=f"OK_{i}", client=g, asset=a)
                for i in range(4)
            ])
            await db.commit()
        return gid

    gid = _run(_seed_orfas_primeiro())
    c, h = client

    todas = c.get(f"/api/clients/{gid}/vlans-enriched", headers=h).json()
    assert len(todas) == 4, "as 4 órfãs têm que sair da resposta"
    assert all(v["name"].startswith("OK_") for v in todas)

    # Por id, as 4 primeiras linhas cruas são as órfãs. Filtrando só no Python,
    # esta página devolveria 0.
    pag = c.get(f"/api/clients/{gid}/vlans-enriched?limit=3", headers=h).json()
    assert len(pag) == 3, (
        f"limit=3 devolveu {len(pag)} — as órfãs estão sendo descartadas depois "
        f"do LIMIT, então a página encurta"
    )
    assert [v["name"] for v in pag] == ["OK_0", "OK_1", "OK_2"]


def test_limit_invalido_e_rejeitado(client):
    c, h = client
    gid = _run(_seed(1, "pag-invalida"))
    assert c.get(f"/api/clients/{gid}/vlans-enriched?limit=0", headers=h).status_code == 422
    assert c.get(f"/api/clients/{gid}/vlans-enriched?offset=-1", headers=h).status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# 3. N+1 — o custo em consultas não pode crescer com o volume
# ─────────────────────────────────────────────────────────────────────────────

def test_vlans_enriched_nao_faz_n_mais_1(client):
    c, h = client
    gid_p = _run(_seed(3, "n1-vlans-pequeno"))
    gid_g = _run(_seed(30, "n1-vlans-grande"))

    with _QueryCounter() as pequeno:
        r = c.get(f"/api/clients/{gid_p}/vlans-enriched", headers=h)
        assert r.status_code == 200 and len(r.json()) == 3

    with _QueryCounter() as grande:
        r = c.get(f"/api/clients/{gid_g}/vlans-enriched", headers=h)
        assert r.status_code == 200 and len(r.json()) == 30

    # Sem isto a comparação abaixo passaria com 0 == 0 (contador não plugado).
    assert len(pequeno) > 0, "o contador de consultas não capturou nada"
    # 10x mais VLANs, mesmo número de consultas. Antes do fix o grande fazia
    # ~60 consultas a mais que o pequeno (1 db.get por interface + 1 select por VLAN).
    assert len(grande) == len(pequeno), (
        f"custo cresceu com o volume: {len(pequeno)} consultas para 3 VLANs, "
        f"{len(grande)} para 30 — o N+1 voltou"
    )


def test_subnets_enriched_nao_faz_n_mais_1(client):
    c, h = client
    gid_p = _run(_seed(3, "n1-subs-pequeno"))
    gid_g = _run(_seed(30, "n1-subs-grande"))

    with _QueryCounter() as pequeno:
        r = c.get(f"/api/clients/{gid_p}/subnets-enriched", headers=h)
        assert r.status_code == 200 and len(r.json()) == 3

    with _QueryCounter() as grande:
        r = c.get(f"/api/clients/{gid_g}/subnets-enriched", headers=h)
        assert r.status_code == 200 and len(r.json()) == 30

    assert len(pequeno) > 0, "o contador de consultas não capturou nada"
    assert len(grande) == len(pequeno), (
        f"custo cresceu com o volume: {len(pequeno)} consultas para 3 subnets, "
        f"{len(grande)} para 30 — o N+1 voltou"
    )
