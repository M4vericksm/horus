"""Busca global de VLAN entre provedores + contagens de cliente por subquery.

A contagem antes vinha de selectinload + len() em Python (carregava todas as
VLANs do banco só para contar); estes testes fixam o contrato do número.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

import database
import models
from main import app, RATE_BUCKETS


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


def _mk_client(c, h, name):
    r = c.post("/api/clients", headers=h, json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _mk_asset(c, h, client_id, hostname, **extra):
    payload = {"hostname": hostname, "client_id": client_id}
    payload.update(extra)
    r = c.post("/api/assets", headers=h, json=payload)
    assert r.status_code == 200, r.text
    return r.json().get("id") or r.json().get("asset", {}).get("id")


# ──────────────────────────────────────────
# Contagens (list_clients / get_client)
# ──────────────────────────────────────────

def test_client_counts_sem_dados(client):
    c, h = client
    cid = _mk_client(c, h, "Prov Zerado")
    body = c.get(f"/api/clients/{cid}", headers=h).json()
    assert body["asset_count"] == 0
    assert body["vlan_count"] == 0
    assert body["subnet_count"] == 0
    assert body["has_bc_link"] is False


def test_asset_count_so_conta_aprovados(client):
    """A contagem de ativos considera apenas is_approved — contrato preservado
    da versão que filtrava em Python."""
    c, h = client
    cid = _mk_client(c, h, "Prov Aprovacao")
    _mk_asset(c, h, cid, "SW-APROVADO")   # POST /api/assets marca is_approved=True
    body = c.get(f"/api/clients/{cid}", headers=h).json()
    assert body["asset_count"] == 1

    lista = c.get("/api/clients", headers=h).json()
    achado = next(x for x in lista if x["id"] == cid)
    assert achado["asset_count"] == 1, "listagem e detalhe devem concordar"


def test_get_client_404_preservado(client):
    c, h = client
    r = c.get("/api/clients/999999", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "client_not_found"


def test_list_clients_mascara_segredos(client):
    """A troca de selectinload por subquery não pode furar o mascaramento."""
    c, h = client
    cid = _mk_client(c, h, "Prov Segredo")
    c.put(f"/api/clients/{cid}", headers=h,
          json={"name": "Prov Segredo", "vpn_host": "10.0.0.1",
                "vpn_user": "admin", "vpn_pass": "segredo-real"})
    achado = next(x for x in c.get("/api/clients", headers=h).json() if x["id"] == cid)
    assert achado["vpn_pass"] == "********"
    assert achado["vpn_user"] == "admin", "campo não-secreto não pode ser mascarado"


# ──────────────────────────────────────────
# Busca global de VLAN entre provedores
# ──────────────────────────────────────────

async def _seed_trilha_vlan100():
    """VLAN 100 atravessando três provedores + ruído que não pode casar.

    PIX (nasce, na borda) → FLASH (transita, 2 ativos) → i4 (termina).
    O provedor 'Outro Prov' tem só a VLAN 999, e a 'ROTA-100' existe para
    provar que a busca textual não é confundida com o VID."""
    async with database.AsyncSessionLocal() as db:
        pix = models.Client(name="Provedor Gama")
        flash = models.Client(name="Provedor Alfa")
        i4 = models.Client(name="Provedor Beta")
        outro = models.Client(name="Outro Prov")

        a_pix = models.Asset(hostname="PIX-BORDA", vendor="huawei", category="core",
                             client=pix, is_approved=True, is_edge_router=True)
        a_fl1 = models.Asset(hostname="FLASH-CORE", vendor="mikrotik", category="core",
                             client=flash, is_approved=True)
        a_fl2 = models.Asset(hostname="FLASH-AGREG", vendor="mikrotik", category="acesso",
                             client=flash, is_approved=True)
        a_i4 = models.Asset(hostname="I4-CORE", vendor="cisco", category="core",
                            client=i4, is_approved=True)
        a_out = models.Asset(hostname="OUTRO-SW", vendor="cisco", client=outro, is_approved=True)

        objs = [
            pix, flash, i4, outro, a_pix, a_fl1, a_fl2, a_i4, a_out,
            models.Vlan(vid=100, name="TRANSPORTE-PIX", description="entrega i4",
                        client=pix, asset=a_pix),
            models.Vlan(vid=100, name="TRANSPORTE", description="transito",
                        client=flash, asset=a_fl1),
            models.Vlan(vid=100, name="TRANSPORTE", description="transito",
                        client=flash, asset=a_fl2),
            models.Vlan(vid=100, name="ENTREGA-PIX", description="cliente final",
                        client=i4, asset=a_i4),
            models.Vlan(vid=999, name="OUTRA", description="nao casa",
                        client=outro, asset=a_out),
        ]
        db.add_all(objs)
        await db.commit()


def test_busca_vlan_atravessa_provedores(client):
    """Cenário real: VLAN 100 nasce na PIX, passa na Flash, vai para a i4."""
    c, h = client
    _run(_seed_trilha_vlan100())

    body = c.get("/api/vlans/search", headers=h, params={"q": "100"}).json()

    nomes = [g["client_name"] for g in body["results"]]
    assert nomes == ["Provedor Alfa", "Provedor Beta", "Provedor Gama"], "ordenado por provedor"
    assert body["client_count"] == 3
    assert body["total"] == 4          # 1 PIX + 2 Flash + 1 i4
    assert body["truncated"] is False
    assert "Outro Prov" not in nomes   # VLAN 999 não entra

    por_prov = {g["client_name"]: g for g in body["results"]}
    assert por_prov["Provedor Alfa"]["occurrence_count"] == 2
    assert por_prov["Provedor Alfa"]["vids"] == [100]
    hosts_flash = {o["asset_hostname"] for o in por_prov["Provedor Alfa"]["occurrences"]}
    assert hosts_flash == {"FLASH-CORE", "FLASH-AGREG"}

    pix_oc = por_prov["Provedor Gama"]["occurrences"][0]
    assert pix_oc["asset_hostname"] == "PIX-BORDA"
    assert pix_oc["is_edge_router"] is True
    assert pix_oc["asset_vendor"] == "huawei"


def test_busca_numerica_e_vid_exato_nao_substring(client):
    """Buscar 500 não pode trazer 1500/2500/3500 — o nome "VLAN_1500" contém
    "500", e casar texto aqui tornava a busca inútil em produção."""
    c, h = client
    _run(_seed_vids_parecidos())

    body = c.get("/api/vlans/search", headers=h, params={"q": "500"}).json()
    vids = {v for g in body["results"] for v in g["vids"]}
    assert vids == {500}, f"esperado só VID 500, veio {vids}"

    # E o inverso continua valendo: 1500 traz só 1500.
    body = c.get("/api/vlans/search", headers=h, params={"q": "1500"}).json()
    vids = {v for g in body["results"] for v in g["vids"]}
    assert vids == {1500}


def test_busca_por_provedores_filtra_transporte(client):
    """Rastreio de transporte: restringe a VLAN aos provedores do circuito."""
    c, h = client
    _run(_seed_trilha_vlan100())

    todos = c.get("/api/vlans/search", headers=h, params={"q": "100"}).json()
    assert todos["client_count"] == 3
    ids = {g["client_name"]: g["client_id"] for g in todos["results"]}

    par = f'{ids["Provedor Gama"]},{ids["Provedor Beta"]}'
    body = c.get("/api/vlans/search", headers=h, params={"q": "100", "clients": par}).json()
    nomes = sorted(g["client_name"] for g in body["results"])
    assert nomes == ["Provedor Gama", "Provedor Beta"] or nomes == ["Provedor Beta", "Provedor Gama"]
    assert body["client_count"] == 2


def test_busca_por_provedores_rejeita_lista_invalida(client):
    c, h = client
    r = c.get("/api/vlans/search", headers=h, params={"q": "100", "clients": "abc"})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "vlan_search_clients_invalid"


async def _seed_vids_parecidos():
    """VIDs que se contêm textualmente: 500, 1500, 2500, 3500."""
    async with database.AsyncSessionLocal() as db:
        cli = models.Client(name="Prov VIDs")
        a = models.Asset(hostname="SW-VIDS", client=cli, is_approved=True)
        objs = [cli, a]
        for vid in (500, 1500, 2500, 3500):
            objs.append(models.Vlan(vid=vid, name=f"VLAN_{vid}",
                                    description=f"rede {vid}", client=cli, asset=a))
        db.add_all(objs)
        await db.commit()


def test_busca_vlan_por_texto_casa_nome(client):
    """Busca textual encontra a VLAN pelo nome, em todos os provedores."""
    c, h = client
    _run(_seed_trilha_vlan100())
    body = c.get("/api/vlans/search", headers=h, params={"q": "TRANSPORTE"}).json()
    nomes = sorted(g["client_name"] for g in body["results"])
    assert nomes == ["Provedor Alfa", "Provedor Gama"]
    assert body["total"] == 3


def test_busca_vlan_exige_termo(client):
    c, h = client
    r = c.get("/api/vlans/search", headers=h, params={"q": "   "})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "vlan_search_empty"


def test_busca_vlan_sem_resultado_responde_vazio(client):
    c, h = client
    r = c.get("/api/vlans/search", headers=h, params={"q": "zzz-nao-existe-zzz"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["client_count"] == 0
    assert body["results"] == []
    assert body["truncated"] is False
