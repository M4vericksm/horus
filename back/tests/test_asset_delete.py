"""Exclusão de ativos: permitida só para os cadastrados manualmente.

Ativo descoberto pela Backup API tem `bc_device_id` preenchido e não pode ser
removido — o próximo discover o recriaria, então a exclusão seria só aparente e
destruiria as VLANs/subnets dele no intervalo.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

import database
import models
from main import app, RATE_BUCKETS


def _run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


async def _seed(*, bc_device_id=None, com_dados=False):
    """Cria um cliente com um ativo; opcionalmente com VLAN e subnet vinculadas."""
    async with database.AsyncSessionLocal() as db:
        cli = models.Client(name=f"Prov {bc_device_id or 'manual'}-{id(object())}")
        a = models.Asset(hostname="SW-TESTE", client=cli, is_approved=True,
                         bc_device_id=bc_device_id)
        objs = [cli, a]
        if com_dados:
            objs += [
                models.Vlan(vid=10, name="V10", client=cli, asset=a),
                models.Vlan(vid=20, name="V20", client=cli, asset=a),
                models.Subnet(network="10.0.0.0", mask=24, client=cli, asset=a),
            ]
        db.add_all(objs)
        await db.commit()
        return a.id


def test_ativo_manual_pode_ser_excluido(client):
    c, h = client
    aid = _run(_seed())
    r = c.delete(f"/api/assets/{aid}", headers=h)
    assert r.status_code == 200
    assert c.delete(f"/api/assets/{aid}", headers=h).status_code == 404, "deve sumir de fato"


def test_ativo_do_backup_nao_pode_ser_excluido(client):
    c, h = client
    aid = _run(_seed(bc_device_id="bc-dev-991"))
    r = c.delete(f"/api/assets/{aid}", headers=h)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "asset_from_backup"


def test_ativo_do_backup_sobrevive_a_tentativa(client):
    """A recusa não pode ter efeito colateral: o ativo continua íntegro."""
    c, h = client
    aid = _run(_seed(bc_device_id="bc-dev-992", com_dados=True))
    c.delete(f"/api/assets/{aid}", headers=h)

    async def _conferir():
        from sqlalchemy import func, select
        async with database.AsyncSessionLocal() as db:
            existe = await db.get(models.Asset, aid)
            n = (await db.execute(
                select(func.count(models.Vlan.id)).where(models.Vlan.asset_id == aid))).scalar()
            return existe is not None, n

    vivo, vlans = _run(_conferir())
    assert vivo, "ativo do BC não pode ser removido"
    assert vlans == 2, "as VLANs dele não podem ser tocadas"


def test_exclusao_reporta_o_que_foi_removido_em_cascata(client):
    """O operador precisa ver o estrago: a remoção leva VLANs e subnets junto."""
    c, h = client
    aid = _run(_seed(com_dados=True))
    body = c.delete(f"/api/assets/{aid}", headers=h).json()
    assert body["vlans_removidas"] == 2
    assert body["subnets_removidas"] == 1
    assert body["hostname"] == "SW-TESTE"


def test_origem_nao_pode_ser_forjada_pela_api(client):
    """bc_device_id fica fora do schema de entrada: um PUT não converte um ativo
    da Backup API em 'manual' para liberar a exclusão."""
    c, h = client
    aid = _run(_seed(bc_device_id="bc-dev-993"))

    c.put(f"/api/assets/{aid}", headers=h,
          json={"hostname": "SW-TESTE", "bc_device_id": None})

    r = c.delete(f"/api/assets/{aid}", headers=h)
    assert r.status_code == 409, "a origem precisa continuar valendo após o PUT"


def test_resposta_expoe_a_origem_para_o_front(client):
    """O front esconde o botão de excluir com base neste campo."""
    c, h = client
    aid = _run(_seed(bc_device_id="bc-dev-994"))

    async def _client_id():
        async with database.AsyncSessionLocal() as db:
            return (await db.get(models.Asset, aid)).client_id

    cid = _run(_client_id())
    lista = c.get(f"/api/clients/{cid}/assets", headers=h).json()
    alvo = next(a for a in lista if a["id"] == aid)
    assert alvo["bc_device_id"] == "bc-dev-994"


def test_excluir_ativo_inexistente_retorna_404(client):
    c, h = client
    r = c.delete("/api/assets/999999", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "asset_not_found"
