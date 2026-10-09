"""Cobertura do caminho (trace) de VLAN: inferência pura + endpoint."""
import asyncio

import pytest
from fastapi.testclient import TestClient

import database
import main
import models
import topology_links
from main import app, RATE_BUCKETS


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


def _run(coro):
    return asyncio.run(coro)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Inferência pura — topology_links.infer_links
# ─────────────────────────────────────────────────────────────────────────────

def _ep(asset_id, hostname, interface, **kw):
    base = {
        "asset_id": asset_id, "hostname": hostname, "interface": interface,
        "mode": "trunk", "description": None, "host_ip": None,
        "network": None, "mask": None, "type": "physical",
    }
    base.update(kw)
    return base


def test_infer_links_empty_when_no_signal():
    eps = [
        _ep(1, "SW-A", "xg1"),
        _ep(2, "SW-B", "xg1"),
    ]
    assert topology_links.infer_links(eps) == []


def test_infer_links_p2p_subnet_high_confidence():
    eps = [
        _ep(1, "SW-A", "xg10", network="10.0.0.0", mask=30, host_ip="10.0.0.1"),
        _ep(2, "SW-B", "xg15", network="10.0.0.0", mask=30, host_ip="10.0.0.2"),
    ]
    links = topology_links.infer_links(eps)
    assert len(links) == 1
    lk = links[0]
    assert lk["confidence"] == "alta"
    assert lk["reason"] == "p2p_subnet"
    assert {lk["a_interface"], lk["b_interface"]} == {"xg10", "xg15"}


def test_infer_links_description_medium_confidence_and_mutual_iface():
    eps = [
        _ep(1, "SW-A", "ge-0/0/1", description="UPLINK PARA SW-B core"),
        _ep(2, "SW-B", "ge-0/0/2", description="UPLINK PARA SW-A core"),
    ]
    links = topology_links.infer_links(eps)
    assert len(links) == 1
    lk = links[0]
    assert lk["confidence"] == "media"
    assert lk["reason"] == "descricao"
    # casamento mútuo resolve a interface da ponta B
    assert {lk["a_interface"], lk["b_interface"]} == {"ge-0/0/1", "ge-0/0/2"}


def test_infer_links_p2p_beats_description_for_same_pair():
    eps = [
        _ep(1, "SW-A", "xg10", network="10.0.0.0", mask=31, host_ip="10.0.0.0",
            description="LINK SW-B"),
        _ep(2, "SW-B", "xg15", network="10.0.0.0", mask=31, host_ip="10.0.0.1",
            description="LINK SW-A"),
    ]
    links = topology_links.infer_links(eps)
    assert len(links) == 1
    assert links[0]["confidence"] == "alta"


def test_infer_links_ignores_same_asset_interfaces():
    eps = [
        _ep(1, "SW-A", "xg1", network="10.0.0.0", mask=30),
        _ep(1, "SW-A", "xg2", network="10.0.0.0", mask=30),
    ]
    assert topology_links.infer_links(eps) == []


def test_infer_links_short_hostname_does_not_false_match():
    # hostname de 2 chars não deve casar dentro de descrições arbitrárias
    eps = [
        _ep(1, "AB", "xg1", description="trunk para distribuicao"),
        _ep(2, "SW-DISTRIB", "xg1", description="ab uplink"),
    ]
    links = topology_links.infer_links(eps)
    # "ab" tem < 3 chars → ignorado; "sw-distrib" não aparece na desc de AB
    assert links == []


# ─────────────────────────────────────────────────────────────────────────────
# 2. Endpoint — /api/clients/{id}/vlans/{vid}/trace
# ─────────────────────────────────────────────────────────────────────────────

async def _seed_vlan_trace():
    """Dois switches com VLAN 100 num /30 (p2p) e VLAN 200 só por descrição.

    Tudo montado via relacionamentos e um único commit — evita lazy-load fora do
    greenlet (acesso a `.id` entre commits dispara IO síncrono no async).
    """
    async with database.AsyncSessionLocal() as db:
        g = models.Client(name="Grupo Trace")
        a = models.Asset(hostname="SW-A", vendor="cisco", category="core", client=g, is_approved=True)
        b = models.Asset(hostname="SW-B", vendor="cisco", category="acesso", client=g, is_approved=True)

        # VLAN 100 e 200 nos dois ativos
        v100a = models.Vlan(vid=100, name="CLIENTE", description="L2 cliente", client=g, asset=a)
        v100b = models.Vlan(vid=100, name="CLIENTE", description="L2 cliente", client=g, asset=b)
        v200a = models.Vlan(vid=200, name="TRANSPORTE", description="uplink", client=g, asset=a)
        v200b = models.Vlan(vid=200, name="TRANSPORTE", description="uplink", client=g, asset=b)

        # Interfaces
        ifa100 = models.AssetInterface(asset=a, name="xg10", type="physical", description="LINK-PARA-SW-B")
        ifb100 = models.AssetInterface(asset=b, name="xg15", type="physical", description="LINK-PARA-SW-A")
        ifa200 = models.AssetInterface(asset=a, name="ge-0/0/1", type="physical", description="UPLINK SW-B")
        ifb200 = models.AssetInterface(asset=b, name="ge-0/0/2", type="physical", description="UPLINK SW-A")

        # Associações VLAN ↔ interface
        vi1 = models.VlanInterface(vlan=v100a, interface=ifa100, mode="trunk")
        vi2 = models.VlanInterface(vlan=v100b, interface=ifb100, mode="trunk")
        vi3 = models.VlanInterface(vlan=v200a, interface=ifa200, mode="trunk")
        vi4 = models.VlanInterface(vlan=v200b, interface=ifb200, mode="trunk")

        # Subnets /30 nas interfaces da VLAN 100 (fecha p2p)
        s1 = models.Subnet(network="10.0.0.0", mask=30, host_ip="10.0.0.1", client=g, asset=a, interface=ifa100)
        s2 = models.Subnet(network="10.0.0.0", mask=30, host_ip="10.0.0.2", client=g, asset=b, interface=ifb100)

        db.add_all([g, a, b, v100a, v100b, v200a, v200b,
                    ifa100, ifb100, ifa200, ifb200, vi1, vi2, vi3, vi4, s1, s2])
        await db.commit()
        await db.refresh(g)
        return g.id


def test_vlan_trace_404_for_unknown_client(client):
    c, h = client
    r = c.get("/api/clients/99999/vlans/100/trace", headers=h)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "client_not_found"


def test_vlan_trace_returns_endpoints_with_config_and_p2p_link(client):
    c, h = client
    gid = _run(_seed_vlan_trace())

    r = c.get(f"/api/clients/{gid}/vlans/100/trace", headers=h)
    assert r.status_code == 200
    data = r.json()

    assert data["vid"] == 100
    assert data["name"] == "CLIENTE"
    # duas pontas, com IP real e descrição
    ifaces = {e["interface"]: e for e in data["endpoints"]}
    assert set(ifaces) == {"xg10", "xg15"}
    assert ifaces["xg10"]["host_ip"] == "10.0.0.1"
    assert ifaces["xg10"]["description"] == "LINK-PARA-SW-B"
    assert ifaces["xg10"]["mode"] == "trunk"

    # enlace inferido por /30 → alta
    assert len(data["links"]) == 1
    assert data["links"][0]["confidence"] == "alta"
    assert data["links"][0]["reason"] == "p2p_subnet"
    assert data["stats"]["asset_count"] == 2


def test_vlan_trace_infers_link_by_description_when_no_subnet(client):
    c, h = client
    gid = _run(_seed_vlan_trace())

    r = c.get(f"/api/clients/{gid}/vlans/200/trace", headers=h)
    assert r.status_code == 200
    data = r.json()

    assert data["vid"] == 200
    assert {e["interface"] for e in data["endpoints"]} == {"ge-0/0/1", "ge-0/0/2"}
    # sem subnet → cai na inferência por descrição (média)
    assert len(data["links"]) == 1
    assert data["links"][0]["confidence"] == "media"
    assert data["links"][0]["reason"] == "descricao"


def test_vlan_trace_empty_for_vlan_without_interfaces(client):
    c, h = client
    gid = _run(_seed_vlan_trace())

    r = c.get(f"/api/clients/{gid}/vlans/4000/trace", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert data["endpoints"] == []
    assert data["links"] == []
