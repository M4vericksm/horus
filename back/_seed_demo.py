"""Seed de DEMONSTRAÇÃO para validação local (NÃO usar em produção).

Cria o grupo "Grupo Demo Atlas" com 3 equipamentos, VLANs, interfaces,
associações VLAN↔interface e subnets — incluindo um enlace /30 (MPLS) entre
borda e core e descrições que citam os vizinhos, para exercitar o trace de VLAN.

Idempotente: se o grupo já existir, não duplica.
Remover depois:  DELETE manual ou recriar o volume do Postgres.
"""
import asyncio

import database
import models
from sqlalchemy import delete
from sqlalchemy.future import select

DEMO_NAME = "Grupo Demo Atlas"
DEMO_HOSTS = ["RT-BORDA-01", "SW-CORE-01", "SW-ACESSO-01"]


async def main():
    async with database.AsyncSessionLocal() as db:
        # Limpa qualquer seed parcial anterior, na ordem dos FKs (filhos primeiro).
        res = await db.execute(select(models.Asset.id).where(models.Asset.hostname.in_(DEMO_HOSTS)))
        asset_ids = [r[0] for r in res.all()]
        if asset_ids:
            vlan_ids = [r[0] for r in (await db.execute(
                select(models.Vlan.id).where(models.Vlan.asset_id.in_(asset_ids)))).all()]
            iface_ids = [r[0] for r in (await db.execute(
                select(models.AssetInterface.id).where(models.AssetInterface.asset_id.in_(asset_ids)))).all()]
            if vlan_ids or iface_ids:
                cond = []
                if vlan_ids:
                    cond.append(models.VlanInterface.vlan_id.in_(vlan_ids))
                if iface_ids:
                    cond.append(models.VlanInterface.interface_id.in_(iface_ids))
                from sqlalchemy import or_
                await db.execute(delete(models.VlanInterface).where(or_(*cond)))
            await db.execute(delete(models.Subnet).where(models.Subnet.asset_id.in_(asset_ids)))
            await db.execute(delete(models.Vlan).where(models.Vlan.asset_id.in_(asset_ids)))
            await db.execute(delete(models.AssetInterface).where(models.AssetInterface.asset_id.in_(asset_ids)))
            await db.execute(delete(models.Asset).where(models.Asset.id.in_(asset_ids)))
        await db.execute(delete(models.Client).where(models.Client.name == DEMO_NAME))
        await db.commit()
        if asset_ids:
            print(f"[seed] seed anterior de '{DEMO_NAME}' removido.")

        # Cria o client e dá flush para obter o id antes de amarrar os FKs.
        g = models.Client(name=DEMO_NAME, ip="10.20.0.0/16")
        db.add(g)
        await db.flush()

        rt = models.Asset(hostname="RT-BORDA-01", vendor="cisco", category="borda", client_id=g.id,
                          ip_address="10.20.0.1", is_approved=True, is_edge_router=True, authority_level=3)
        core = models.Asset(hostname="SW-CORE-01", vendor="huawei", category="core", client_id=g.id,
                            ip_address="10.20.0.2", is_approved=True, authority_level=2)
        acc = models.Asset(hostname="SW-ACESSO-01", vendor="datacom", category="acesso", client_id=g.id,
                          ip_address="10.20.0.3", is_approved=True, authority_level=1)
        db.add_all([rt, core, acc])
        await db.flush()

        # ── VLAN 100 TRANSPORTE-MPLS: borda ↔ core num /30 (enlace L3) ───────
        v100_rt = models.Vlan(vid=100, name="TRANSPORTE-MPLS", description="Uplink MPLS borda-core", vlan_type="l2vc",
                              config="interface xg-0/0/10\n description LINK-PARA-SW-CORE-01\n xconnect 172.16.0.2 100 encapsulation mpls", client=g, asset=rt)
        v100_core = models.Vlan(vid=100, name="TRANSPORTE-MPLS", description="Uplink MPLS borda-core", vlan_type="l2vc",
                                config="interface XGigabitEthernet0/0/15.100 mode l2\n encapsulation dot1q vid 100\n mpls l2vc 172.16.0.1 100 vlan 100", client=g, asset=core)
        if_rt_xg10 = models.AssetInterface(asset=rt, name="xg-0/0/10", type="physical", description="LINK-PARA-SW-CORE-01")
        if_core_xg15 = models.AssetInterface(asset=core, name="XGigabitEthernet0/0/15", type="physical", description="LINK-PARA-RT-BORDA-01")
        vi_rt_100 = models.VlanInterface(vlan=v100_rt, interface=if_rt_xg10, mode="tagged")
        vi_core_100 = models.VlanInterface(vlan=v100_core, interface=if_core_xg15, mode="tagged")
        sub_rt = models.Subnet(network="172.16.0.0", mask=30, host_ip="172.16.0.1", description="P2P MPLS",
                               client=g, asset=rt, interface=if_rt_xg10)
        sub_core = models.Subnet(network="172.16.0.0", mask=30, host_ip="172.16.0.2", description="P2P MPLS",
                                 client=g, asset=core, interface=if_core_xg15)

        # ── VLAN 10 CLIENTES-PPPOE: atravessa core ↔ acesso (trunk) ──────────
        v10_core = models.Vlan(vid=10, name="CLIENTES-PPPOE", description="Banda larga PPPoE", vlan_type="routed",
                               config="vlan 10\n name CLIENTES-PPPOE\ninterface Vlanif10\n description GW Clientes PPPoE\n ip address 10.30.10.1 255.255.255.0", client=g, asset=core)
        v10_acc = models.Vlan(vid=10, name="CLIENTES-PPPOE", description="Banda larga PPPoE",
                              config="vlan 10\n name CLIENTES-PPPOE\ninterface ten-gigabit-ethernet-1/1/1\n switchport mode trunk\n switchport trunk allowed vlan add 10", client=g, asset=acc)
        if_core_xg1 = models.AssetInterface(asset=core, name="XGigabitEthernet0/0/1", type="physical", description="DOWNLINK-SW-ACESSO-01")
        if_acc_xg1 = models.AssetInterface(asset=acc, name="ten-gigabit-ethernet-1/1/1", type="physical", description="UPLINK-SW-CORE-01")
        vi_core_10 = models.VlanInterface(vlan=v10_core, interface=if_core_xg1, mode="trunk")
        vi_acc_10 = models.VlanInterface(vlan=v10_acc, interface=if_acc_xg1, mode="trunk")
        # SVI de gateway dos clientes no core
        if_core_svi = models.AssetInterface(asset=core, name="Vlanif10", type="vlan", description="GW Clientes PPPoE")
        vi_core_svi = models.VlanInterface(vlan=v10_core, interface=if_core_svi, mode="routed")
        sub_clientes = models.Subnet(network="10.30.10.0", mask=24, host_ip="10.30.10.1", description="Clientes PPPoE",
                                     client=g, asset=core, interface=if_core_svi)
        # Blocos extras para demonstrar aninhamento de IPs:
        # /29 dentro do /24 (contenção real) + dois /30 que geram um /24 agregado (inferido) + bloco público.
        sub_ger = models.Subnet(network="10.30.10.0", mask=29, host_ip="10.30.10.2", description="Gerência clientes",
                                client=g, asset=core)
        sub_p2p_a = models.Subnet(network="10.30.20.0", mask=30, host_ip="10.30.20.1", description="P2P core-acesso A",
                                  client=g, asset=core)
        sub_p2p_b = models.Subnet(network="10.30.20.4", mask=30, host_ip="10.30.20.5", description="P2P core-acesso B",
                                  client=g, asset=acc)
        sub_pub = models.Subnet(network="203.0.113.0", mask=29, host_ip="203.0.113.1", description="Bloco público",
                                client=g, asset=rt)

        # ── VLAN 200 GERENCIA: presente nos 3 (sem enlace inferível) ─────────
        v200_rt = models.Vlan(vid=200, name="GERENCIA", description="OOB mgmt",
                              config="vlan 200\n name GERENCIA\ninterface Loopback0\n description Mgmt\n ip address 10.20.0.1 255.255.255.255", client=g, asset=rt)
        v200_core = models.Vlan(vid=200, name="GERENCIA", description="OOB mgmt",
                                config="vlan 200\n name GERENCIA\ninterface MEth0/0/1\n description Mgmt", client=g, asset=core)
        v200_acc = models.Vlan(vid=200, name="GERENCIA", description="OOB mgmt",
                               config="vlan 200\n name GERENCIA\ninterface mgmt\n description Mgmt", client=g, asset=acc)
        if_rt_mgmt = models.AssetInterface(asset=rt, name="Loopback0", type="loopback", description="Mgmt", is_management=True)
        if_core_mgmt = models.AssetInterface(asset=core, name="MEth0/0/1", type="physical", description="Mgmt", is_management=True)
        if_acc_mgmt = models.AssetInterface(asset=acc, name="mgmt", type="physical", description="Mgmt", is_management=True)
        vi_rt_200 = models.VlanInterface(vlan=v200_rt, interface=if_rt_mgmt, mode="access")
        vi_core_200 = models.VlanInterface(vlan=v200_core, interface=if_core_mgmt, mode="access")
        vi_acc_200 = models.VlanInterface(vlan=v200_acc, interface=if_acc_mgmt, mode="access")

        db.add_all([
            g, rt, core, acc,
            v100_rt, v100_core, if_rt_xg10, if_core_xg15, vi_rt_100, vi_core_100, sub_rt, sub_core,
            v10_core, v10_acc, if_core_xg1, if_acc_xg1, vi_core_10, vi_acc_10,
            if_core_svi, vi_core_svi, sub_clientes,
            sub_ger, sub_p2p_a, sub_p2p_b, sub_pub,
            v200_rt, v200_core, v200_acc, if_rt_mgmt, if_core_mgmt, if_acc_mgmt,
            vi_rt_200, vi_core_200, vi_acc_200,
        ])
        await db.commit()
        print(f"[seed] '{DEMO_NAME}' criado: 3 ativos, VLANs 10/100/200, enlace /30 MPLS.")


if __name__ == "__main__":
    asyncio.run(main())
