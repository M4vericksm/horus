"""Testes dos drivers VSOL, FiberHome, ZTE e Intelbras (parsers de configs reais)."""
from drivers.vsol import VsolDriver
from drivers.fiberhome import FiberHomeDriver
from drivers.zte import ZteDriver
from drivers.intelbras import IntelbrasDriver

ZTE_CFG = """show running-config
Building configuration...
onu profile vlan 1040 tag-mode tag cvlan 1040 pri 7
onu profile vlan PPPOE tag-mode tag cvlan 122
vlan 100
"""

INTELBRAS_CFG = """intelbras-olt> show running-config
bridge add xeth 1 uplink vlan 2000 tagged
bridge add gpon 1 onu 1 downlink vlan 2001 tagged data eth 1
bridge add eth 1 downlink vlan 797 untagged
"""


def test_zte_parse_vlans_de_onu_profile_cvlan():
    d = ZteDriver(hostname="olt", ip="", user="", password="")
    vids = {v["id"] for v in d.parse_vlans(ZTE_CFG)}
    assert vids == {1040, 122, 100}


ZTE_MIM_CFG = """show startup-config
!<mim>
interface vlan748
service 1 gemport 1 vlan 266
vlan port eth_0/1 mode tag vlan 266
service-port 1 user-vlan 266 vlan 266
switchport vlan 266,748,800-803 tag
switchport vlan 851,890,4040 tag
"""


def test_zte_variante_mim_switchport_e_service():
    d = ZteDriver(hostname="olt", ip="", user="", password="")
    vids = {v["id"] for v in d.parse_vlans(ZTE_MIM_CFG)}
    assert vids == {266, 748, 800, 801, 802, 803, 851, 890, 4040}


def test_intelbras_parse_vlans_de_bridge_add():
    d = IntelbrasDriver(hostname="olt", ip="", user="", password="")
    vids = {v["id"] for v in d.parse_vlans(INTELBRAS_CFG)}
    assert vids == {2000, 2001, 797}


HUAWEI_OLT_CFG = """[MA5800V100R019C10]
#
vlan 100 to 102 smart
vlan 2022 smart
#
port vlan eth 1 translation 100 user-vlan 100
gem mapping 410 0 vlan 2022
gem mapping 101 0 vlan 1001
port vlan iphost translation 99 user-vlan 99
"""


def test_huawei_olt_parse_vlans_port_vlan_gem_smart():
    from drivers.huawei import HuaweiDriver
    d = HuaweiDriver(hostname="olt", ip="", user="", password="")
    vids = {v["id"] for v in d.parse_vlans(HUAWEI_OLT_CFG)}
    # vlan 100-102 + 2022 (smart) ; translation/user-vlan 100,99 ; gem vlan 2022,1001
    assert {100, 101, 102, 2022, 1001, 99}.issubset(vids)


def test_is_monitoring_host():
    from auto_discovery import _is_monitoring_host
    assert _is_monitoring_host("CLIENTE - GATEWAY - ZABBIX SERVER")
    assert _is_monitoring_host("X - GRAFANA")
    assert _is_monitoring_host("G5 WILL - LINUX - ZABBIX")
    assert not _is_monitoring_host("ISP EXEMPLO - CRS 317 CORE")


HILLSTONE_CFG = """show configuration
hostname "FW-01"
vlan 31
zone "trust"
zone "untrust"
interface aggregate1.90
 ip address 10.0.90.1/24
interface aggregate1.1001
 ip address 172.16.1.1 255.255.255.0
"""


def test_hillstone_parse_vlans_e_subnets():
    from drivers.hillstone import HillstoneDriver
    d = HillstoneDriver(hostname="fw", ip="", user="", password="")
    vids = {v["id"] for v in d.parse_vlans(HILLSTONE_CFG)}
    assert {31, 90, 1001}.issubset(vids)
    nets = {s["network"] for s in d.parse_subnets(HILLSTONE_CFG)}
    assert "10.0.90.0" in nets and "172.16.1.0" in nets

VSOL_CFG = """!
! hostname ISP-EXEMPLO
vlan 1
vlan 201 - 216
vlan 1000
vlan 4000
interface vlan 4000
 ip address 192.168.120.2/24
interface gigabitethernet 0/1
 switchport mode hybrid
 switchport hybrid vlan 4000 tagged
 switchport hybrid pvid vlan 1
"""

FH_CFG = """!WOS system config file
set manage vlan name GERENCIA vid 4000 inputport 19:1 tagged
set manage vlan name GERENCIA ip 10.40.39.7/28  10.40.39.1
set service VLAN3100 vid_begin 3100 vid_end 3100 uplink 19:1 tagged service_type 1
set service POOL vid_begin 3105 vid_end 3107 uplink 19:1 tagged service_type 1
"""


def test_vsol_parse_vlans_expande_ranges_e_ignora_interface_vlan():
    d = VsolDriver(hostname="olt", ip="", user="", password="")
    vids = {v["id"] for v in d.parse_vlans(VSOL_CFG)}
    # 1, 201..216 (16), 1000, 4000 = 19; 'interface vlan 4000' NÃO conta como definição nova
    assert 201 in vids and 216 in vids and 1000 in vids and 4000 in vids
    assert len(vids) == 19


def test_vsol_parse_subnets_da_interface_vlan():
    d = VsolDriver(hostname="olt", ip="", user="", password="")
    subs = d.parse_subnets(VSOL_CFG)
    s = next(x for x in subs if x["network"] == "192.168.120.0")
    assert s["mask"] == 24 and s["host_ip"] == "192.168.120.2"


def test_fiberhome_parse_vlans_service_e_manage():
    d = FiberHomeDriver(hostname="olt", ip="", user="", password="")
    vlans = {v["id"]: v for v in d.parse_vlans(FH_CFG)}
    assert set(vlans) == {4000, 3100, 3105, 3106, 3107}
    assert vlans[4000]["name"] == "GERENCIA"


def test_fiberhome_parse_subnets_manage_vlan_ip():
    d = FiberHomeDriver(hostname="olt", ip="", user="", password="")
    subs = d.parse_subnets(FH_CFG)
    assert len(subs) == 1
    assert subs[0]["network"] == "10.40.39.0" and subs[0]["mask"] == 28
    assert subs[0]["host_ip"] == "10.40.39.7"
