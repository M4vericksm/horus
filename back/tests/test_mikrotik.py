"""
Testes para MikrotikDriver.parse_subnets.

Critérios de aceite:
- Prefixes /32 são incluídos (hosts individuais, loopbacks, blocos CGNAT têm valor de inventário)
- address=IP sem CIDR explícito é tratado como /32 (comportamento padrão do RouterOS)
- /128 continua filtrado (IPv6 host único, sem valor topológico)
- Prefixes /24, /30 continuam sendo extraídos normalmente
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "drivers"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from drivers.mikrotik import MikrotikDriver


def make_driver():
    return MikrotikDriver(hostname="test", ip="192.168.0.1", user="admin", password="")


class TestParseSubnetsFilter:
    def test_slash32_explicit_is_included(self):
        """RouterOS loopbacks com /32 explícito devem ser capturados."""
        config = (
            "/ip address add address=10.0.0.1/32 interface=loopback network=10.0.0.1\n"
        )
        result = make_driver().parse_subnets(config)
        assert len(result) == 1
        assert result[0]["network"] == "10.0.0.1"
        assert result[0]["mask"] == 32

    def test_slash32_implicit_no_cidr_is_included(self):
        """RouterOS às vezes exporta address=IP sem CIDR — deve ser tratado como /32."""
        config = (
            "/ip address add address=198.51.100.239 interface=Loopback-CGNAT-Bloco-78 "
            "network=198.51.100.239\n"
        )
        result = make_driver().parse_subnets(config)
        assert len(result) == 1
        assert result[0]["network"] == "198.51.100.239"
        assert result[0]["mask"] == 32

    def test_slash128_is_filtered(self):
        """IPv6 /128 (host único) deve permanecer filtrado."""
        config = (
            "/ip address add address=192.168.1.1/128 interface=lo network=192.168.1.1\n"
        )
        result = make_driver().parse_subnets(config)
        assert result == [], f"Esperava lista vazia, obteve: {result}"

    def test_slash24_is_included(self):
        config = (
            '/ip address add address=10.1.1.1/24 comment="GERENCIA" '
            "interface=ether1 network=10.1.1.0\n"
        )
        result = make_driver().parse_subnets(config)
        assert len(result) == 1
        assert result[0]["network"] == "10.1.1.0"
        assert result[0]["mask"] == 24
        assert result[0]["description"] == "GERENCIA"

    def test_slash30_is_included(self):
        config = (
            "/ip address add address=172.16.0.1/30 interface=ether2 network=172.16.0.0\n"
        )
        result = make_driver().parse_subnets(config)
        assert len(result) == 1
        assert result[0]["network"] == "172.16.0.0"
        assert result[0]["mask"] == 30

    def test_mixed_includes_slash32(self):
        """/32 deve aparecer junto com /24 e /30."""
        config = (
            "/ip address add address=10.0.0.1/32 interface=lo network=10.0.0.1\n"
            "/ip address add address=10.1.1.1/24 interface=ether1 network=10.1.1.0\n"
            "/ip address add address=10.2.2.1/30 interface=ether2 network=10.2.2.0\n"
            "/ip address add address=192.168.99.1/32 interface=dummy network=192.168.99.1\n"
        )
        result = make_driver().parse_subnets(config)
        masks = sorted(s["mask"] for s in result)
        assert masks == [24, 30, 32, 32]

    def test_cgnat_loopback_block_no_cidr(self):
        """Bloco de loopbacks CGNAT sem CIDR explícito: cada IP vira um /32."""
        lines = "\n".join(
            f"/ip address add address=198.51.100.{i} interface=Loopback-CGNAT network=198.51.100.{i}"
            for i in range(239, 244)
        )
        result = make_driver().parse_subnets(lines)
        assert len(result) == 5
        assert all(s["mask"] == 32 for s in result)

    def test_empty_config_returns_empty(self):
        assert make_driver().parse_subnets("") == []

    def test_no_ip_address_lines_returns_empty(self):
        config = "/interface vlan add interface=ether1 name=VLAN-10 vlan-id=10\n"
        assert make_driver().parse_subnets(config) == []


class TestMikrotikRouterOS7:
    def test_vlan_line_continuation(self):
        config = (
            "/interface vlan add interface=ether1 name=VLAN-100-CLIENTES \\\n"
            "    vlan-id=100\n"
        )

        result = make_driver().parse_vlans(config)

        assert result == [
            {"id": 100, "name": "VLAN-100-CLIENTES", "description": "VLAN-100-CLIENTES"}
        ]

    def test_ip_address_line_continuation(self):
        config = (
            '/ip address add address=10.1.1.1/24 comment="GERENCIA" \\\n'
            "    interface=ether1 network=10.1.1.0\n"
        )

        result = make_driver().parse_subnets(config)

        assert result == [{"network": "10.1.1.0", "mask": 24, "description": "GERENCIA", "host_ip": "10.1.1.1"}]

    def test_multiple_continuations_mixed(self):
        config = (
            "/interface vlan add interface=ether1 name=VLAN-100-CLIENTES \\\n"
            "    vlan-id=100\n"
            "/interface vlan add interface=ether1 name=VLAN-200-VOZ vlan-id=200\n"
            '/ip address add address=10.1.1.1/24 comment="GERENCIA" \\\n'
            "    interface=ether1 network=10.1.1.0\n"
            "/ip address add address=172.16.0.1/30 interface=ether2 network=172.16.0.0\n"
        )

        vlans = make_driver().parse_vlans(config)
        subnets = make_driver().parse_subnets(config)

        assert [vlan["id"] for vlan in vlans] == [100, 200]
        assert len(subnets) == 2
        assert {"network": "10.1.1.0", "mask": 24, "description": "GERENCIA", "host_ip": "10.1.1.1"} in subnets
        assert {"network": "172.16.0.0", "mask": 30, "description": "Interface ether2", "host_ip": "172.16.0.1"} in subnets

    def test_device_info_routeros7_header(self):
        config = (
            "# model = CCR2004-1G-12S+2XS\n"
            "# serial number = HAH0ABC1234\n"
            "# exported by RouterOS 7.6\n"
        )

        result = make_driver().parse_device_info(config)

        assert result == {"model": "CCR2004-1G-12S+2XS", "serial_number": "HAH0ABC1234"}

    def test_routeros6_no_continuation_unchanged(self):
        config = "/interface vlan add interface=ether1 name=VLAN-10 vlan-id=10\n"

        result = make_driver().parse_vlans(config)

        assert result == [{"id": 10, "name": "VLAN-10", "description": "VLAN-10"}]


class TestParseVlansBridgeAndSwitch:
    """Bridge VLAN filtering (lista/range) e chip de switch (RB2011/hEX)."""

    def test_bridge_vlan_ids_list_expands(self):
        config = "/interface bridge vlan add bridge=bridge1 tagged=ether1 vlan-ids=10,20,30 comment=CLIENTES\n"
        result = make_driver().parse_vlans(config)
        assert sorted(v["id"] for v in result) == [10, 20, 30]
        assert all(v["name"] == "CLIENTES" for v in result)

    def test_bridge_vlan_ids_range_expands(self):
        config = "/interface bridge vlan add bridge=bridge1 vlan-ids=100-103\n"
        result = make_driver().parse_vlans(config)
        assert sorted(v["id"] for v in result) == [100, 101, 102, 103]

    def test_bridge_combo_list_and_range(self):
        config = "/interface bridge vlan add bridge=bridge1 vlan-ids=10,20-22,30\n"
        result = make_driver().parse_vlans(config)
        assert sorted(v["id"] for v in result) == [10, 20, 21, 22, 30]

    def test_switch_chip_vlan_id(self):
        config = "/interface ethernet switch vlan add ports=ether2,ether3 switch=switch1 vlan-id=200\n"
        result = make_driver().parse_vlans(config)
        assert [v["id"] for v in result] == [200]

    def test_non_numeric_vlan_ids_ignored(self):
        config = "/interface bridge vlan add bridge=bridge1 vlan-ids=none\n"
        result = make_driver().parse_vlans(config)
        assert result == []

    def test_classic_vlan_interface_still_works(self):
        config = "/interface vlan add interface=ether1 name=VLAN-100-CLIENTES vlan-id=100\n"
        result = make_driver().parse_vlans(config)
        assert [v["id"] for v in result] == [100]
        assert result[0]["name"] == "VLAN-100-CLIENTES"
