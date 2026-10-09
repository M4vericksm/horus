import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "drivers"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from drivers.juniper import JuniperDriver


def make_driver():
    return JuniperDriver(hostname="test", ip="192.168.0.1", user="admin", password="")


def test_parse_vlans_single_vlan():
    config = 'set vlans Users vlan-id 10\nset vlans Users description "Rede de usuarios"'

    result = make_driver().parse_vlans(config)

    assert result == [{"id": 10, "name": "Users", "description": "Rede de usuarios"}]


def test_parse_vlans_and_subnets_from_interfaces_and_static_routes():
    config = """
set vlans Voice vlan-id 20
set vlans Users vlan-id 10
set vlans Users description "Rede de usuarios"
set interfaces ge-0/0/0 unit 0 family inet address 10.20.30.1/24
set interfaces ge-0/0/1 unit 0 family inet address 172.16.5.1/30
set routing-options static route 192.168.50.0/24 next-hop 10.20.30.254
set routing-options static route 0.0.0.0/0 next-hop 10.20.30.254
"""

    vlans = make_driver().parse_vlans(config)
    subnets = make_driver().parse_subnets(config)

    assert [vlan["id"] for vlan in vlans] == [10, 20]
    assert vlans[0]["description"] == "Rede de usuarios"
    assert vlans[1]["description"] == "Voice"
    assert len(subnets) == 3
    assert {"network": "10.20.30.0", "mask": 24, "description": "Interface ge-0/0/0", "host_ip": "10.20.30.1"} in subnets
    assert {"network": "172.16.5.0", "mask": 30, "description": "Interface ge-0/0/1", "host_ip": "172.16.5.1"} in subnets
    assert {"network": "192.168.50.0", "mask": 24, "description": "Rota 192.168.50.0", "host_ip": None} in subnets


def test_parse_malformed_config_degrades_gracefully():
    config = "hostname sem formato junos\ninterface vlan 10"

    driver = make_driver()

    assert driver.parse_vlans(config) == []
    assert driver.parse_subnets(config) == []
    assert driver.parse_device_info(config) == {"model": None, "serial_number": None}


def test_parse_empty_config_degrades_gracefully():
    driver = make_driver()

    assert driver.parse_vlans("") == []
    assert driver.parse_subnets("") == []


def test_parse_device_info_model_best_effort():
    config = "## Model: MX204\nset system host-name BORDA-SP-01"

    assert make_driver().parse_device_info(config) == {"model": "MX204", "serial_number": None}
