"""Testes de network_logic.get_driver_class — dispatcher de driver por fabricante."""
import sys
import os

# Adiciona a raiz do repo ao path para que `from drivers.* import ...` funcione
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from network_logic import get_driver_class
from drivers.mikrotik import MikrotikDriver
from drivers.huawei import HuaweiDriver
from drivers.cisco import CiscoDriver
from drivers.datacom import DatacomDriver


def test_get_driver_class_mikrotik():
    assert get_driver_class("mikrotik") is MikrotikDriver


def test_get_driver_class_huawei():
    assert get_driver_class("huawei") is HuaweiDriver


def test_get_driver_class_cisco():
    assert get_driver_class("cisco") is CiscoDriver


def test_get_driver_class_datacom():
    assert get_driver_class("datacom") is DatacomDriver


def test_get_driver_class_is_case_insensitive():
    assert get_driver_class("MIKROTIK") is MikrotikDriver
    assert get_driver_class("Huawei") is HuaweiDriver


def test_get_driver_class_unknown_returns_dummy():
    """Vendor não suportado retorna DummyDriver de fallback (não levanta exceção)."""
    Driver = get_driver_class("unknown_vendor")
    assert Driver is not None
    instance = Driver()
    assert instance.parse_vlans("any config") == []
    assert instance.parse_subnets("any config") == []
    assert instance.parse_device_info("any config") == {"model": None, "serial_number": None}
