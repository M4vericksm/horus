"""Testes das funções de parse puras em auto_discovery.py."""
import pytest

from auto_discovery import (
    VENDOR_MARKERS,
    sanitize_filename,
    _mikrotik_ssh_port,
    _mikrotik_mgmt_ip,
    _huawei_mgmt,
    _cisco_family_mgmt,
    extract_connection_info,
    identify_vendor,
    detect_edge_router,
    get_category_weight,
)


# ──────────────────────────────────────────
# sanitize_filename
# ──────────────────────────────────────────

@pytest.mark.parametrize("entrada,esperado", [
    ("config.txt", "config.txt"),
    ("backup/with/slash", "backup_with_slash"),
    ("file:name?.txt", "file_name_.txt"),
    ('quoted"name', "quoted_name"),
    ("<script>alert(1)</script>", "_script_alert(1)__script_"),
])
def test_sanitize_filename(entrada, esperado):
    assert sanitize_filename(entrada) == esperado


def test_sanitize_filename_strips_whitespace():
    assert sanitize_filename("  arquivo.txt  ") == "arquivo.txt"


# ──────────────────────────────────────────
# _mikrotik_ssh_port
# ──────────────────────────────────────────

def test_mikrotik_ssh_port_default_22():
    assert _mikrotik_ssh_port("/system identity set name=router") == 22


def test_mikrotik_ssh_port_from_ip_service():
    config = "/ip service set ssh port=2222 disabled=no"
    assert _mikrotik_ssh_port(config) == 2222


def test_mikrotik_ssh_port_from_name_ssh():
    config = "name=ssh address=0.0.0.0/0 port=8222"
    assert _mikrotik_ssh_port(config) == 8222


# ──────────────────────────────────────────
# _mikrotik_mgmt_ip
# ──────────────────────────────────────────

def test_mikrotik_mgmt_ip_returns_none_when_no_addresses():
    assert _mikrotik_mgmt_ip("# config sem ip address") is None


def test_mikrotik_mgmt_ip_prefers_gerencia_comment():
    config = """
/ip address add address=10.1.1.1/24 interface=ether2 comment="WAN"
/ip address add address=192.168.99.1/24 interface=ether5 comment="GERENCIA"
"""
    assert _mikrotik_mgmt_ip(config) == "192.168.99.1"


def test_mikrotik_mgmt_ip_skips_loopback_and_link_local():
    config = """
/ip address add address=127.0.0.1/8 interface=lo
/ip address add address=169.254.1.1/16 interface=ether1
/ip address add address=10.0.0.5/24 interface=ether2 comment=GERENCIA
"""
    assert _mikrotik_mgmt_ip(config) == "10.0.0.5"


def test_mikrotik_mgmt_ip_falls_back_to_first_when_no_score():
    config = "/ip address add address=10.10.10.1/24 interface=ether10"
    assert _mikrotik_mgmt_ip(config) == "10.10.10.1"


# ──────────────────────────────────────────
# _huawei_mgmt
# ──────────────────────────────────────────

def test_huawei_mgmt_default_port_and_no_ip():
    ip, port = _huawei_mgmt("sysname ROUTER")
    assert ip is None
    assert port == 22


def test_huawei_mgmt_extracts_ip_and_custom_port():
    config = """
ssh server port 2202
interface Vlanif100
 ip address 10.5.5.1 255.255.255.0
"""
    ip, port = _huawei_mgmt(config)
    assert ip == "10.5.5.1"
    assert port == 2202


def test_huawei_mgmt_supports_prefix_length():
    config = """
interface Vlanif10
 ip address 172.16.1.1 24
"""
    ip, _ = _huawei_mgmt(config)
    assert ip == "172.16.1.1"


def test_huawei_mgmt_skips_blocked_ips():
    config = """
interface lo
 ip address 127.0.0.1 255.0.0.0
interface vlan10
 ip address 192.168.10.1 255.255.255.0
"""
    ip, _ = _huawei_mgmt(config)
    assert ip == "192.168.10.1"


# ──────────────────────────────────────────
# _cisco_family_mgmt
# ──────────────────────────────────────────

def test_cisco_mgmt_default_when_empty():
    ip, port = _cisco_family_mgmt("hostname R1")
    assert ip is None and port == 22


def test_cisco_mgmt_custom_ssh_port():
    config = "ip ssh port 2022 rotary 1\ninterface Loopback0\n ip address 10.1.1.1 255.255.255.255"
    ip, port = _cisco_family_mgmt(config)
    assert ip == "10.1.1.1"
    assert port == 2022


def test_cisco_mgmt_skips_secondary_addresses():
    config = """
interface Gig0/0
 ip address 10.0.0.2 255.255.255.0 secondary
 ip address 10.0.0.1 255.255.255.0
"""
    ip, _ = _cisco_family_mgmt(config)
    assert ip == "10.0.0.1"


# ──────────────────────────────────────────
# extract_connection_info (dispatcher)
# ──────────────────────────────────────────

def test_extract_connection_info_mikrotik():
    config = '/ip address add address=10.1.1.1/24 interface=ether1 comment=GERENCIA'
    ip, port = extract_connection_info(config, vendor="mikrotik")
    assert ip == "10.1.1.1"
    assert port == 22


def test_extract_connection_info_huawei():
    config = "interface vlan10\n ip address 10.2.2.2 24"
    ip, _ = extract_connection_info(config, vendor="huawei")
    assert ip == "10.2.2.2"


def test_extract_connection_info_cisco():
    config = "interface Gig0\n ip address 10.3.3.3 255.255.255.0"
    ip, _ = extract_connection_info(config, vendor="cisco")
    assert ip == "10.3.3.3"


def test_extract_connection_info_datacom_uses_cisco_family():
    config = "interface gigabit\n ip address 10.4.4.4 255.255.255.0"
    ip, _ = extract_connection_info(config, vendor="datacom")
    assert ip == "10.4.4.4"


def test_extract_connection_info_unknown_vendor_tries_all():
    config = "/ip address add address=10.9.9.9/24 interface=ether1 comment=mgmt"
    ip, _ = extract_connection_info(config, vendor=None)
    assert ip == "10.9.9.9"


# ──────────────────────────────────────────
# identify_vendor
# ──────────────────────────────────────────

@pytest.mark.parametrize("config,esperado", [
    ("display current-configuration\nsysname R1", "huawei"),
    ("aaa authentication-order radius local", "datacom"),
    ("tunnel-mac datacom 00:11:22:33:44:55", "datacom"),
    ("show running-config\nversion 15.2", "cisco"),
    ("/system identity set name=hap", "mikrotik"),
    ("/ip address add address=10.0.0.1/24", "mikrotik"),
    ("/interface vlan add name=vlan10 vlan-id=10", "mikrotik"),
    ("set system host-name R1\nset interfaces ge-0/0/0 unit 0", "juniper"),
    ("vlan 10\ninterface gigabitethernet 0/1\n switchport hybrid pvid vlan 1", "vsol"),
    ("!WOS system config file\nset service VLAN3100 vid_begin 3100 vid_end 3100", "fiberhome"),
    ("show running-config\nonu profile vlan 1040 tag-mode tag cvlan 1040 pri 7", "zte"),
    ("show startup-config\n!<mim>\nservice-port 1 user-vlan 266 vlan 266\nvlan port eth_0/1 mode tag", "zte"),
    ("intelbras-olt> show running-config\nbridge add xeth 1 uplink vlan 2000 tagged", "intelbras"),
    ("[MA5800V100R019]\ngem mapping 100 0 vlan 100\nport vlan eth 1 translation 100 user-vlan 100", "huawei"),
    ("/export terse\n[admin@MikroTik] >\n/interface bridge add name=bridge1", "mikrotik"),
    ('show configuration\nzone "untrust"\ninterface aggregate1.4002', "hillstone"),
    ("gibberish sem padrão conhecido", "unknown"),
])
def test_identify_vendor(config, esperado):
    assert identify_vendor(config) == esperado


def test_identify_vendor_priority_resolves_generic_echo():
    # O eco genérico 'show running-config' (marker cisco) NÃO deve mascarar a
    # assinatura específica do vendor: a prioridade resolve para o mais específico.
    assert identify_vendor("sysname R1\nshow running-config") == "huawei"
    assert identify_vendor("show running-config\naaa authentication-order local") == "datacom"
    assert identify_vendor("show running-config\nswitchport hybrid pvid vlan 1") == "vsol"


def test_identify_vendor_empty_returns_unknown():
    assert identify_vendor("") == "unknown"


def test_vendor_markers_table_vendors():
    assert set(VENDOR_MARKERS) == {
        "cisco", "datacom", "huawei", "mikrotik", "juniper",
        "vsol", "fiberhome", "zte", "intelbras", "hillstone",
    }


# ──────────────────────────────────────────
# detect_edge_router
# ──────────────────────────────────────────

@pytest.mark.parametrize("hostname,esperado", [
    ("BORDA-SP-01", True),
    ("router-core", True),
    ("aut-rj-1", True),
    ("gw-01", True),
    ("gateway-pe", True),
    ("ne8000-x16", True),
    ("ccr2004-router", True),
    ("switch-acesso-01", False),
    ("ap-wifi", False),
    ("olt-zte", False),
])
def test_detect_edge_router(hostname, esperado):
    assert detect_edge_router(hostname) is esperado


# ──────────────────────────────────────────
# get_category_weight
# ──────────────────────────────────────────

@pytest.mark.parametrize("categoria,peso", [
    ("borda", 10000),
    ("BORDA", 10000),
    ("autenticador", 8000),
    ("core", 6000),
    ("olt", 4000),
    ("acesso", 2000),
    ("desconhecido", 1000),
    ("", 1000),
])
def test_get_category_weight(categoria, peso):
    assert get_category_weight(categoria) == peso


# HuaweiDriver.extract_zip_config
import io
import zipfile as _zipfile

from drivers.huawei import HuaweiDriver
from exceptions import BCParseError


def _make_zip(files: dict[str, str]) -> bytes:
    """Cria um ZIP em memoria com os arquivos fornecidos {nome: conteudo}."""
    buf = io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_extract_zip_cfg_file():
    """ZIP com .cfg Huawei extrai texto e parseia VLANs."""
    cfg = "vlan 100\n name CORP\n#\nvlan 200\n name MGMT\n#"
    zip_bytes = _make_zip({"config.cfg": cfg})
    text = HuaweiDriver.extract_zip_config(zip_bytes)
    assert "vlan 100" in text
    vlans = HuaweiDriver("ne800", "192.0.2.1", "user", "pass").parse_vlans(text)
    ids = [v["id"] for v in vlans]
    assert 100 in ids and 200 in ids


def test_extract_zip_txt_file():
    """ZIP com .txt tambem deve ser extraido."""
    cfg = "vlan 300\n name TEST\n#"
    zip_bytes = _make_zip({"running-config.txt": cfg})
    text = HuaweiDriver.extract_zip_config(zip_bytes)
    assert "vlan 300" in text


def test_extract_zip_multiple_files():
    """ZIP com multiplos .cfg concatena tudo."""
    zip_bytes = _make_zip({
        "part1.cfg": "vlan 10\n name A\n#",
        "part2.cfg": "vlan 20\n name B\n#",
    })
    text = HuaweiDriver.extract_zip_config(zip_bytes)
    assert "vlan 10" in text and "vlan 20" in text


def test_extract_zip_no_cfg_raises():
    """ZIP sem .cfg/.txt deve levantar BCParseError."""
    zip_bytes = _make_zip({"readme.md": "irrelevante", "data.xml": "<root/>"})
    with pytest.raises(BCParseError):
        HuaweiDriver.extract_zip_config(zip_bytes)
