"""Mapeamento de rotas estáticas → blocos declarados, em TODOS os vendors.

Num provedor, o bloco delegado ao cliente muitas vezes existe apenas como rota
estática no equipamento de borda (não há IP dele em interface nossa). Se o driver
não captura a rota, o bloco fica invisível no inventário/IPAM.

Contrato verificado por vendor:
  - o prefixo vira {network, mask} correto;
  - a rota default (0.0.0.0/0) NUNCA entra (não é alocação);
  - `host_ip` é None em rota (só IP de interface preenche host_ip).
"""
import pytest

from drivers.cisco import CiscoDriver
from drivers.datacom import DatacomDriver
from drivers.hillstone import HillstoneDriver
from drivers.huawei import HuaweiDriver
from drivers.juniper import JuniperDriver
from drivers.mikrotik import MikrotikDriver


def _drv(cls):
    """Driver só para parse: os dados de conexão são exigidos pelo construtor
    mas não são usados ao parsear texto de config."""
    return cls(hostname="test", ip="192.168.0.1", user="admin", password="")

# Config mínima por vendor, no formato real de cada fabricante: um bloco de
# cliente + a rota default (que deve ser descartada).
CASOS = [
    pytest.param(
        _drv(CiscoDriver),
        """
        ip route 0.0.0.0 0.0.0.0 200.1.1.1
        ip route 192.168.10.0 255.255.255.0 10.1.1.2 name CLIENTE_ACME
        """,
        ("192.168.10.0", 24), id="cisco"),
    pytest.param(
        _drv(HuaweiDriver),
        """
        ip route-static 0.0.0.0 0.0.0.0 200.1.1.1
        ip route-static 192.168.10.0 255.255.255.0 10.1.1.2
        """,
        ("192.168.10.0", 24), id="huawei"),
    pytest.param(
        _drv(DatacomDriver),
        """
        ipv4 route 0.0.0.0/0 200.1.1.1
        ipv4 route 192.168.10.0/24 10.1.1.2
        """,
        ("192.168.10.0", 24), id="datacom"),
    pytest.param(
        _drv(JuniperDriver),
        """
        set routing-options static route 0.0.0.0/0 next-hop 200.1.1.1
        set routing-options static route 192.168.10.0/24 next-hop 10.1.1.2
        """,
        ("192.168.10.0", 24), id="juniper"),
    pytest.param(
        _drv(MikrotikDriver),
        """
        /ip route add distance=1 dst-address=0.0.0.0/0 gateway=200.1.1.1
        /ip route add distance=1 dst-address=192.168.10.0/24 gateway=10.1.1.2 comment="CLIENTE ACME"
        """,
        ("192.168.10.0", 24), id="mikrotik"),
    pytest.param(
        _drv(HillstoneDriver),
        """
        ip route 0.0.0.0/0 200.1.1.1
        ip route 192.168.10.0/24 10.1.1.2
        """,
        ("192.168.10.0", 24), id="hillstone"),
]


@pytest.mark.parametrize("driver,config,esperado", CASOS)
def test_rota_estatica_vira_bloco_declarado(driver, config, esperado):
    subnets = driver.parse_subnets(config)
    achados = {(s["network"], s["mask"]) for s in subnets}
    assert esperado in achados, f"{driver.__class__.__name__} não capturou a rota do cliente"


@pytest.mark.parametrize("driver,config,esperado", CASOS)
def test_rota_default_nunca_entra(driver, config, esperado):
    """0.0.0.0/0 não é bloco de alocação — poluiria o IPAM em todo equipamento."""
    subnets = driver.parse_subnets(config)
    assert not [s for s in subnets if s["network"] == "0.0.0.0"]


@pytest.mark.parametrize("driver,config,esperado", CASOS)
def test_rota_nao_preenche_host_ip(driver, config, esperado):
    """host_ip representa IP configurado localmente; rota não tem um."""
    subnets = driver.parse_subnets(config)
    rota = next(s for s in subnets if (s["network"], s["mask"]) == esperado)
    assert rota.get("host_ip") is None


# ── MikroTik: casos específicos do RouterOS ──────────────────────────────────

def test_mikrotik_formato_secao():
    """Export não-terse: '/ip route' abre seção e as linhas seguintes são 'add ...'."""
    cfg = """
/ip route
add distance=1 dst-address=172.20.0.0/22 gateway=10.9.9.1 comment="POP NORTE"
add distance=1 dst-address=0.0.0.0/0 gateway=200.1.1.1
/ip firewall filter
add action=accept chain=input dst-address=10.0.0.0/8
"""
    subnets = _drv(MikrotikDriver).parse_subnets(cfg)
    achados = {(s["network"], s["mask"]) for s in subnets}
    assert ("172.20.0.0", 22) in achados
    assert ("0.0.0.0", 0) not in achados
    # A linha de firewall tem dst-address mas não é rota: não pode virar bloco.
    assert ("10.0.0.0", 8) not in achados


def test_mikrotik_comment_vira_descricao():
    cfg = '/ip route add dst-address=192.168.50.0/24 gateway=10.1.1.9 comment="CLIENTE XPTO"'
    sub = _drv(MikrotikDriver).parse_subnets(cfg)[0]
    assert sub["description"] == "CLIENTE XPTO"


def test_mikrotik_sem_comment_usa_gateway():
    cfg = '/ip route add dst-address=192.168.60.0/24 gateway=10.1.1.9'
    sub = _drv(MikrotikDriver).parse_subnets(cfg)[0]
    assert "10.1.1.9" in sub["description"]


def test_mikrotik_rota_desabilitada_ignorada():
    """Rota desabilitada não é alocação ativa."""
    cfg = '/ip route add dst-address=192.168.70.0/24 gateway=10.1.1.9 disabled=yes'
    assert _drv(MikrotikDriver).parse_subnets(cfg) == []


def test_mikrotik_interface_e_rota_convivem():
    """O ganho não pode custar o comportamento antigo: IP de interface continua."""
    cfg = """
/ip address add address=10.1.1.1/24 comment="GERENCIA" interface=ether1 network=10.1.1.0
/ip route add dst-address=192.168.10.0/24 gateway=10.1.1.2 comment="CLIENTE"
"""
    subnets = _drv(MikrotikDriver).parse_subnets(cfg)
    por_rede = {s["network"]: s for s in subnets}
    assert por_rede["10.1.1.0"]["host_ip"] == "10.1.1.1"   # interface preserva host_ip
    assert por_rede["192.168.10.0"]["host_ip"] is None      # rota não tem host_ip
    assert len(subnets) == 2


def test_mikrotik_nao_duplica_bloco_ja_visto():
    """Mesmo bloco em interface e rota entra uma vez só."""
    cfg = """
/ip address add address=10.1.1.1/24 interface=ether1 network=10.1.1.0
/ip route add dst-address=10.1.1.0/24 gateway=10.9.9.9
"""
    assert len(_drv(MikrotikDriver).parse_subnets(cfg)) == 1
