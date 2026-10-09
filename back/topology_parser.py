"""
topology_parser.py — Parser de Interfaces de Rede por Fabricante
=================================================================
Módulo independente responsável por extrair dados topológicos a partir
do texto raw de configuração de equipamentos de rede.

Não altera o comportamento dos drivers existentes (cisco.py, huawei.py,
mikrotik.py, datacom.py). É chamado por auto_discovery.py após o parse
convencional de VLANs e Subnets.

Retorno de parse_interfaces():
    [
        {
            "name": "GigabitEthernet0/1",
            "type": "physical",          # physical | vlan | bridge | lag | loopback | tunnel | unknown
            "description": "Uplink SW-CORE",
            "is_management": False,       # True se este IF carrega o IP de gerência do ativo
            "vlans": [
                {"vid": 100, "mode": "trunk"},
                {"vid": 200, "mode": "access"}
            ],
            "ip_address": "10.1.1.1",    # None se não houver IP configurado
            "mask": 24                   # None se não houver IP configurado
        },
        ...
    ]
"""
import re
from logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# Utilitários
# ─────────────────────────────────────────────────────────────────────────────

def _mask_to_cidr(mask_str: str) -> int:
    """Converte '255.255.255.0' para 24."""
    try:
        return sum(bin(int(x)).count('1') for x in mask_str.split('.'))
    except Exception:
        return 32


def _expand_vlan_range(vlan_str: str) -> list[int]:
    """
    Expande strings de VLAN como '10,20-30,100' em lista de inteiros.
    Usado para trunk allowed vlan (Cisco/Huawei) e port trunk allow-pass vlan (Huawei).
    """
    result = []
    for part in vlan_str.replace(' ', '').split(','):
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                result.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                result.append(int(part))
            except ValueError:
                continue
    return result


_SKIP_IP = re.compile(r'^(127\.|0\.|255\.|224\.|169\.254\.|0\.0\.0\.0)')


def _classify_interface_type(name: str) -> str:
    """Classifica o tipo de interface pelo prefixo do nome."""
    n = name.lower()
    if any(n.startswith(p) for p in ('loopback', 'lo')):
        return 'loopback'
    if any(n.startswith(p) for p in ('vlan', 'vlanif', 'vl')):
        return 'vlan'
    if any(n.startswith(p) for p in ('bridge', 'br')):
        return 'bridge'
    # Sub-interfaces (ex: Eth-Trunk0.202, GigabitEthernet0/1.100)
    if re.search(r'\.\d+$', n):
        return 'subinterface'
    # LAG: Huawei (Eth-Trunk) + padrões genéricos
    if any(n.startswith(p) for p in ('port-channel', 'po', 'ae', 'bond', 'lag', 'eth-trunk')):
        return 'lag'
    if any(n.startswith(p) for p in ('tunnel', 'tun')):
        return 'tunnel'
    return 'physical'


# ─────────────────────────────────────────────────────────────────────────────
# Parser MikroTik (RouterOS /export terse)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_mikrotik(config_text: str, mgmt_ip: str | None = None) -> list[dict]:
    """
    Extrai interfaces de um config RouterOS no formato /export terse.

    Fluxo:
    1. Lê /interface ethernet add para interfaces físicas.
    2. Lê /interface vlan add para VLAN interfaces (guarda parent interface).
    3. Lê /interface bridge port add para associar portas físicas a bridges.
    4. Lê /ip address add para descobrir IPs por interface.
    """
    interfaces: dict[str, dict] = {}

    # ── 1. Interfaces físicas (ethernet) ─────────────────────────────────────
    # /interface ethernet set [ find default-name=ether1 ] name=WAN comment="Uplink"
    for m in re.finditer(
        r'/interface ethernet set[^\n]*name=(["\']?)(\S+)\1[^\n]*(?:comment=(["\']?)([^\s"\']+)\3)?',
        config_text, re.IGNORECASE
    ):
        name = m.group(2).strip()
        desc = (m.group(4) or '').strip() or None
        if name and name not in interfaces:
            interfaces[name] = {
                'name': name,
                'type': 'physical',
                'description': desc,
                'is_management': False,
                'vlans': [],
                'ip_address': None,
                'mask': None,
            }

    # /interface ethernet add name=ether2 comment="LAN"
    for m in re.finditer(
        r'/interface ethernet add[^\n]*name=(["\']?)(\S+)\1[^\n]*(?:comment=(["\']?)([^\s"\']+)\3)?',
        config_text, re.IGNORECASE
    ):
        name = m.group(2).strip()
        desc = (m.group(4) or '').strip() or None
        if name and name not in interfaces:
            interfaces[name] = {
                'name': name,
                'type': 'physical',
                'description': desc,
                'is_management': False,
                'vlans': [],
                'ip_address': None,
                'mask': None,
            }

    # ── 2. VLAN interfaces ───────────────────────────────────────────────────
    # /interface vlan add interface=ether2 name=VLAN-100-CLIENTES vlan-id=100
    for m in re.finditer(
        r'/interface vlan add[^\n]*\binterface=(["\']?)(\S+)\1[^\n]*\bvlan-id=(\d+)',
        config_text, re.IGNORECASE
    ):
        parent = m.group(2).strip()
        vid = int(m.group(3))
        # Busca o name= da mesma linha
        nm = re.search(r'\bname=(["\']?)(\S+)\1', m.group(0))
        vlan_if_name = nm.group(2).strip() if nm else f'vlan{vid}'

        # Registra a VLAN interface
        if vlan_if_name not in interfaces:
            interfaces[vlan_if_name] = {
                'name': vlan_if_name,
                'type': 'vlan',
                'description': None,
                'is_management': False,
                'vlans': [{'vid': vid, 'mode': 'tagged'}],
                'ip_address': None,
                'mask': None,
            }

        # Também marca a VLAN como passando pela interface pai
        if parent not in interfaces:
            interfaces[parent] = {
                'name': parent,
                'type': _classify_interface_type(parent),
                'description': None,
                'is_management': False,
                'vlans': [],
                'ip_address': None,
                'mask': None,
            }
        # Evita duplicata de VLAN na mesma interface
        existing_vids = [v['vid'] for v in interfaces[parent]['vlans']]
        if vid not in existing_vids:
            interfaces[parent]['vlans'].append({'vid': vid, 'mode': 'trunk'})

    # ── 3. Bridge ports ──────────────────────────────────────────────────────
    # /interface bridge port add bridge=bridge1 interface=ether3
    for m in re.finditer(
        r'/interface bridge port add[^\n]*\bbridge=(["\']?)(\S+)\1[^\n]*\binterface=(["\']?)(\S+)\3',
        config_text, re.IGNORECASE
    ):
        bridge = m.group(2).strip()
        port = m.group(4).strip()
        if bridge not in interfaces:
            interfaces[bridge] = {
                'name': bridge,
                'type': 'bridge',
                'description': None,
                'is_management': False,
                'vlans': [],
                'ip_address': None,
                'mask': None,
            }
        if port not in interfaces:
            interfaces[port] = {
                'name': port,
                'type': 'physical',
                'description': None,
                'is_management': False,
                'vlans': [],
                'ip_address': None,
                'mask': None,
            }

    # ── 4. IPs por interface ──────────────────────────────────────────────────
    # /ip address add address=10.1.1.1/24 interface=ether1 network=10.1.1.0
    for m in re.finditer(
        r'/ip address add[^\n]*\baddress=(["\']?)([\d.]+)(?:/(\d+))?\1[^\n]*\binterface=(["\']?)(\S+)\4',
        config_text, re.IGNORECASE
    ):
        ip = m.group(2).strip()
        cidr = int(m.group(3)) if m.group(3) else 32
        iface = m.group(5).strip()
        if _SKIP_IP.match(ip):
            continue
        if iface not in interfaces:
            interfaces[iface] = {
                'name': iface,
                'type': _classify_interface_type(iface),
                'description': None,
                'is_management': False,
                'vlans': [],
                'ip_address': None,
                'mask': None,
            }
        if interfaces[iface]['ip_address'] is None:
            interfaces[iface]['ip_address'] = ip
            interfaces[iface]['mask'] = cidr
        if mgmt_ip and ip == mgmt_ip:
            interfaces[iface]['is_management'] = True

    return list(interfaces.values())


# ─────────────────────────────────────────────────────────────────────────────
# Parser Cisco / Datacom (show running-config)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cisco_family(config_text: str, mgmt_ip: str | None = None) -> list[dict]:
    """
    Extrai interfaces de configs no estilo Cisco IOS / IOS-XE / Datacom DmOS.

    Blocos de interface:
        interface GigabitEthernet0/1
          description Uplink SW-CORE
          switchport mode trunk
          switchport trunk allowed vlan 100,200-300
          ip address 10.1.1.1 255.255.255.0
        !

    Também suporta 'channel-group' (LAG) e subinterfaces (GigabitEthernet0/1.100).
    """
    interfaces: list[dict] = []
    current: dict | None = None

    for raw_line in config_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        # ── Início do bloco de interface ──────────────────────────────────────
        m_if = re.match(r'^interface\s+(\S+)', line)
        if m_if:
            if current:
                interfaces.append(current)
            if_name = m_if.group(1)
            # Vlan<N> (SVI Cisco/Datacom): auto-popula VID sem depender de switchport commands
            initial_vlans: list[dict] = []
            m_vlan_svi = re.match(r'^[Vv]lan(\d+)$', if_name)
            if m_vlan_svi:
                initial_vlans = [{'vid': int(m_vlan_svi.group(1)), 'mode': 'routed'}]
            current = {
                'name': if_name,
                'type': _classify_interface_type(if_name),
                'description': None,
                'is_management': False,
                'vlans': initial_vlans,
                'ip_address': None,
                'mask': None,
            }
            continue

        if current is None:
            continue

        # ── Fim do bloco (linha sem indentação que não é 'interface') ─────────
        if line and not line.startswith(' ') and not line.startswith('!'):
            interfaces.append(current)
            current = None
            continue

        # ── Atributos dentro do bloco ─────────────────────────────────────────

        # description
        m_desc = re.match(r'\s+description\s+(.+)', line)
        if m_desc:
            current['description'] = m_desc.group(1).strip()
            continue

        # switchport access vlan <id>
        m_access = re.match(r'\s+switchport\s+access\s+vlan\s+(\d+)', line, re.IGNORECASE)
        if m_access:
            vid = int(m_access.group(1))
            if not any(v['vid'] == vid for v in current['vlans']):
                current['vlans'].append({'vid': vid, 'mode': 'access'})
            continue

        # switchport trunk allowed vlan <range>
        m_trunk = re.match(r'\s+switchport\s+trunk\s+allowed\s+vlan\s+(?:add\s+)?(.+)', line, re.IGNORECASE)
        if m_trunk:
            for vid in _expand_vlan_range(m_trunk.group(1)):
                if not any(v['vid'] == vid for v in current['vlans']):
                    current['vlans'].append({'vid': vid, 'mode': 'trunk'})
            continue

        # switchport trunk native vlan <id>
        m_native = re.match(r'\s+switchport\s+trunk\s+native\s+vlan\s+(\d+)', line, re.IGNORECASE)
        if m_native:
            vid = int(m_native.group(1))
            if not any(v['vid'] == vid for v in current['vlans']):
                current['vlans'].append({'vid': vid, 'mode': 'native'})
            continue

        # ip address <ip> <mask>
        m_ip = re.match(r'\s+ip\s+address\s+([\d.]+)\s+([\d.]+)', line, re.IGNORECASE)
        if m_ip:
            ip = m_ip.group(1)
            cidr = _mask_to_cidr(m_ip.group(2))
            if not _SKIP_IP.match(ip) and current['ip_address'] is None:
                current['ip_address'] = ip
                current['mask'] = cidr
                if mgmt_ip and ip == mgmt_ip:
                    current['is_management'] = True
            continue

        # encapsulation dot1Q <vid>  (subinterface)
        m_dot1q = re.match(r'\s+encapsulation\s+dot1[qQ]\s+(\d+)', line)
        if m_dot1q:
            vid = int(m_dot1q.group(1))
            if not any(v['vid'] == vid for v in current['vlans']):
                current['vlans'].append({'vid': vid, 'mode': 'tagged'})
            continue

    if current:
        interfaces.append(current)

    return interfaces


# ─────────────────────────────────────────────────────────────────────────────
# Parser Huawei VRP (display current-configuration)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_huawei(config_text: str, mgmt_ip: str | None = None) -> list[dict]:
    """
    Extrai interfaces de configs Huawei VRP.

    Blocos de interface:
        interface GigabitEthernet0/0/1
         description Uplink-CORE
         port link-type trunk
         port trunk allow-pass vlan 100 200 to 300
         ip address 10.1.1.1 255.255.255.0
        #

    Também suporta:
    - port default vlan <id>   (access)
    - port hybrid pvid vlan <id>  (native)
    - port hybrid tagged vlan <range>
    - Vlanif<id> interfaces (SVI)
    """
    interfaces: list[dict] = []
    current: dict | None = None

    for raw_line in config_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        # ── Início do bloco de interface ──────────────────────────────────────
        m_if = re.match(r'^interface\s+(\S+)', line)
        if m_if:
            if current:
                interfaces.append(current)
            if_name = m_if.group(1)
            # Vlanif<N>: auto-popula o VID sem depender de linha de config adicional
            initial_vlans: list[dict] = []
            m_vlanif = re.match(r'^[Vv]lanif(\d+)$', if_name)
            if m_vlanif:
                initial_vlans = [{'vid': int(m_vlanif.group(1)), 'mode': 'routed'}]
            current = {
                'name': if_name,
                'type': _classify_interface_type(if_name),
                'description': None,
                'is_management': False,
                'vlans': initial_vlans,
                'ip_address': None,
                'mask': None,
            }
            continue

        if current is None:
            continue

        # ── Fim do bloco (#) ─────────────────────────────────────────────────
        if stripped == '#':
            interfaces.append(current)
            current = None
            continue

        # ── Atributos dentro do bloco ─────────────────────────────────────────

        # description
        m_desc = re.match(r'\s+description\s+(.+)', line)
        if m_desc:
            current['description'] = m_desc.group(1).strip()
            continue

        # port link-type (informativo — classifica modo padrão do IF)
        # Não altera estrutura de dados, apenas contexto

        # port default vlan <id>  (access)
        m_access = re.match(r'\s+port\s+default\s+vlan\s+(\d+)', line, re.IGNORECASE)
        if m_access:
            vid = int(m_access.group(1))
            if not any(v['vid'] == vid for v in current['vlans']):
                current['vlans'].append({'vid': vid, 'mode': 'access'})
            continue

        # port trunk allow-pass vlan <range>
        m_trunk = re.match(r'\s+port\s+trunk\s+allow-pass\s+vlan\s+(.+)', line, re.IGNORECASE)
        if m_trunk:
            # Huawei usa espaços: "100 200 300" ou "100 to 300"
            raw = m_trunk.group(1).strip()
            # Normaliza "to" → "-" para reutilizar _expand_vlan_range
            raw_norm = re.sub(r'\s+to\s+', '-', raw, flags=re.IGNORECASE)
            raw_norm = raw_norm.replace(' ', ',')
            for vid in _expand_vlan_range(raw_norm):
                if vid != 1 and not any(v['vid'] == vid for v in current['vlans']):
                    current['vlans'].append({'vid': vid, 'mode': 'trunk'})
            continue

        # port hybrid tagged vlan <range>
        m_hybrid = re.match(r'\s+port\s+hybrid\s+tagged\s+vlan\s+(.+)', line, re.IGNORECASE)
        if m_hybrid:
            raw = m_hybrid.group(1).strip()
            raw_norm = re.sub(r'\s+to\s+', '-', raw, flags=re.IGNORECASE)
            raw_norm = raw_norm.replace(' ', ',')
            for vid in _expand_vlan_range(raw_norm):
                if not any(v['vid'] == vid for v in current['vlans']):
                    current['vlans'].append({'vid': vid, 'mode': 'tagged'})
            continue

        # port hybrid pvid vlan <id>  (native/untagged)
        m_pvid = re.match(r'\s+port\s+hybrid\s+pvid\s+vlan\s+(\d+)', line, re.IGNORECASE)
        if m_pvid:
            vid = int(m_pvid.group(1))
            if not any(v['vid'] == vid for v in current['vlans']):
                current['vlans'].append({'vid': vid, 'mode': 'native'})
            continue

        # ip address <ip> <mask>
        m_ip = re.match(r'\s+ip\s+address\s+([\d.]+)\s+([\d.]+)', line, re.IGNORECASE)
        if m_ip:
            ip = m_ip.group(1)
            cidr = _mask_to_cidr(m_ip.group(2))
            if not _SKIP_IP.match(ip) and current['ip_address'] is None:
                current['ip_address'] = ip
                current['mask'] = cidr
                if mgmt_ip and ip == mgmt_ip:
                    current['is_management'] = True
            continue

        # dot1q termination vid <id>  (sub-interface Huawei — equivalente ao encapsulation dot1Q Cisco)
        m_dot1q = re.match(r'\s+dot1q\s+termination\s+vid\s+(\d+)', line, re.IGNORECASE)
        if m_dot1q:
            vid = int(m_dot1q.group(1))
            if not any(v['vid'] == vid for v in current['vlans']):
                current['vlans'].append({'vid': vid, 'mode': 'tagged'})
            continue

    if current:
        interfaces.append(current)

    return interfaces


# ─────────────────────────────────────────────────────────────────────────────────
# Parser Juniper JunOS (display set)
# ─────────────────────────────────────────────────────────────────────────────────

def _parse_juniper(config_text: str, mgmt_ip: str | None = None) -> list[dict]:
    """
    Extrai interfaces de configs Juniper JunOS (formato 'display set').

    Cada 'unit' vira uma sub-interface lógica: ae0.100 para 'ae0 unit 100'.

    Padrões suportados:
        set interfaces ae0 unit 100 vlan-id 100
        set interfaces ae0 unit 100 family inet address 10.1.1.1/30
        set interfaces ae0 unit 100 description "PTP-CLIENTE"
        set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members MGMT
        set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk
    """
    # mapa de vlan-name -> vid (para resolver 'vlan members <nome>')
    vlan_name_to_vid: dict[str, int] = {}
    for line in config_text.splitlines():
        m = re.match(r'^set\s+vlans\s+(\S+)\s+vlan-id\s+(\d+)', line.strip(), re.IGNORECASE)
        if m:
            vlan_name_to_vid[m.group(1).strip('"')] = int(m.group(2))

    # mapa de (phys, unit) -> dict de interface
    units: dict[tuple, dict] = {}

    for line in config_text.splitlines():
        line = line.strip()
        if not line.startswith('set interfaces '):
            continue
        m = re.match(r'^set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+(.*)', line, re.IGNORECASE)
        if not m:
            continue
        phys, unit, rest = m.group(1), int(m.group(2)), m.group(3).strip()
        key = (phys, unit)
        if key not in units:
            logical_name = f'{phys}.{unit}' if unit > 0 else phys
            units[key] = {
                'name': logical_name,
                'type': _classify_interface_type(logical_name),
                'description': None,
                'is_management': False,
                'vlans': [],
                'ip_address': None,
                'mask': None,
            }
        u = units[key]

        # vlan-id <N>  (sub-interface L3)
        m_vid = re.match(r'^vlan-id\s+(\d+)', rest, re.IGNORECASE)
        if m_vid:
            vid = int(m_vid.group(1))
            if not any(v['vid'] == vid for v in u['vlans']):
                u['vlans'].append({'vid': vid, 'mode': 'tagged'})
            continue

        # family inet address <ip>/<mask>  (IP configurado na unidade)
        m_ip = re.match(r'^family\s+inet\s+address\s+([\d.]+)/(\d+)', rest, re.IGNORECASE)
        if m_ip:
            ip, cidr = m_ip.group(1), int(m_ip.group(2))
            if not _SKIP_IP.match(ip) and u['ip_address'] is None:
                u['ip_address'] = ip
                u['mask'] = cidr
                if mgmt_ip and ip == mgmt_ip:
                    u['is_management'] = True
            continue

        # description
        m_desc = re.match(r'^description\s+(.+)', rest, re.IGNORECASE)
        if m_desc:
            u['description'] = m_desc.group(1).strip().strip('"')
            continue

        # family ethernet-switching vlan members <nome-ou-vid>  (switch port)
        m_esw = re.match(r'^family\s+ethernet-switching\s+vlan\s+members\s+(\S+)', rest, re.IGNORECASE)
        if m_esw:
            member = m_esw.group(1).strip('"')
            try:
                vid = int(member)
            except ValueError:
                vid = vlan_name_to_vid.get(member)
            if vid is not None and not any(v['vid'] == vid for v in u['vlans']):
                u['vlans'].append({'vid': vid, 'mode': 'trunk'})
            continue

        # family ethernet-switching interface-mode trunk|access
        m_mode = re.match(r'^family\s+ethernet-switching\s+interface-mode\s+(\S+)', rest, re.IGNORECASE)
        if m_mode:
            mode_val = 'access' if m_mode.group(1).lower() == 'access' else 'trunk'
            for vlan in u['vlans']:
                if vlan['mode'] not in ('tagged',):  # preserva vlan-id explícito
                    vlan['mode'] = mode_val
            continue

    return list(units.values())


# ─────────────────────────────────────────────────────────────────────────────
# Ponto de entrada público
# ─────────────────────────────────────────────────────────────────────────────

def parse_interfaces(config_text: str, vendor: str, mgmt_ip: str | None = None) -> list[dict]:
    """
    Extrai a lista de interfaces de um texto de configuração.

    Args:
        config_text: Texto raw da configuração do equipamento.
        vendor:      Fabricante identificado pelo identify_vendor() em auto_discovery.py
                     ('mikrotik', 'cisco', 'datacom', 'huawei', 'unknown').
        mgmt_ip:     IP de gerência do ativo (usado para marcar is_management=True
                     na interface que o carrega).

    Returns:
        Lista de dicts com a estrutura descrita no docstring do módulo.
        Retorna [] em caso de erro — nunca propaga exceção.
    """
    v = (vendor or '').strip().lower()
    try:
        if v == 'mikrotik':
            result = _parse_mikrotik(config_text, mgmt_ip)
        elif v in ('cisco', 'datacom'):
            result = _parse_cisco_family(config_text, mgmt_ip)
        elif v == 'huawei':
            result = _parse_huawei(config_text, mgmt_ip)
        elif v == 'juniper':
            result = _parse_juniper(config_text, mgmt_ip)
        else:
            logger.debug(f'[topology_parser] Vendor "{vendor}" sem parser de interfaces. Retornando [].')
            return []

        logger.info(f'[topology_parser] {len(result)} interfaces extraídas para vendor={vendor}.')
        return result

    except Exception as e:
        logger.warning(f'[topology_parser] Erro ao parsear interfaces para vendor={vendor}: {e}')
        return []
