"""Driver V-SOL / VSOL — OLTs GPON/EPON (CLI estilo switch).

Implementado a partir de configs reais de produção (jun/2026). Formato observado:
  vlan 1
  vlan 201 - 216            (ranges com espaços)
  vlan 4000
  interface vlan 4000
   ip address 192.168.120.2/24
  interface gigabitethernet 0/1
   switchport mode hybrid
   switchport hybrid vlan 4000 tagged
   switchport hybrid pvid vlan 1
"""
import ipaddress
import re
from .base import NetworkDriver


def _net_from(ip: str, mask) -> tuple:
    """Retorna (network, prefixlen) a partir de IP + máscara (CIDR int ou dotted)."""
    try:
        if isinstance(mask, str) and "." in mask:
            iface = ipaddress.ip_interface(f"{ip}/{ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen}")
        else:
            iface = ipaddress.ip_interface(f"{ip}/{int(mask)}")
        return str(iface.network.network_address), iface.network.prefixlen
    except Exception:
        return None, None


class VsolDriver(NetworkDriver):
    display_name = "V-SOL"
    vendor_key = "vsol"

    def get_ssh_command_setup(self) -> str:
        return ""

    def get_config_command(self) -> str:
        return "show running-config"

    def parse_vlans(self, config_text: str) -> list:
        vlans = {}
        for raw in config_text.splitlines():
            s = raw.strip()
            # Apenas definições 'vlan <id>' / 'vlan <a> - <b>' — NÃO 'interface vlan'.
            m = re.match(r'^vlan\s+(\d+)(?:\s*-\s*(\d+))?\s*$', s, re.I)
            if not m:
                continue
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            if hi < lo or hi - lo > 4094:
                hi = lo
            for vid in range(lo, hi + 1):
                vlans.setdefault(vid, {"id": vid, "name": f"VLAN_{vid}", "description": ""})
        return sorted(vlans.values(), key=lambda x: x["id"])

    def parse_subnets(self, config_text: str) -> list:
        subnets = []
        seen = set()
        cur_vlan = None
        for raw in config_text.splitlines():
            s = raw.strip()
            mi = re.match(r'^interface vlan\s+(\d+)', s, re.I)
            if mi:
                cur_vlan = mi.group(1)
                continue
            if re.match(r'^interface\b', s, re.I):
                cur_vlan = None
            m = re.match(r'^ip address\s+([\d.]+)\s*/\s*(\d+)', s, re.I) or \
                re.match(r'^ip address\s+([\d.]+)\s+([\d.]+)', s, re.I)
            if not m:
                continue
            ip, mask = m.group(1), m.group(2)
            if ip.startswith("127."):
                continue
            net, prefix = _net_from(ip, mask)
            if not net:
                continue
            key = f"{net}/{prefix}"
            if key in seen:
                continue
            seen.add(key)
            subnets.append({
                "network": net, "mask": prefix,
                "description": f"Vlan{cur_vlan}" if cur_vlan else "",
                "host_ip": ip,
            })
        return subnets

    def parse_device_info(self, config_text: str) -> dict:
        model = None
        m = re.search(r'!\s*Software Version\s*:\s*(\S+)', config_text, re.I)
        return {"model": m.group(1) if m else model, "serial_number": None}
