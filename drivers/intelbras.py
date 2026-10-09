"""Driver Intelbras — OLTs (linha OLT GPON, CLI 'intelbras-olt').

Implementado a partir de configs reais de produção (jun/2026). Formato observado:
  bridge add xeth 1 uplink vlan 2000 tagged
  bridge add gpon 1 onu 1 downlink vlan 2001 tagged data eth 1
  bridge add eth 1 downlink vlan 797 untagged
As VLANs de serviço aparecem nas linhas 'bridge add ... vlan <id>'.
"""
import ipaddress
import re
from .base import NetworkDriver


class IntelbrasDriver(NetworkDriver):
    display_name = "Intelbras"
    vendor_key = "intelbras"

    def get_ssh_command_setup(self) -> str:
        return "screen-length 0 temporary"

    def get_config_command(self) -> str:
        return "show running-config"

    def parse_vlans(self, config_text: str) -> list:
        vlans = {}
        for raw in config_text.splitlines():
            s = raw.strip()
            if not re.match(r'^bridge\b', s, re.I):
                # tambem aceita 'vlan <id>' / 'interface vlan <id>' diretos, se houver
                m = re.match(r'^(?:interface\s+)?vlan\s+(\d+)\b', s, re.I)
                if not m:
                    continue
                vid = int(m.group(1))
            else:
                m = re.search(r'\bvlan\s+(\d+)\b', s, re.I)
                if not m:
                    continue
                vid = int(m.group(1))
            if 1 <= vid <= 4094:
                vlans.setdefault(vid, {"id": vid, "name": f"VLAN_{vid}", "description": ""})
        return sorted(vlans.values(), key=lambda x: x["id"])

    def parse_subnets(self, config_text: str) -> list:
        subnets, seen = [], set()
        for raw in config_text.splitlines():
            s = raw.strip()
            m = re.match(r'^ip address\s+([\d.]+)\s*/\s*(\d+)', s, re.I) or \
                re.match(r'^ip address\s+([\d.]+)\s+([\d.]+)', s, re.I)
            if not m:
                continue
            ip, mask = m.group(1), m.group(2)
            if ip.startswith("127."):
                continue
            try:
                pfx = ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen if '.' in str(mask) else int(mask)
                net = str(ipaddress.ip_interface(f"{ip}/{pfx}").network.network_address)
            except Exception:
                continue
            key = f"{net}/{pfx}"
            if key in seen:
                continue
            seen.add(key)
            subnets.append({"network": net, "mask": pfx, "description": "", "host_ip": ip})
        return subnets

    def parse_device_info(self, config_text: str) -> dict:
        return {"model": None, "serial_number": None}
