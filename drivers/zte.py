"""Driver ZTE — OLTs ZXA10 C300/C320/C600 (GPON/EPON).

Implementado a partir de configs reais de produção (jun/2026). Formato observado:
  onu profile vlan 1040 tag-mode tag cvlan 1040 pri 7
  onu profile vlan PPPOE tag-mode tag cvlan 122
As VLANs de serviço aparecem no 'cvlan'/'svlan' dos perfis de ONU; também há
definições diretas 'vlan <id>' / 'interface vlan <id>'.
"""
import ipaddress
import re
from .base import NetworkDriver


class ZteDriver(NetworkDriver):
    display_name = "ZTE"
    vendor_key = "zte"

    def get_ssh_command_setup(self) -> str:
        return "terminal length 0"

    def get_config_command(self) -> str:
        return "show running-config"

    def parse_vlans(self, config_text: str) -> list:
        vlans = {}

        def add(vid):
            try:
                vid = int(vid)
            except (TypeError, ValueError):
                return
            if 1 <= vid <= 4094:
                vlans.setdefault(vid, {"id": vid, "name": f"VLAN_{vid}", "description": ""})

        def expand(tok):
            # '266,748,800-847' -> 266, 748, 800..847
            for part in str(tok).split(','):
                part = part.strip()
                if '-' in part:
                    try:
                        lo, hi = part.split('-')
                        if int(hi) - int(lo) <= 4094:
                            for v in range(int(lo), int(hi) + 1):
                                add(v)
                    except ValueError:
                        add(part)
                elif part:
                    add(part)

        for raw in config_text.splitlines():
            s = raw.strip()
            low = s.lower()
            # 'switchport vlan 266,748,800-847 tag' (listas e ranges)
            m = re.match(r'^switchport vlan\s+([\d,\-]+)', s, re.I)
            if m:
                expand(m.group(1)); continue
            # 'interface vlan748' / 'interface vlan 748'
            m = re.match(r'^interface\s+vlan\s*(\d+)\b', s, re.I)
            if m:
                add(m.group(1)); continue
            # 'onu profile vlan <nome> tag-mode tag cvlan <id>'
            if 'onu profile vlan' in low or 'tag-mode' in low:
                for mm in re.finditer(r'\b(?:c?vlan|svlan)\s+(\d+)', s, re.I):
                    add(mm.group(1))
                continue
            # 'service-port ... user-vlan X vlan X' / 'service N gemport N vlan X' / 'vlan port eth_ ... vlan X'
            if re.search(r'\b(service-port|service\s+\d|vlan port|gemport)\b', s, re.I):
                for mm in re.finditer(r'\b(?:user-vlan|cvlan|svlan|vlan)\s+(\d+)', s, re.I):
                    add(mm.group(1))
                continue
            # 'svlan <id>' avulso e 'vlan <id>' (definição direta)
            for mm in re.finditer(r'\bsvlan\s+(\d+)', s, re.I):
                add(mm.group(1))
            m = re.match(r'^vlan\s+(\d+)\b', s, re.I)
            if m:
                add(m.group(1))
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
        m = re.search(r'\b(ZXA10\s*\S+|C3\d\d|C6\d\d)\b', config_text)
        return {"model": m.group(1).strip() if m else None, "serial_number": None}
