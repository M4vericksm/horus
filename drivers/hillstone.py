"""Driver Hillstone (firewall StoneOS).

Implementado a partir de configs reais de produção (jun/2026). Formato observado:
  vlan 31
  interface aggregate1.4002    (o sufixo após o '.' é o VLAN-id da sub-interface)
   ip address 10.0.0.1/30
  zone "trust" / zone "untrust"
"""
import ipaddress
import re
from .base import NetworkDriver


class HillstoneDriver(NetworkDriver):
    display_name = "Hillstone StoneOS"
    vendor_key = "hillstone"

    def get_ssh_command_setup(self) -> str:
        return "terminal length 0"

    def get_config_command(self) -> str:
        return "show configuration"

    def parse_vlans(self, config_text: str) -> list:
        vlans = {}

        def add(vid, name=None):
            if 1 <= vid <= 4094:
                cur = vlans.get(vid)
                if cur is None:
                    vlans[vid] = {"id": vid, "name": name or f"VLAN_{vid}", "description": name or ""}
                elif name and str(cur["name"]).startswith("VLAN_"):
                    cur["name"] = name
                    cur["description"] = name

        for raw in config_text.splitlines():
            s = raw.strip()
            m = re.match(r'^vlan\s+(\d+)\b', s, re.I)
            if m:
                add(int(m.group(1))); continue
            # sub-interface: 'interface aggregate1.4002' / 'interface ethernet0/1.100'
            m = re.match(r'^interface\s+\S+\.(\d+)\b', s, re.I)
            if m:
                add(int(m.group(1)))
        return sorted(vlans.values(), key=lambda x: x["id"])

    def parse_subnets(self, config_text: str) -> list:
        subnets, seen = [], set()
        cur_vlan = None
        for raw in config_text.splitlines():
            s = raw.strip()
            mi = re.match(r'^interface\s+\S+\.(\d+)\b', s, re.I)
            if mi:
                cur_vlan = mi.group(1)
            elif re.match(r'^interface\b', s, re.I):
                cur_vlan = None
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
            subnets.append({"network": net, "mask": pfx,
                            "description": f"Vlan{cur_vlan}" if cur_vlan else "", "host_ip": ip})

        # Rotas estáticas do vrouter: num firewall de borda é onde ficam os blocos
        # encaminhados a clientes, que não aparecem como IP de interface.
        # Formato Hillstone: `ip route <rede>/<cidr> <gateway|interface>`.
        for raw in config_text.splitlines():
            s = raw.strip()
            m = re.match(r'^ip route\s+([\d.]+)/(\d+)(?:\s+(\S+))?', s, re.I)
            if not m:
                continue
            net, pfx, gw = m.group(1), int(m.group(2)), m.group(3)
            if net == "0.0.0.0":  # default não é bloco de alocação
                continue
            key = f"{net}/{pfx}"
            if key in seen:
                continue
            seen.add(key)
            subnets.append({
                "network": net, "mask": pfx,
                "description": f"Rota {net}/{pfx}" + (f" via {gw}" if gw else ""),
                "host_ip": None,
            })
        return subnets

    def parse_device_info(self, config_text: str) -> dict:
        m = re.search(r'\b(SG-?\d{3,}|E\d{4})\b', config_text)
        return {"model": m.group(1) if m else None, "serial_number": None}
