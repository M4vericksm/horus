"""Driver FiberHome — OLTs AN5516/AN6000 (FiberHome OS / "WOS").

Implementado a partir de configs reais de produção (jun/2026). Formato observado:
  set manage vlan name GERENCIA vid 4000 inputport 19:1 tagged
  set manage vlan name GERENCIA ip 10.40.39.7/28  10.40.39.1
  set service VLAN3100 vid_begin 3100 vid_end 3100 uplink 19:1 tagged service_type 1
"""
import ipaddress
import re
from .base import NetworkDriver


class FiberHomeDriver(NetworkDriver):
    display_name = "FiberHome"
    vendor_key = "fiberhome"

    def get_ssh_command_setup(self) -> str:
        return ""

    def get_config_command(self) -> str:
        return "show startup-config"

    def parse_vlans(self, config_text: str) -> list:
        vlans = {}
        for raw in config_text.splitlines():
            s = raw.strip()
            # VLAN de gerência: 'set manage vlan name <NOME> vid <X>'
            m = re.match(r'^set manage vlan name\s+(\S+)\s+vid\s+(\d+)', s, re.I)
            if m:
                name, vid = m.group(1), int(m.group(2))
                vlans[vid] = {"id": vid, "name": name, "description": name}
                continue
            # VLANs de serviço: 'set service <NOME> vid_begin <X> vid_end <Y>'
            m = re.match(r'^set service\s+(\S+)\s+vid_begin\s+(\d+)\s+vid_end\s+(\d+)', s, re.I)
            if m:
                name, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
                if hi < lo or hi - lo > 4094:
                    hi = lo
                for vid in range(lo, hi + 1):
                    nm = name if lo == hi else f"{name}_{vid}"
                    vlans.setdefault(vid, {"id": vid, "name": nm, "description": name})
        return sorted(vlans.values(), key=lambda x: x["id"])

    def parse_subnets(self, config_text: str) -> list:
        subnets = []
        seen = set()
        for raw in config_text.splitlines():
            s = raw.strip()
            # 'set manage vlan name <NOME> ip <ip>/<cidr> <gw>'
            m = re.match(r'^set manage vlan name\s+(\S+)\s+ip\s+([\d.]+)/(\d+)', s, re.I)
            if not m:
                continue
            name, ip, cidr = m.group(1), m.group(2), int(m.group(3))
            try:
                net = str(ipaddress.ip_interface(f"{ip}/{cidr}").network.network_address)
            except Exception:
                continue
            key = f"{net}/{cidr}"
            if key in seen:
                continue
            seen.add(key)
            subnets.append({"network": net, "mask": cidr, "description": name, "host_ip": ip})
        return subnets

    def parse_device_info(self, config_text: str) -> dict:
        m = re.search(r'\b(AN\d{4}\w*)\b', config_text)
        return {"model": m.group(1) if m else None, "serial_number": None}
