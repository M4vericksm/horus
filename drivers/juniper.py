from .base import NetworkDriver
import ipaddress
import re
from logger import logger


class JuniperDriver(NetworkDriver):
    """
    Driver para equipamentos Juniper Junos em formato `display set`.
    """
    display_name = "Juniper Junos"
    vendor_key = "juniper"

    def get_ssh_command_setup(self) -> str:
        return "set cli screen-length 0"

    def get_config_command(self) -> str:
        return "show configuration | display set | no-more"

    def _clean_token(self, value: str) -> str:
        return value.strip().strip('"')

    def parse_vlans(self, config_text: str) -> list:
        vlans: dict[str, dict] = {}
        for line in config_text.splitlines():
            line = line.strip()
            vlan_match = re.match(
                r'^set\s+vlans\s+(?P<name>"[^"]+"|\S+)\s+vlan-id\s+(?P<vid>\d+)\b',
                line,
                re.IGNORECASE,
            )
            if vlan_match:
                name = self._clean_token(vlan_match.group("name"))
                vid = int(vlan_match.group("vid"))
                current = vlans.setdefault(name, {"id": vid, "name": name, "description": name})
                current["id"] = vid
                current["name"] = name
                if not current.get("description"):
                    current["description"] = name
                continue

            desc_match = re.match(
                r'^set\s+vlans\s+(?P<name>"[^"]+"|\S+)\s+description\s+(?P<desc>.+)$',
                line,
                re.IGNORECASE,
            )
            if desc_match:
                name = self._clean_token(desc_match.group("name"))
                desc = self._clean_token(desc_match.group("desc"))
                current = vlans.setdefault(name, {"id": None, "name": name, "description": name})
                current["description"] = desc or name

        result = [vlan for vlan in vlans.values() if vlan.get("id") is not None]
        if not result:
            return result

        # Segunda passagem: units com IP (PTP/Peering) — adiciona bloco de config à VLAN
        vid_to_vlan = {v["id"]: v for v in result}
        unit_data: dict[tuple, dict] = {}

        for line in config_text.splitlines():
            line = line.strip()
            if not line.startswith("set interfaces "):
                continue
            m = re.match(
                r'^set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+(.+)',
                line, re.IGNORECASE,
            )
            if not m:
                continue
            phys, unit, rest = m.group(1), int(m.group(2)), m.group(3).strip()
            key = (phys, unit)
            if key not in unit_data:
                unit_data[key] = {"phys": phys, "unit": unit, "vid": None, "ip": None, "desc": None}
            ud = unit_data[key]

            m_vid = re.match(r'^vlan-id\s+(\d+)', rest, re.IGNORECASE)
            if m_vid:
                ud["vid"] = int(m_vid.group(1))

            m_ip = re.match(r'^family\s+inet\s+address\s+([\d.]+/\d+)', rest, re.IGNORECASE)
            if m_ip:
                ud["ip"] = m_ip.group(1)

            m_desc = re.match(r'^description\s+(.+)', rest, re.IGNORECASE)
            if m_desc:
                ud["desc"] = m_desc.group(1).strip().strip('"')

        for ud in unit_data.values():
            vid = ud.get("vid")
            ip = ud.get("ip")
            if vid is None or ip is None:
                continue
            target = vid_to_vlan.get(vid)
            if target is None:
                target = {"id": vid, "name": f"VLAN_{vid}", "description": ""}
                vid_to_vlan[vid] = target
                result.append(target)
            lines_cfg = [f'set interfaces {ud["phys"]} unit {ud["unit"]} vlan-id {vid}']
            if ud.get("desc"):
                lines_cfg.append(f'set interfaces {ud["phys"]} unit {ud["unit"]} description "{ud["desc"]}"')
            lines_cfg.append(f'set interfaces {ud["phys"]} unit {ud["unit"]} family inet address {ip}')
            existing = target.get("config") or ""
            target["config"] = (existing + ("\n\n" if existing else "") + "\n".join(lines_cfg)).strip()
            if target.get("type") not in ("vsi", "l2vc"):
                target["type"] = "routed"

        return sorted(result, key=lambda x: x["id"])

    def parse_subnets(self, config_text: str) -> list:
        subnets = []
        seen = set()
        for line in config_text.splitlines():
            line = line.strip()
            interface_match = re.match(
                r'^set\s+interfaces\s+(?P<iface>\S+)\s+unit\s+\S+\s+family\s+inet\s+address\s+'
                r'(?P<address>\d+\.\d+\.\d+\.\d+/\d+)\b',
                line,
                re.IGNORECASE,
            )
            if interface_match:
                iface = interface_match.group("iface")
                try:
                    _ipiface = ipaddress.ip_interface(interface_match.group("address"))
                    net = _ipiface.network
                except ValueError as e:
                    logger.debug(f"[JuniperDriver] subnet interface inválida ignorada: {line} ({e})")
                    continue
                item = {
                    "network": str(net.network_address),
                    "mask": net.prefixlen,
                    "description": f"Interface {iface}",
                    "host_ip": str(_ipiface.ip),  # IP da interface
                }
                key = (item["network"], item["mask"], item["description"])
                if key not in seen:
                    subnets.append(item)
                    seen.add(key)
                continue

            route_match = re.match(
                r'^set\s+routing-options\s+static\s+route\s+(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)\b',
                line,
                re.IGNORECASE,
            )
            if route_match:
                try:
                    net = ipaddress.ip_network(route_match.group("prefix"), strict=False)
                except ValueError as e:
                    logger.debug(f"[JuniperDriver] rota estática inválida ignorada: {line} ({e})")
                    continue
                if str(net) == "0.0.0.0/0":
                    continue
                item = {
                    "network": str(net.network_address),
                    "mask": net.prefixlen,
                    "description": f"Rota {net.network_address}",
                    "host_ip": None,  # rota estática não tem IP de host
                }
                key = (item["network"], item["mask"], item["description"])
                if key not in seen:
                    subnets.append(item)
                    seen.add(key)

        return subnets

    def parse_device_info(self, config_text: str) -> dict:
        model = None
        for line in config_text.splitlines():
            line = line.strip()
            if not model:
                comment_match = re.match(r'^##\s*Model:\s*(?P<model>.+)$', line, re.IGNORECASE)
                if comment_match:
                    model = comment_match.group("model").strip()
                    break
            if not model:
                chassis_match = re.match(r'^set\s+chassis\s+.*\bmodel\s+(?P<model>\S+)', line, re.IGNORECASE)
                if chassis_match:
                    model = chassis_match.group("model").strip()
                    break
        logger.debug(f"[JuniperDriver] model={model} serial=None")
        return {"model": model, "serial_number": None}
