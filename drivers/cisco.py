from .base import NetworkDriver
import re
from logger import logger

class CiscoDriver(NetworkDriver):
    """
    Driver para equipamentos Cisco (IOS / IOS-XE).
    """
    display_name = "Cisco IOS/IOS-XE"
    vendor_key = "cisco"

    def get_ssh_command_setup(self) -> str:
        return "terminal length 0"

    def get_config_command(self) -> str:
        return "show running-config"

    def _mask_to_cidr(self, mask_str: str) -> int:
        """
        Converte máscara decimal '255.255.255.0' para o formato CIDR 24.
        O phpIPAM exige a máscara em formato CIDR (int).
        """
        try:
            return sum(bin(int(x)).count('1') for x in mask_str.split('.'))
        except Exception as e:
            logger.warning(f"[CiscoDriver] Falha ao converter máscara '{mask_str}' para CIDR: {e}")
            return 32  # Fallback de segurança em caso de formato inválido

    def _flush_cisco_ptp(self, vlans: dict, vid: int, iface_name: str | None, stanza: list) -> None:
        """Registra bloco de sub-interface PTP (encapsulation dot1Q + ip address) como 'routed'."""
        if not iface_name:
            return
        if vid not in vlans:
            vlans[vid] = {"id": vid, "name": f"VLAN_{vid}", "description": ""}
        vlans[vid]["type"] = "routed"
        block = f"interface {iface_name}\n" + "\n".join(stanza)
        existing = vlans[vid].get("config") or ""
        vlans[vid]["config"] = (existing + ("\n\n" if existing else "") + block).strip()

    def parse_vlans(self, config_text: str) -> list:
        # [TOPOLOGY] ... (comentário original preservado)
        vlans = {}
        current_vlan = None

        for line in config_text.splitlines():
            line = line.rstrip()

            vlan_match = re.match(r'^vlan\s+(\d+)', line)
            if vlan_match:
                vid = int(vlan_match.group(1))
                current_vlan = vid
                vlans[vid] = {"id": vid, "name": f"VLAN_{vid}", "description": ""}
                continue

            if current_vlan and line.startswith(" "):
                name_match = re.match(r'\s+name\s+(.+)', line)
                if name_match:
                    name = name_match.group(1).strip()
                    vlans[current_vlan]["name"] = name
                    vlans[current_vlan]["description"] = name

            elif current_vlan and not line.startswith(" ") and not line.startswith("vlan"):
                current_vlan = None

        # Segunda passagem: sub-interfaces PTP (encapsulation dot1Q + ip address)
        current_iface: str | None = None
        cur_if_vid: int | None = None
        stanza_buf: list[str] = []
        cur_stanza_flushed = False

        for line in config_text.splitlines():
            line = line.rstrip()
            stripped = line.strip()

            mif = re.match(r'^interface\s+(\S+)', stripped)
            if mif:
                if cur_if_vid is not None and not cur_stanza_flushed:
                    if any(' ip address ' in ln for ln in stanza_buf):
                        self._flush_cisco_ptp(vlans, cur_if_vid, current_iface, stanza_buf)
                current_iface = mif.group(1)
                cur_if_vid = None
                stanza_buf = []
                cur_stanza_flushed = False
                m_sub = re.search(r'\.(\d+)$', current_iface)
                if m_sub:
                    cur_if_vid = int(m_sub.group(1))
                continue

            if cur_if_vid is None:
                continue

            if stripped == '!' or (line and not line.startswith(' ')):
                if not cur_stanza_flushed and any(' ip address ' in ln for ln in stanza_buf):
                    self._flush_cisco_ptp(vlans, cur_if_vid, current_iface, stanza_buf)
                cur_if_vid = None
                stanza_buf = []
                cur_stanza_flushed = False
                continue

            if line.startswith(' ') and re.match(
                r'\s+(?:description|encapsulation\s+dot1[qQ]|ip\s+address)\s', line, re.IGNORECASE
            ):
                stanza_buf.append(line)

            m_enc = re.match(r'\s+encapsulation\s+dot1[qQ]\s+(\d+)', line, re.IGNORECASE)
            if m_enc:
                cur_if_vid = int(m_enc.group(1))
                cur_stanza_flushed = False

        # Flush EOF
        if cur_if_vid is not None and not cur_stanza_flushed:
            if any(' ip address ' in ln for ln in stanza_buf):
                self._flush_cisco_ptp(vlans, cur_if_vid, current_iface, stanza_buf)

        return sorted(list(vlans.values()), key=lambda x: x['id'])

    def parse_subnets(self, config_text: str) -> list:
        # [TOPOLOGY] Blocos de 'interface VlanX' com 'ip address' são capturados por
        # topology_parser._parse_cisco_family() para vincular subnet ↔ interface.
        # 'ip route' (capturado aqui) é rota estática; topology_parser não os duplica.
        subnets = []
        for line in config_text.splitlines():
            line = line.strip()
            
            # Cisco: ip route 192.168.10.0 255.255.255.0 10.1.1.1 name NOME_DA_ROTA
            match = re.match(r'^ip route\s+([\d\.]+)\s+([\d\.]+)(.*)', line)
            if match:
                network = match.group(1)
                mask_str = match.group(2)
                resto_linha = match.group(3)
                
                # Ignora a rota default
                if network == "0.0.0.0":
                    continue
                
                # Em roteadores Cisco mais novos, rotas podem ter a tag 'name'
                desc_match = re.search(r'name\s+(.+)', resto_linha)
                desc = desc_match.group(1).strip() if desc_match else f"Rota {network}"
                
                cidr = self._mask_to_cidr(mask_str)
                
                subnets.append({
                    "network": network,
                    "mask": cidr,
                    "description": desc
                })
                
        return subnets

    def parse_device_info(self, config_text: str) -> dict:
        """
        Extrai model e serial do config Cisco IOS/IOS-XE.
        Padrões buscados nos comentários do backup:
          ! cisco WS-C3750G-24TS (PowerPC405) processor
          ! Processor board ID FDO1234ABCD

        # [TOPOLOGY] Extensão futura: implementar parse_interfaces() nativo no driver
        # para retornar interfaces com VLANs e IPs diretamente do config_text.
        # Enquanto isso, o topology_parser.py cumpre esta função de forma centralizada.
        """
        model = None
        serial = None
        for line in config_text.splitlines():
            line = line.strip()
            if not model:
                m = re.match(r'^[!#]\s*cisco\s+(\S+)\s+\(', line, re.IGNORECASE)
                if m:
                    model = m.group(1).strip()
            if not serial:
                s = re.match(r'^[!#]\s*[Pp]rocessor\s+board\s+ID\s+(\S+)', line)
                if s:
                    serial = s.group(1).strip()
            if model and serial:
                break
        logger.debug(f"[CiscoDriver] model={model} serial={serial}")
        return {"model": model, "serial_number": serial}
