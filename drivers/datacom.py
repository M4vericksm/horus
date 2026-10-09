from .base import NetworkDriver
import re
from logger import logger

class DatacomDriver(NetworkDriver):
    """
    Driver para equipamentos Datacom (geralmente baseados no DmOS).
    """
    display_name = "Datacom DmOS"
    vendor_key = "datacom"
    
    def get_ssh_command_setup(self) -> str:
        return "screen-length 0"

    def get_config_command(self) -> str:
        return "show running-config"

    def _expand_vlan_str(self, vlan_str: str) -> list:
        """
        Converte strings de VLAN do Datacom como '192-193,2530' 
        para uma lista real de inteiros: [192, 193, 2530]
        """
        vlan_ids = []
        parts = vlan_str.replace(" ", "").split(',')
        for part in parts:
            if '-' in part:
                try:
                    start_str, end_str = part.split('-')
                    vlan_ids.extend(range(int(start_str), int(end_str) + 1))
                except ValueError:
                    logger.warning(f"[DatacomDriver] Intervalo de VLAN inválido ignorado: '{part}'")
                    continue
            else:
                try: 
                    vlan_ids.append(int(part))
                except ValueError: 
                    logger.warning(f"[DatacomDriver] ID de VLAN inválido ignorado: '{part}'")
                    continue
        return vlan_ids

    def _flush_ptp(self, vlans: dict, vid: int, iface_name: str | None, stanza: list) -> None:
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
        # [TOPOLOGY] Blocos de 'interface' com 'switchport access vlan' e
        # 'switchport trunk allowed vlan' no DmOS são processados por
        # topology_parser._parse_cisco_family() (formato compatível) para
        # mapear VLAN ↔ Interface. Não duplicar aqui.
        vlans = {}
        in_dot1q = False
        current_vlans_batch = []

        for line in config_text.splitlines():
            stripped = line.strip()

            if stripped == "dot1q":
                in_dot1q = True
                continue

            if not in_dot1q:
                continue

            if line and not line.startswith(" ") and stripped != "!" and stripped != "dot1q":
                in_dot1q = False
                current_vlans_batch = []
                continue

            if stripped.startswith("vlan "):
                vlan_str = stripped[5:]
                current_vlans_batch = self._expand_vlan_str(vlan_str)
                for vid in current_vlans_batch:
                    vlans[vid] = {"id": vid, "name": f"VLAN_{vid}", "description": ""}
                continue

            if stripped.startswith("name ") and current_vlans_batch:
                name = stripped[5:]
                for vid in current_vlans_batch:
                    vlans[vid]["name"] = name
                    vlans[vid]["description"] = name
                continue

            if stripped == "!":
                current_vlans_batch = []
                continue

        # Padrões adicionais (OLTs DM e DmOS recente) fora do bloco 'dot1q'
        extra_rx = (
            r'^interface l3[ \-]vlan(?:if)?\s*(\d+)',
            r'^native vlan vlan-id\s+(\d+)',
            r'^pw-type vlan\s+(\d+)',
            r'^lower-layer-if vlan\s+(\d+)',
        )
        for line in config_text.splitlines():
            s = line.strip()
            for rx in extra_rx:
                m = re.match(rx, s, re.IGNORECASE)
                if m:
                    vid = int(m.group(1))
                    if 1 <= vid <= 4094:
                        vlans.setdefault(vid, {"id": vid, "name": f"VLAN_{vid}", "description": ""})
                    break

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
                        self._flush_ptp(vlans, cur_if_vid, current_iface, stanza_buf)
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
                    self._flush_ptp(vlans, cur_if_vid, current_iface, stanza_buf)
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

        if cur_if_vid is not None and not cur_stanza_flushed:
            if any(' ip address ' in ln for ln in stanza_buf):
                self._flush_ptp(vlans, cur_if_vid, current_iface, stanza_buf)

        return sorted(list(vlans.values()), key=lambda x: x['id'])

    def parse_subnets(self, config_text: str) -> list:
        # [TOPOLOGY] Blocos de 'interface' com 'ip address' no DmOS são capturados
        # por topology_parser._parse_cisco_family() para vincular subnet ↔ interface.
        # 'ipv4 route' (capturado aqui) são rotas estáticas, não duplicadas pelo parser.
        subnets = []
        for line in config_text.splitlines():
            line = line.strip()
            
            # Datacom (DmOS) geralmente usa formato CIDR direto: ipv4 route 192.168.10.0/24 ...
            match = re.match(r'^ipv4 route\s+([\d\.]+)/(\d+)', line)
            if match:
                network = match.group(1)
                cidr = int(match.group(2))
                
                # Ignora a rota default (0.0.0.0/0)
                if network == "0.0.0.0":
                    continue
                
                # Datacom geralmente não tem "description" na mesma linha de rota. 
                # Usamos um nome genérico para o phpIPAM não ficar em branco.
                subnets.append({
                    "network": network,
                    "mask": cidr,
                    "description": f"Rota {network}/{cidr}"
                })
                
        return subnets

    def parse_device_info(self, config_text: str) -> dict:
        """
        Extrai model e serial do config Datacom DmOS.
        Padrões buscados:
          ! DM4170-28SS
          ! Serial: XXXXXXXXX
        """
        model = None
        serial = None
        for line in config_text.splitlines():
            line = line.strip()
            if not model:
                m = re.match(r'^[!#]\s*(DM\d[\w\-]+)', line, re.IGNORECASE)
                if m:
                    model = m.group(1).strip()
            if not serial:
                s = re.match(r'^[!#]\s*[Ss]erial[:\s]+(\S+)', line)
                if s:
                    serial = s.group(1).strip()
            if model and serial:
                break
        logger.debug(f"[DatacomDriver] model={model} serial={serial}")
        return {"model": model, "serial_number": serial}
