from .base import NetworkDriver
import io
import re
import zipfile
from logger import logger

class HuaweiDriver(NetworkDriver):
    display_name = "Huawei VRP"
    vendor_key = "huawei"

    def get_ssh_command_setup(self) -> str:
        # Desativa a paginação no terminal do Huawei
        return "screen-length 0 temporary"

    def get_config_command(self) -> str:
        # Comando para extrair a configuração completa
        return "display current-configuration"

    @staticmethod
    def extract_zip_config(zip_bytes: bytes) -> str:
        """
        NE800 entrega config como .zip com um ou mais arquivos .cfg/.txt.
        Retorna o conteudo concatenado de todos os .cfg/.txt encontrados.
        Levanta BCParseError se o ZIP nao contiver nenhum arquivo .cfg/.txt.
        """
        from exceptions import BCParseError

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            parts = []
            for name in zf.namelist():
                if name.lower().endswith((".cfg", ".txt")):
                    parts.append(zf.read(name).decode("utf-8", errors="ignore"))
            if not parts:
                raise BCParseError(f"ZIP sem .cfg/.txt: {zf.namelist()}")
            return "\n".join(parts)

    def parse_vlans(self, config_text: str) -> list:
        # [TOPOLOGY] Blocos de 'interface' com 'port trunk allow-pass vlan' e
        # 'port default vlan' são processados por topology_parser._parse_huawei()
        # para mapear VLAN ↔ Interface (modo trunk/access/hybrid).
        # Não duplicar aqui: o topology_parser é chamado por auto_discovery._persist_interfaces().
        vlans = {}
        current_vlan = None

        # Divide o texto do backup linha por linha
        lines = config_text.splitlines()

        # Pré-passagem: cria entradas para TODOS os VIDs referenciados no config,
        # independente de terem um bloco 'vlan <num>' explícito. Sem isso, VLANs
        # declaradas apenas via batch, user-vlan, dot1q, trunk allow-pass ou Vlanif
        # ficam de fora do dicionário e a segunda passagem não as enriquece.
        def _ensure_vid(vid):
            if 1 <= vid <= 4094 and vid not in vlans:
                vlans[vid] = {
                    "id": vid,
                    "name": f"VLAN_{vid}",
                    "description": "",
                    "_cfg": [f"vlan {vid}"],
                }

        for raw_line in lines:
            stripped = raw_line.strip()

            # vlan batch X to Y Z ...
            batch_match = re.match(r'^vlan batch\s+(.*)', stripped)
            if batch_match:
                batch_str = batch_match.group(1)
                expanded = re.sub(
                    r'(\d+)\s+to\s+(\d+)',
                    lambda m: ' '.join(str(v) for v in range(int(m.group(1)), int(m.group(2)) + 1)),
                    batch_str,
                )
                for vid_str in re.findall(r'\d+', expanded):
                    _ensure_vid(int(vid_str))
                continue

            # user-vlan <num> [<num> ...]
            uv_match = re.match(r'^user-vlan\s+([\d\s]+)', stripped)
            if uv_match:
                for vid_str in re.findall(r'\d+', uv_match.group(1)):
                    _ensure_vid(int(vid_str))
                continue

            # ── Huawei OLT (SmartAX MA5600/MA5800), formato distinto do VRP ──
            # 'port vlan eth 1 translation 100 user-vlan 100', 'port vlan iphost ...',
            # 'gem mapping 100 0 vlan 100', 'service-port ... vlan 100'
            if re.search(r'\b(port vlan|gem mapping|service-port)\b', stripped, re.IGNORECASE):
                for vid_str in re.findall(r'\b(?:user-vlan|translation|vlan)\s+(\d+)', stripped, re.IGNORECASE):
                    _ensure_vid(int(vid_str))
                continue

            # 'vlan 2800 to 2864 smart' / 'vlan 100 smart' / 'vlan 100 standard'
            smart_match = re.match(r'^vlan\s+(\d+)(?:\s+to\s+(\d+))?\s+(?:smart|mux|standard)\b', stripped, re.IGNORECASE)
            if smart_match:
                lo = int(smart_match.group(1))
                hi = int(smart_match.group(2)) if smart_match.group(2) else lo
                if hi >= lo and hi - lo <= 4094:
                    for vid in range(lo, hi + 1):
                        _ensure_vid(vid)
                continue

            # vlan-type dot1q <num>
            dt_match = re.search(r'vlan-type\s+dot1q\s+(\d+)', stripped, re.IGNORECASE)
            if dt_match:
                _ensure_vid(int(dt_match.group(1)))

            # interface Vlanif<num>
            vif_match = re.match(r'^interface\s+Vlanif(\d+)', stripped, re.IGNORECASE)
            if vif_match:
                _ensure_vid(int(vif_match.group(1)))

            # port default vlan <num>
            pd_match = re.search(r'port\s+default\s+vlan\s+(\d+)', stripped, re.IGNORECASE)
            if pd_match:
                _ensure_vid(int(pd_match.group(1)))

            # port trunk allow-pass vlan <list>
            tp_match = re.search(r'port\s+trunk\s+allow-pass\s+vlan\s+([\d\s,to-]+)', stripped, re.IGNORECASE)
            if tp_match:
                tp_str = tp_match.group(1)
                tp_expanded = re.sub(
                    r'(\d+)\s+to\s+(\d+)',
                    lambda m: ' '.join(str(v) for v in range(int(m.group(1)), int(m.group(2)) + 1)),
                    tp_str,
                )
                for vid_str in re.findall(r'\d+', tp_expanded):
                    _ensure_vid(int(vid_str))

        # Acumula linhas de config bruto por VID (buffer interno '_cfg', removido no fim).
        def add_cfg(vid, text):
            if vid in vlans:
                vlans[vid].setdefault("_cfg", []).append(text)

        # Adiciona uma linha de atributo sob seu 'interface ...', sem repetir o
        # cabeçalho da interface quando várias linhas caem na mesma stanza.
        last_if = {}
        def add_under_iface(vid, iface, attr_line):
            if vid not in vlans:
                return
            if iface and last_if.get(vid) != iface:
                vlans[vid].setdefault("_cfg", []).append("")
                vlans[vid]["_cfg"].append(iface)
                last_if[vid] = iface
            vlans[vid].setdefault("_cfg", []).append(f" {attr_line}")

        for line in lines:
            line = line.strip()

            # 1. Identifica o bloco raiz da VLAN (Ignora 'vlan batch')
            # Ex: vlan 501
            vlan_match = re.match(r'^vlan\s+(\d+)$', line)
            if vlan_match:
                vlan_id = int(vlan_match.group(1))
                current_vlan = vlan_id

                # Inicializa a VLAN no dicionário com valores padrão
                vlans[vlan_id] = {
                    "id": vlan_id,
                    "name": f"VLAN_{vlan_id}",
                    "description": "",
                    "_cfg": [f"vlan {vlan_id}"],
                }
                continue

            # 2. Se estivermos dentro do bloco de uma VLAN, procuramos atributos
            if current_vlan is not None:
                # O bloco termina se a linha começar com "#" ou se for outro comando global
                if line.startswith("#") or (line and line[0].isalpha() and not line.startswith(("name", "description"))):
                    current_vlan = None
                    continue

                # Procura por "description TEXTO" ou "name TEXTO"
                match = re.match(r'^(description|name)\s+(.+)', line)
                if match:
                    # Huawei permite 'name' e 'description'. Vamos mapear o valor encontrado para ambos.
                    valor = match.group(2).strip()
                    vlans[current_vlan]["name"] = valor
                    vlans[current_vlan]["description"] = valor
                    add_cfg(current_vlan, f" {line}")

        # 3. Segunda passagem: tipos (routed/vsi/l2vc) + captura do bloco de config.
        #    Cobre a sintaxe REAL dos equipamentos (validada no BackupCenter):
        #    sub-interface dot1q + 'mpls l2vc <peer> <vc-id>' (L2VC) ou
        #    'l2 binding vsi <nome>' (VSI). Mantém Vlanif routed e os padrões antigos.
        def ensure_vlan(vid, name=None):
            if vid not in vlans:
                vlans[vid] = {"id": vid, "name": name or f"VLAN_{vid}", "description": name or "", "_cfg": [f"vlan {vid}"]}
            elif name and str(vlans[vid].get("name", "")).startswith("VLAN_"):
                vlans[vid]["name"] = name
                vlans[vid]["description"] = name

        def flush_stanza(vid, vtype, iface, buf):
            ensure_vlan(vid)
            vlans[vid]["type"] = vtype
            if iface and last_if.get(vid) != iface:
                vlans[vid].setdefault("_cfg", []).append("")
                vlans[vid]["_cfg"].append(iface)
                last_if[vid] = iface
            for ln in buf:
                vlans[vid]["_cfg"].append(f" {ln}")

        current_vlanif = None
        current_iface = None     # última linha 'interface ...' vista
        cur_if_vid = None        # vid dot1q da sub-interface atual
        stanza_buf = []          # linhas dot1q acumuladas da sub-interface
        cur_stanza_flushed = False  # True após flush l2vc/vsi (evita re-flush como PTP)
        for line in lines:
            line = line.strip()

            mif = re.match(r'^interface\s+(\S+)', line, re.IGNORECASE)
            if mif:
                # Flush da stanza PTP anterior: sub-interface com IP mas sem l2vc/vsi
                if cur_if_vid is not None and not cur_stanza_flushed:
                    if any(ln.startswith('ip address') for ln in stanza_buf):
                        flush_stanza(cur_if_vid, 'routed', current_iface, stanza_buf)
                current_iface = line
                cur_if_vid = None
                stanza_buf = []
                cur_stanza_flushed = False
                m_sub = re.search(r'\.(\d+)\b', mif.group(1))
                if m_sub:
                    cur_if_vid = int(m_sub.group(1))

            # vid dot1q da sub-interface (sobrescreve o sufixo)
            m_dot = re.search(r'(?:vlan-type\s+dot1q|dot1q\s+termination\s+vid|encapsulation\s+dot1q\s+vid|control-vid)\s+(\d+)', line, re.IGNORECASE)
            if m_dot and current_iface is not None:
                cur_if_vid = int(m_dot.group(1))
                stanza_buf.append(line)

            # description e ip address em sub-interface (PTP/Peering) — exclui Vlanif (tratado abaixo)
            if cur_if_vid is not None and current_vlanif is None and not cur_stanza_flushed:
                if re.match(r'^(?:description|ip address)\s', line, re.IGNORECASE) and line not in stanza_buf:
                    stanza_buf.append(line)

            # Routed (Vlanif com IP)
            match_vif = re.match(r'^interface\s+Vlanif(\d+)', line, re.IGNORECASE)
            if match_vif:
                current_vlanif = int(match_vif.group(1))
                cur_if_vid = current_vlanif   # o SVI (Vlanif) pode carregar l2vc/vsi como AC
                add_cfg(current_vlanif, "")
                add_cfg(current_vlanif, line)
                continue

            if current_vlanif is not None:
                if line.startswith("#") or (line and line[0].isalpha() and not line.startswith(("ip address", "description", "ipv6"))):
                    current_vlanif = None
                elif line.startswith(("ip address", "description", "ipv6")):
                    add_cfg(current_vlanif, f" {line}")
                    if line.startswith("ip address") and current_vlanif in vlans and vlans[current_vlanif].get("type") not in ("vsi", "l2vc"):
                        vlans[current_vlanif]["type"] = "routed"

            # L2VC real: 'mpls l2vc <peer> <vc-id>' na sub-interface
            if cur_if_vid is not None and re.search(r'mpls\s+l2vc\b', line, re.IGNORECASE):
                flush_stanza(cur_if_vid, "l2vc", current_iface, stanza_buf + [line])
                stanza_buf = []
                cur_stanza_flushed = True

            # VSI real: 'l2 binding vsi <nome>'
            m_bind = re.search(r'l2\s+binding\s+vsi\s+(\S+)', line, re.IGNORECASE)
            if m_bind and cur_if_vid is not None:
                ensure_vlan(cur_if_vid, m_bind.group(1))
                flush_stanza(cur_if_vid, "vsi", current_iface, stanza_buf + [line])
                stanza_buf = []
                cur_stanza_flushed = True

            # ── Fallbacks (sintaxe antiga) ──
            match_encap = re.search(r'encapsulation\s+vlan\s+(\d+)', line, re.IGNORECASE)
            if match_encap:
                vid = int(match_encap.group(1))
                if vid in vlans:
                    vlans[vid]["type"] = "vsi"
                    add_under_iface(vid, current_iface, line)

            match_xconnect = re.search(r'vlan-type\s+dot1q\s+(\d+).*?xconnect\s+vsi', line, re.IGNORECASE)
            if match_xconnect:
                vid = int(match_xconnect.group(1))
                if vid in vlans:
                    vlans[vid]["type"] = "vsi"
                    add_under_iface(vid, current_iface, line)

            match_l2vc = re.search(r'l2vc\s+\S+\s+\d+\s+vlan\s+(\d+)', line, re.IGNORECASE)
            if match_l2vc:
                vid = int(match_l2vc.group(1))
                if vid in vlans:
                    vlans[vid]["type"] = "l2vc"
                    add_under_iface(vid, current_iface, line)

        # Flush final: sub-interface PTP no fim do arquivo (sem nova 'interface' após)
        if cur_if_vid is not None and not cur_stanza_flushed:
            if any(ln.startswith('ip address') for ln in stanza_buf):
                flush_stanza(cur_if_vid, 'routed', current_iface, stanza_buf)

        # Monta a string de config por VLAN (remove o buffer interno) e ordena por ID.
        result = []
        for v in vlans.values():
            cfg_lines = v.pop("_cfg", [])
            v["config"] = "\n".join(cfg_lines).strip() or None
            result.append(v)
        return sorted(result, key=lambda x: x['id'])
    
    def _mask_to_cidr(self, mask_str: str) -> int:
        """Converte '255.255.255.0' para 24"""
        try:
            return sum(bin(int(x)).count('1') for x in mask_str.split('.'))
        except Exception as e:
            logger.warning(f"[HuaweiDriver] Falha ao converter máscara '{mask_str}' para CIDR: {e}")
            return 32  # Fallback seguro

    def parse_subnets(self, config_text: str) -> list:
        # [TOPOLOGY] Blocos de 'interface Vlanif<id>' e 'interface GigabitEthernetX'
        # com 'ip address' são capturados por topology_parser._parse_huawei()
        # para vincular subnet ↔ interface. 'ip route-static' (capturado aqui)
        # são rotas estáticas e não são duplicados pelo topology_parser.
        subnets = []
        for line in config_text.splitlines():
            line = line.strip()
            
            # Busca rotas estáticas: ip route-static <IP> <MASCARA> [resto da linha...]
            match = re.match(r'^ip route-static\s+([\d\.]+)\s+([\d\.]+)(.*)', line)
            if match:
                network = match.group(1)
                mask_str = match.group(2)
                resto = match.group(3)
                
                # Ignora a rota default (0.0.0.0/0) pois não é uma Subnet de alocação
                if network == "0.0.0.0":
                    continue
                
                # Procura se existe uma descrição na linha
                desc_match = re.search(r'description\s+(.+)', resto)
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
        Extrai model e serial do config Huawei VRP.
        Padrões buscados:
          board add 0/0 S5731-H48T4XC
          esn 21023XXXXXXXX  /  sn: XXXXXXXX

        # [TOPOLOGY] Extensão futura: implementar parse_interfaces() nativo no driver
        # para retornar interfaces com VLANs (trunk/access/hybrid) e IPs (Vlanif + loopback).
        # Enquanto isso, o topology_parser.py cumpre esta função de forma centralizada.
        """
        model = None
        serial = None
        for line in config_text.splitlines():
            line = line.strip()
            if not model:
                m = re.match(r'^board\s+add\s+[\d/]+\s+(\S+)', line, re.IGNORECASE)
                if m:
                    model = m.group(1).strip()
            if not serial:
                s = re.match(r'^(?:esn|sn)\s+(\S+)', line, re.IGNORECASE)
                if s:
                    serial = s.group(1).strip()
            if model and serial:
                break
        logger.debug(f"[HuaweiDriver] model={model} serial={serial}")
        return {"model": model, "serial_number": serial}
