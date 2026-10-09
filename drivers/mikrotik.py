from .base import NetworkDriver
import re
from logger import logger


def _expand_vid_list(raw: str) -> list:
    """Expande 'vlan-ids' do RouterOS em VIDs: '10,20,30', '100-200', '10-12,30'.

    Ignora tokens não-numéricos (none/all/untagged) e ranges absurdos.
    """
    out = []
    for part in (raw or "").strip('"').replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
            except ValueError:
                continue
            if 0 <= a <= b <= 4094 and (b - a) <= 4094:
                out.extend(range(a, b + 1))
        else:
            try:
                v = int(part)
            except ValueError:
                continue
            if 0 <= v <= 4094:
                out.append(v)
    return out


class MikrotikDriver(NetworkDriver):
    """
    Driver para equipamentos MikroTik (RouterOS).

    Extrai VLANs e subnets a partir do output do comando `/export terse`,
    que é o formato compacto usado pela Backup API para salvar configurações.

    Formato esperado:
      /interface vlan add interface=ether1 name=VLAN-100-CLIENTES vlan-id=100
      /ip address add address=10.1.1.1/24 comment="GERENCIA" interface=ether1 network=10.1.1.0
    """
    display_name = "MikroTik RouterOS"
    vendor_key = "mikrotik"

    def get_ssh_command_setup(self) -> str:
        # RouterOS não tem paginação problemática; o export já é compacto.
        # Enviamos um espaço em branco para não travar o prompt inicial.
        return ""

    def get_config_command(self) -> str:
        return "/export terse"

    def _join_continuations(self, config_text: str) -> str:
        """RouterOS 7 quebra linhas longas com '\\' + newline indentado.
        Junta cada linha terminada em '\\' com a seguinte, num único espaço."""
        out = []
        buffer = ""
        for line in config_text.splitlines():
            if buffer:
                buffer = buffer + " " + line.strip()
            else:
                buffer = line
            if buffer.rstrip().endswith("\\"):
                buffer = buffer.rstrip()[:-1].rstrip()
            else:
                out.append(buffer)
                buffer = ""
        if buffer:
            out.append(buffer)
        return "\n".join(out)

    # ------------------------------------------------------------------
    # DEVICE INFO
    # ------------------------------------------------------------------

    def parse_device_info(self, config_text: str) -> dict:
        """
        Extrai model e serial do cabeçalho do /export terse.
        Formato:
          # model = CCR1009-8G-1S
          # serial number = 606C04151131
        """
        model = None
        serial = None
        for line in config_text.splitlines():
            line = line.strip()
            if not line.startswith("#"):
                if model and serial:
                    break
                continue
            m = re.match(r'^#\s*model\s*=\s*(.+)', line)
            if m:
                model = m.group(1).strip()
                continue
            s = re.match(r'^#\s*serial\s*number\s*=\s*(.+)', line, re.IGNORECASE)
            if s:
                serial = s.group(1).strip()
        logger.debug(f"[MikrotikDriver] model={model} serial={serial}")
        return {"model": model, "serial_number": serial}

    # ------------------------------------------------------------------
    # VLANS
    # ------------------------------------------------------------------

    def parse_vlans(self, config_text: str) -> list:
        """
        Extrai VLANs da saída do RouterOS `/export terse`.

        Linha esperada:
          /interface vlan add interface=<IF> name=<NAME> vlan-id=<ID>

        O campo `name` do RouterOS é usado como nome E descrição da VLAN
        no phpIPAM.

        # [TOPOLOGY] As linhas '/interface vlan add interface=<parent> vlan-id=<id>'
        # são também processadas por topology_parser._parse_mikrotik() para mapear
        # VLAN ↔ Interface pai (modo 'tagged'). Não duplicar aqui.
        # '/ip address add address=<ip> interface=<if>' é usado para vincular
        # subnet ↔ interface no mesmo parser.
        """
        config_text = self._join_continuations(config_text)
        vlans = {}

        for line in config_text.splitlines():
            line = line.strip()

            # Só processa linhas de criação de VLAN
            if not line.startswith("/interface vlan add"):
                continue

            # Extrai o vlan-id
            vid_match = re.search(r'\bvlan-id=(\d+)', line)
            if not vid_match:
                logger.warning(f"[MikrotikDriver] Linha de VLAN sem vlan-id ignorada: {line!r}")
                continue
            vid = int(vid_match.group(1))

            # Extrai o name (pode vir com ou sem aspas)
            name_match = re.search(r'\bname=("([^"]+)"|(\S+))', line)
            if name_match:
                # grupo 2 → com aspas, grupo 3 → sem aspas
                name = (name_match.group(2) or name_match.group(3)).strip()
            else:
                name = f"VLAN_{vid}"

            # Evita duplicatas: se a VLAN já existe, mantém a primeira ocorrência
            if vid not in vlans:
                vlans[vid] = {
                    "id": vid,
                    "name": name,
                    "description": name,
                }
            else:
                logger.debug(
                    f"[MikrotikDriver] VLAN {vid} duplicada ignorada "
                    f"(já registrada como '{vlans[vid]['name']}')"
                )

        # Duas outras fontes de VLAN no RouterOS, ambas com vlan-ids podendo ser
        # lista/range ('10,20,100-200'):
        #  - bridge VLAN filtering (RouterOS 7 / switches CRS em bridge mode):
        #      /interface bridge vlan add ... vlan-ids=...
        #  - chip de switch (RB2011/hEX/CRS1xx legado):
        #      /interface ethernet switch vlan add ... vlan-id=...
        for line in config_text.splitlines():
            line = line.strip()
            if not (line.startswith("/interface bridge vlan add")
                    or line.startswith("/interface ethernet switch vlan add")):
                continue
            m = re.search(r'\bvlan-ids?=(\S+)', line)  # casa vlan-id= e vlan-ids=
            if not m:
                continue
            comment_match = re.search(r'\bcomment=("([^"]+)"|(\S+))', line)
            base_name = (comment_match.group(2) or comment_match.group(3)).strip() if comment_match else None
            for vid in _expand_vid_list(m.group(1)):
                if vid in vlans:
                    continue
                vlans[vid] = {"id": vid, "name": base_name or f"VLAN_{vid}", "description": base_name or f"VLAN_{vid}"}

        # Segunda passagem: associa IPs de PTP/Peering às VLANs
        # Constrói mapa: nome de interface VLAN → VID
        vlan_if_to_vid: dict[str, int] = {}
        for line in config_text.splitlines():
            line = line.strip()
            if not line.startswith("/interface vlan add"):
                continue
            vid_m = re.search(r'\bvlan-id=(\d+)', line)
            name_m = re.search(r'\bname=("([^"]+)"|(\S+))', line)
            if vid_m and name_m:
                if_name = (name_m.group(2) or name_m.group(3)).strip()
                vlan_if_to_vid[if_name] = int(vid_m.group(1))

        for line in config_text.splitlines():
            line = line.strip()
            if not line.startswith("/ip address add"):
                continue
            iface_m = re.search(r'\binterface=("([^"]+)"|(\S+))', line)
            addr_m = re.search(r'\baddress=(\S+)', line)
            if not iface_m or not addr_m:
                continue
            if_name = (iface_m.group(2) or iface_m.group(3)).strip()
            vid = vlan_if_to_vid.get(if_name)
            if vid is None or vid not in vlans:
                continue
            ip_addr = addr_m.group(1)
            ip_line = f"/ip address add address={ip_addr} interface={if_name}"
            existing = vlans[vid].get("config") or ""
            vlans[vid]["config"] = (existing + ("\n" if existing else "") + ip_line).strip()
            if not vlans[vid].get("type"):
                vlans[vid]["type"] = "routed"

        result = sorted(vlans.values(), key=lambda x: x["id"])
        logger.info(f"[MikrotikDriver] {len(result)} VLANs extraídas.")
        return result

    # ------------------------------------------------------------------
    # SUBNETS / BLOCOS IP
    # ------------------------------------------------------------------

    def parse_subnets(self, config_text: str) -> list:
        """
        Extrai subnets dos endereços IP configurados nas interfaces.

        Linha esperada:
          /ip address add address=<IP>[/<CIDR>] [comment=<DESC>] interface=<IF> network=<NET>

        Estratégia:
        - Usa o campo `network` do RouterOS para obter o endereço de rede exato.
        - Usa o campo `address` para extrair o prefixo CIDR (default /32 quando omitido).
        - Usa o campo `comment` como descrição legível; se ausente, usa o nome da interface.
        - Inclui /32 (hosts individuais, loopbacks, blocos CGNAT) pois representam
          endereços gerenciáveis no inventário.
        - Pula apenas /128 (IPv6 host único), que não agrega valor topológico.

        # [TOPOLOGY] topology_parser._parse_mikrotik() também lê estas linhas para
        # extrair o campo 'interface=' e vincular subnet ↔ AssetInterface no banco.
        # Não duplicar aqui: a persistemência é feita por auto_discovery._persist_interfaces().
        """
        config_text = self._join_continuations(config_text)
        subnets = []
        seen = set()  # evita subnets duplicadas

        for line in config_text.splitlines():
            line = line.strip()

            if not line.startswith("/ip address add"):
                continue

            # Campo address=IP ou address=IP/CIDR (CIDR opcional no RouterOS)
            addr_match = re.search(r'\baddress=([\d\.]+)(?:/(\d+))?', line)
            if not addr_match:
                logger.warning(f"[MikrotikDriver] Linha sem address válido ignorada: {line!r}")
                continue

            ip = addr_match.group(1)
            cidr = int(addr_match.group(2)) if addr_match.group(2) else 32

            # /128 são endereços de host IPv6 — sem valor topológico para subnets
            if cidr == 128:
                logger.debug(f"[MikrotikDriver] Prefix /128 ignorado (host IPv6): {line!r}")
                continue

            # Prefere o campo `network` para o endereço base da subnet
            net_match = re.search(r'\bnetwork=([\d\.]+)', line)
            if net_match:
                network = net_match.group(1)
            else:
                # Fallback: usa o IP do campo address (pode não ser o endereço de rede)
                network = ip

            # Evita duplicatas (mesma subnet pode aparecer em múltiplas interfaces)
            key = (network, cidr)
            if key in seen:
                continue
            seen.add(key)

            # Descrição: prefere `comment`; se ausente, usa nome da interface
            comment_match = re.search(r'\bcomment=("([^"]+)"|(\S+))', line)
            if comment_match:
                description = (comment_match.group(2) or comment_match.group(3)).strip()
            else:
                iface_match = re.search(r'\binterface=("([^"]+)"|(\S+))', line)
                if iface_match:
                    description = f"Interface {(iface_match.group(2) or iface_match.group(3)).strip()}"
                else:
                    description = f"Subnet {network}/{cidr}"

            subnets.append({
                "network": network,
                "mask": cidr,
                "description": description,
                "host_ip": ip,  # IP configurado na interface (address=)
            })

        # Rotas estáticas: em provedor, o bloco delegado ao cliente costuma existir
        # só como rota (não há IP dele em interface nossa). Sem isto o bloco fica
        # invisível no inventário — os demais vendors já capturavam, o MikroTik não.
        subnets.extend(self._parse_static_routes(config_text, seen))

        logger.info(f"[MikrotikDriver] {len(subnets)} subnets extraídas.")
        return subnets

    def _parse_static_routes(self, config_text: str, seen: set) -> list:
        """Extrai blocos declarados em `/ip route`.

        Aceita os dois formatos de export do RouterOS:
          - terse:  `/ip route add dst-address=192.168.10.0/24 gateway=... comment=...`
          - seção:  linha `/ip route` seguida de linhas `add dst-address=...`

        Descarta: rota default (0.0.0.0/0), rotas desabilitadas (`disabled=yes`)
        e prefixos inválidos. `host_ip` é None — rota não configura IP local.
        """
        routes = []
        in_route_section = False

        for raw in config_text.splitlines():
            line = raw.strip()
            if not line:
                continue

            # Controle de seção: '/ip route' abre; qualquer outro '/...' fecha.
            if line.startswith("/"):
                in_route_section = bool(re.match(r'^/ip route\b(?!\s+add)', line))
                if not re.match(r'^/ip route\s+add\b', line):
                    continue

            if not in_route_section and not line.startswith("/ip route add"):
                continue
            if not re.match(r'^(add|/ip route add)\b', line):
                continue

            # Rota desabilitada não representa alocação ativa.
            if re.search(r'\bdisabled=yes\b', line):
                continue

            dst = re.search(r'\bdst-address=([\d\.]+)/(\d+)', line)
            if not dst:
                continue
            network, cidr = dst.group(1), int(dst.group(2))

            if network == "0.0.0.0":  # rota default não é bloco de alocação
                continue

            key = (network, cidr)
            if key in seen:
                continue
            seen.add(key)

            comment = re.search(r'\bcomment=("([^"]+)"|(\S+))', line)
            if comment:
                description = (comment.group(2) or comment.group(3)).strip()
            else:
                gw = re.search(r'\bgateway=("([^"]+)"|(\S+))', line)
                description = (f"Rota {network}/{cidr} via "
                               f"{(gw.group(2) or gw.group(3)).strip()}") if gw else f"Rota {network}/{cidr}"

            routes.append({
                "network": network,
                "mask": cidr,
                "description": description,
                "host_ip": None,  # rota estática não configura IP local
            })

        if routes:
            logger.info(f"[MikrotikDriver] {len(routes)} rotas estáticas extraídas.")
        return routes
