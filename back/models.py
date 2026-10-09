from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, func
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

# ==========================================
# TABELA: Servidores BackupCenter
# ==========================================
class BCServer(Base):
    __tablename__ = "bc_servers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    url = Column(String)
    token = Column(String)
    
    clients = relationship("Client", back_populates="bc_server")


# ==========================================
# TABELA: Grupos (Clientes / Sites)
# ==========================================
class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    system = Column(String, default="phpIPAM")
    ip = Column(String, nullable=True)
    token_name = Column(String, nullable=True)
    token = Column(String, nullable=True)
    
    l2_domain_id = Column(Integer, default=1)
    section_id = Column(Integer, default=1)
    vlan_prefix = Column(String, nullable=True)
    auto_approve_assets = Column(Boolean, default=False)

    # Credenciais phpIPAM para re-autenticação automática
    phpipam_user = Column(String, nullable=True)
    phpipam_pass = Column(String, nullable=True)

    # NetBox (credenciais independentes do phpIPAM)
    netbox_url = Column(String, nullable=True)
    netbox_token = Column(String, nullable=True)
    netbox_vlan_group_id = Column(Integer, nullable=True)
    netbox_site_id = Column(Integer, nullable=True)

    # Zabbix (monitoramento do provedor — modo A, leitura via API JSON-RPC).
    # Token de API read-only, criptografado (CLIENT_SECRET_FIELDS). verify_tls
    # permite operar Zabbix interno com certificado self-signed.
    zabbix_url = Column(String, nullable=True)
    zabbix_token = Column(String, nullable=True)
    zabbix_verify_tls = Column(Boolean, default=True)

    # VPN / Jump Host global do grupo
    vpn_host = Column(String, nullable=True)
    vpn_port = Column(Integer, default=22)
    vpn_user = Column(String, nullable=True)
    vpn_pass = Column(String, nullable=True)
    
    bc_server_id = Column(Integer, ForeignKey("bc_servers.id"), nullable=True)
    external_group_id = Column(String, nullable=True)
    
    bc_server = relationship("BCServer", back_populates="clients")

    assets = relationship("Asset", back_populates="client", cascade="all, delete-orphan")
    vlans = relationship("Vlan", back_populates="client", cascade="all, delete-orphan")
    subnets = relationship("Subnet", back_populates="client", cascade="all, delete-orphan")
    bc_links = relationship("ClientBCLink", back_populates="client", cascade="all, delete-orphan")


# ==========================================
# TABELA: Vínculos BackupCenter por Grupo (N:M)
# ==========================================
class ClientBCLink(Base):
    """Um grupo pode ter múltiplos vínculos com grupos do BackupCenter."""
    __tablename__ = "client_bc_links"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True)
    bc_server_id = Column(Integer, ForeignKey("bc_servers.id", ondelete="CASCADE"), nullable=False)
    external_group_id = Column(String, nullable=False)
    label = Column(String, nullable=True)   # ex: "Rede POP", "Rede Core" — opcional

    client = relationship("Client", back_populates="bc_links")
    bc_server = relationship("BCServer")


# ==========================================
# TABELA: Equipamentos (Roteadores / Switches)
# ==========================================
class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    
    ip_address = Column(String, nullable=True)
    port = Column(Integer, default=22)
    vendor = Column(String, nullable=True)
    model = Column(String, nullable=True)
    serial_number = Column(String, nullable=True)
    category = Column(String, default="acesso")
    authority_level = Column(Integer, default=1)
    
    is_edge_router = Column(Boolean, default=False)
    is_approved = Column(Boolean, default=False)
    sync_mode = Column(String, default="manual")
    backup_id = Column(String, nullable=True)
    bc_device_id = Column(String, nullable=True, index=True)
    override_l2_domain_id = Column(Integer, nullable=True)
    ignore_vlan_conflict = Column(Boolean, default=False)
    last_sync_status = Column(String, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_error = Column(String, nullable=True)

    # Credenciais SSH do equipamento
    ssh_user = Column(String, nullable=True)
    ssh_pass = Column(String, nullable=True)

    # VPN / Jump Host override (se diferente do grupo)
    override_vpn_host = Column(String, nullable=True)
    override_vpn_port = Column(Integer, nullable=True)
    override_vpn_user = Column(String, nullable=True)
    override_vpn_pass = Column(String, nullable=True)
    
    client_id = Column(Integer, ForeignKey("clients.id"))
    client = relationship("Client", back_populates="assets")
    
    vlans = relationship("Vlan", back_populates="asset", cascade="all, delete-orphan")
    subnets = relationship("Subnet", back_populates="asset", cascade="all, delete-orphan")
    interfaces = relationship("AssetInterface", back_populates="asset", cascade="all, delete-orphan")


# ==========================================
# TABELAS DE DADOS EXTRAÍDOS
# ==========================================
class Vlan(Base):
    __tablename__ = "vlans"
    id = Column(Integer, primary_key=True, index=True)
    vid = Column(Integer)
    name = Column(String)
    description = Column(String)
    vlan_type = Column(String, nullable=True)  # None=L2 regular, 'routed', 'vsi', 'l2vc'
    # Bloco de config bruto extraído do equipamento que define a VLAN (vsi/l2vc/routed/L2).
    # None quando a extração não capturou (dados antigos) — o front reconstrói um fallback.
    config = Column(String, nullable=True)

    client_id = Column(Integer, ForeignKey("clients.id"))
    asset_id = Column(Integer, ForeignKey("assets.id"))
    
    client = relationship("Client", back_populates="vlans")
    asset = relationship("Asset", back_populates="vlans")
    vlan_interfaces = relationship("VlanInterface", back_populates="vlan", cascade="all, delete-orphan")

class Subnet(Base):
    __tablename__ = "subnets"
    id = Column(Integer, primary_key=True, index=True)
    network = Column(String)
    mask = Column(Integer)
    description = Column(String)
    # IP host configurado na interface (ex: 10.1.1.1) — usado para criar o "address"
    # correspondente no phpIPAM. None quando a origem é uma rota estática (sem IP de host).
    host_ip = Column(String, nullable=True)
    vlan_id = Column(Integer, ForeignKey("vlans.id", ondelete="SET NULL"), nullable=True)
    # FK para a interface física/lógica onde este IP está configurado (populado pelo topology_parser)
    interface_id = Column(Integer, ForeignKey("asset_interfaces.id", ondelete="SET NULL"), nullable=True)

    client_id = Column(Integer, ForeignKey("clients.id"))
    asset_id = Column(Integer, ForeignKey("assets.id"))

    client = relationship("Client", back_populates="subnets")
    asset = relationship("Asset", back_populates="subnets")
    interface = relationship("AssetInterface", back_populates="subnets", foreign_keys=[interface_id])


# ==========================================
# TABELA: Logs de Execução
# ==========================================
class ExecutionLog(Base):
    __tablename__ = "execution_logs"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("clients.id", ondelete="SET NULL"), nullable=True, index=True)
    operation = Column(String, index=True)          # ex: sync_assets, extract_bc, sync_phpipam
    status = Column(String, index=True)             # success | error
    message = Column(String, nullable=True)
    detail = Column(String, nullable=True)          # traceback / detalhe de erro
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), index=True)


# ==========================================
# TABELA: Usuários do sistema
# ==========================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    # E-mail corporativo (login self-service). Nullable p/ compatibilidade com
    # usuários antigos (seed) que logam por username.
    email = Column(String, unique=True, index=True, nullable=True)
    full_name = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    # Administrador do sistema: único papel com acesso à gestão de usuários.
    # A designação efetiva também considera o e-mail (ATLAS_ADMIN_EMAIL) — ver
    # _is_admin_user em main.py —, então contas antigas com a coluna nula
    # continuam sendo reconhecidas pelo e-mail.
    is_admin = Column(Boolean, default=False)
    # MFA (TOTP): segredo base32 e flag de enrolamento concluído.
    mfa_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    # Versão da sessão: todo token carrega a versão vigente no momento do login;
    # o logout a incrementa, invalidando (revogando) server-side todos os tokens
    # emitidos antes — sem isso a sessão stateless só expiraria após o TTL.
    # Em bancos antigos a coluna entra nullable pelo schema-guard; trate NULL=0.
    token_version = Column(Integer, nullable=False, server_default="0", default=0)
    # Reset/convite de senha: guarda o SHA-256 (hex) do token enviado por e-mail
    # (o token cru nunca é persistido) e sua validade. Usado por "esqueci a senha"
    # e pelo convite de novos usuários (definir a 1ª senha).
    password_reset_token = Column(String, nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


# ==========================================
# TABELA: Interfaces físicas e lógicas de um ativo
# Populada pelo topology_parser.py durante a extração de configurações.
# ==========================================
class AssetInterface(Base):
    """Representa uma interface física ou lógica de um equipamento de rede."""
    __tablename__ = "asset_interfaces"
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)

    # Nome da interface, ex: GigabitEthernet0/1, ether2, Vlanif100, bridge
    name = Column(String, nullable=False, index=True)

    # Tipo: physical | vlan | bridge | lag | loopback | tunnel | unknown
    type = Column(String, default="physical")

    # Descrição configurada no equipamento (ex: "Uplink SW-CORE")
    description = Column(String, nullable=True)

    # True se esta interface carrega o IP de gerência do ativo
    is_management = Column(Boolean, default=False)

    asset = relationship("Asset", back_populates="interfaces")
    vlan_interfaces = relationship("VlanInterface", back_populates="interface", cascade="all, delete-orphan")
    subnets = relationship("Subnet", back_populates="interface", foreign_keys="Subnet.interface_id")


# ==========================================
# TABELA: Mapeamento VLAN ↔ Interface (M:N)
# Indica por quais interfaces físicas cada VLAN trafega e em qual modo.
# ==========================================
class VlanInterface(Base):
    """Associação entre uma VLAN e uma interface física/lógica de um ativo."""
    __tablename__ = "vlan_interfaces"
    id = Column(Integer, primary_key=True, index=True)
    vlan_id = Column(Integer, ForeignKey("vlans.id", ondelete="CASCADE"), nullable=False, index=True)
    interface_id = Column(Integer, ForeignKey("asset_interfaces.id", ondelete="CASCADE"), nullable=False, index=True)

    # Modo de operação da VLAN nesta interface:
    # access | trunk | tagged | native | routed
    mode = Column(String, default="trunk")

    vlan = relationship("Vlan", back_populates="vlan_interfaces")
    interface = relationship("AssetInterface", back_populates="vlan_interfaces")
