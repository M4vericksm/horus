from abc import ABC, abstractmethod

class NetworkDriver(ABC):
    """
    Classe base para todos os drivers de equipamentos de rede.
    Força a implementação dos métodos essenciais para coleta de dados.
    """
    display_name: str = "Genérico"
    vendor_key: str = "unknown"
    supports_ssh_extract: bool = True
    supports_bc_extract: bool = True
    
    def __init__(self, hostname, ip, user, password, port=22):
        self.hostname = hostname
        self.ip = ip
        self.user = user
        self.password = password
        self.port = port

    @abstractmethod
    def get_ssh_command_setup(self) -> str:
        """
        Retorna o comando necessário para desativar a paginação no terminal.
        Ex: 'screen-length 0 temporary' (Huawei) ou 'terminal length 0' (Cisco).
        """
        pass

    @abstractmethod
    def get_config_command(self) -> str:
        """
        Retorna o comando para exibir a configuração completa do equipamento.
        Ex: 'display current-configuration' (Huawei) ou 'show running-config' (Cisco/Datacom).
        """
        pass

    @abstractmethod
    def parse_vlans(self, config_text: str) -> list:
        """
        Recebe o texto bruto retornado pelo equipamento e extrai as VLANs.
        
        Deve retornar uma lista de dicionários no formato:
        [
            {"id": 100, "name": "VLAN_100", "description": "NOME_DA_VLAN", "type": "vsi"},
            ...
        ]
        O campo 'type' é opcional (default None = L2). Valores possíveis: 'vsi', 'l2vc', 'routed'.
        """
        pass
    
    @abstractmethod
    def parse_subnets(self, config_text: str) -> list:
        """Extrai as subnets/rotas do arquivo de configuração."""
        pass

    def parse_device_info(self, config_text: str) -> dict:
        """
        Extrai informações do dispositivo: model e serial_number.
        Retorna dict com chaves 'model' e 'serial_number' (podem ser None).
        Cada driver sobrescreve conforme o formato do fabricante.
        """
        return {"model": None, "serial_number": None}
