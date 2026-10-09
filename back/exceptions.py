"""Exceções customizadas do NetworkAtlas."""

from dataclasses import dataclass

import httpx


class BackupSyncError(Exception):
    """Classe base para todas as exceções do NetworkAtlas."""
    pass


class BCConnectionError(BackupSyncError):
    """
    Levantada quando não é possível estabelecer conexão com um servidor BackupCenter.
    Exemplos: timeout, URL inválida, token expirado, servidor offline.
    """
    pass


class SSHAuthError(BCConnectionError):
    """Falha de autenticação ao conectar via SSH."""

    error_code = "ssh_auth_failed"
    hint = "Verifique usuário, senha e permissões SSH do ativo ou jump host."

    def __init__(self, ip: str, port: int):
        super().__init__(f"Falha de autenticação SSH em {ip}:{port}")


class SSHTimeoutError(BCConnectionError):
    """Timeout ao conectar ou executar comando via SSH."""

    error_code = "ssh_timeout"
    hint = "Verifique conectividade, porta SSH, rota/VPN e ajuste SSH_TIMEOUT se necessário."

    def __init__(self, ip: str, port: int):
        super().__init__(f"Timeout SSH em {ip}:{port}")


class BCParseError(BackupSyncError):
    """
    Levantada quando a resposta da API do BackupCenter não pode ser interpretada.
    Exemplos: JSON malformado, campos ausentes, formato inesperado de backup.
    """
    pass


class IPAMSyncError(BackupSyncError):
    """
    Levantada quando ocorre falha ao sincronizar dados com o phpIPAM.
    Exemplos: token inválido, endpoint inacessível, conflito de dados.
    """
    pass


class NetBoxSyncError(BackupSyncError):
    """Levantada quando ocorre falha ao sincronizar dados com o NetBox."""
    pass


class RetryableError(BackupSyncError):
    """Levantada para falhas transitórias que podem ser tentadas novamente."""
    pass


def _mask_url(url: str) -> str:
    try:
        parsed = httpx.URL(url)
    except Exception:
        return url.replace("@", "***@")
    if parsed.username or parsed.password:
        return str(parsed.copy_with(username="***", password="***"))
    return str(parsed)


@dataclass
class BCAPIError(BackupSyncError):
    message: str
    url: str
    status_code: int | None = None
    response_text: str | None = None

    def __str__(self) -> str:
        status = f"HTTP {self.status_code}" if self.status_code else "erro de rede"
        detail = f": {self.response_text[:300]}" if self.response_text else ""
        return f"{self.message} ({status}) em {_mask_url(self.url)}{detail}"


class VendorNotSupportedError(BackupSyncError):
    """
    Levantada quando o fabricante identificado não possui driver implementado.
    Exemplos: vendor='mikrotik', vendor='juniper', vendor='unknown'.
    """
    def __init__(self, vendor: str):
        self.vendor = vendor
        super().__init__(f"Fabricante não suportado: '{vendor}'. Drivers disponíveis: cisco, datacom, huawei, mikrotik, juniper, vsol, fiberhome, zte, intelbras, hillstone.")
