import asyncio
import os
import socket
import paramiko
from concurrent.futures import ThreadPoolExecutor

from logger import logger
from exceptions import BCConnectionError, SSHAuthError, SSHTimeoutError

# Máximo de conexões SSH simultâneas — configurável via variável de ambiente
MAX_SSH_CONCURRENT = int(os.getenv("MAX_SSH_CONCURRENT", "20"))

# Semáforo asyncio: limita quantas co-rotinas podem aguardar uma conexão SSH
# ao mesmo tempo, sem bloquear o event loop
_ssh_semaphore = asyncio.Semaphore(MAX_SSH_CONCURRENT)

# Thread pool para rodar o Paramiko (que é síncrono) fora do event loop
executor = ThreadPoolExecutor(max_workers=MAX_SSH_CONCURRENT)


def _ssh_timeout() -> int:
    return int(os.getenv("SSH_TIMEOUT", "30"))


def _raise_ssh_error(exc: Exception, ip: str, port: int, generic_prefix: str = "SSH falhou"):
    if isinstance(exc, paramiko.AuthenticationException):
        raise SSHAuthError(ip, port) from exc
    if isinstance(exc, (TimeoutError, socket.timeout)):
        raise SSHTimeoutError(ip, port) from exc
    raise BCConnectionError(f"{generic_prefix} para {ip}:{port}: {exc}") from exc


def _apply_host_key_policy(client: paramiko.SSHClient) -> None:
    """
    Aplica a política de verificação de host key no SSHClient, de forma
    centralizada e configurável por variável de ambiente. Esta é a ÚNICA função
    que mexe em host key policy — todos os pontos de conexão a chamam.

    SSH_HOST_KEY_POLICY (default: "tofu"):
      - "tofu": trust-on-first-use. No 1º contato com um host, a chave é aceita
        e PERSISTIDA em disco (SSH_KNOWN_HOSTS_FILE). Nos contatos seguintes a
        chave é verificada contra a persistida: se ela for a MESMA, conecta
        normalmente (sem prompt); se MUDAR, o Paramiko levanta
        BadHostKeyException (ganho anti-MITM).
      - "autoadd": comportamento LEGADO — aceita qualquer chave cegamente, sem
        persistir nem verificar (AutoAddPolicy puro, em memória). Serve como
        rollback de emergência via env, sem precisar reverter código.

    SSH_KNOWN_HOSTS_FILE: caminho do known_hosts próprio do app, usado no modo
    tofu. Default: ~/.ssh/horus_known_hosts (gravável pelo usuário que
    roda o processo).

    IMPORTANTE (não-quebrar): esta função NUNCA derruba uma conexão por causa de
    problema de arquivo/diretório. Se o known_hosts não puder ser criado/lido/
    gravado, loga um warning e cai para AutoAddPolicy em memória (exatamente o
    comportamento antigo), garantindo que a coleta continue funcionando.
    """
    # AutoAddPolicy é a base em AMBOS os modos. A diferença é que, no modo tofu,
    # client.load_host_keys(path) aponta para um arquivo GRAVÁVEL: aí o
    # AutoAddPolicy persiste a chave no 1º contato e o Paramiko passa a verificar
    # os contatos seguintes, levantando BadHostKeyException se a chave mudar.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    policy = os.getenv("SSH_HOST_KEY_POLICY", "tofu").strip().lower()
    if policy == "autoadd":
        # Rollback explícito: AutoAddPolicy puro, sem persistência nem verificação.
        return

    # Modo TOFU (default).
    path = os.getenv("SSH_KNOWN_HOSTS_FILE", "").strip() or os.path.expanduser(
        "~/.ssh/horus_known_hosts"
    )
    try:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        # load_host_keys() exige que o arquivo exista; cria vazio no 1º uso.
        if not os.path.exists(path):
            with open(path, "a", encoding="utf-8"):
                pass
        # Marca este arquivo como known_hosts gravável: o AutoAddPolicy passa a
        # persistir nele e o Paramiko passa a verificar as chaves já conhecidas.
        client.load_host_keys(path)
    except Exception as e:
        # Diretório/arquivo não gravável, permissão negada, etc. Nunca derruba a
        # conexão por isso: loga e segue com AutoAddPolicy em memória (legado).
        logger.warning(
            f"[SSH] known_hosts indisponível ({path}): {e}. "
            f"Caindo para AutoAddPolicy em memória (sem persistência/verificação)."
        )


def ssh_execute_sync(ip, user, pwd, command, port=22):
    ssh = paramiko.SSHClient()
    _apply_host_key_policy(ssh)
    timeout = _ssh_timeout()
    try:
        ssh.connect(ip, port=port, username=user, password=pwd, timeout=timeout)
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        return stdout.read().decode('utf-8', errors='ignore')
    except Exception as e:
        logger.warning(f"[SSH] Falha na conexão com {ip}:{port}: {e}")
        _raise_ssh_error(e, ip, port)
    finally:
        ssh.close()


def ssh_execute_with_proxy(target_ip, target_port, target_user, target_pass,
                            proxy_ip, proxy_port, proxy_user, proxy_pass,
                            setup_cmd, config_cmd):
    """
    Conecta no proxy (jump host) via SSH e cria túnel direto até o equipamento alvo.
    Executa setup_cmd (para desativar paginação) + config_cmd e retorna o output completo.
    """
    proxy = paramiko.SSHClient()
    _apply_host_key_policy(proxy)
    target = paramiko.SSHClient()
    _apply_host_key_policy(target)
    timeout = _ssh_timeout()

    try:
        # 1. Conectar no jump host
        try:
            proxy.connect(proxy_ip, port=proxy_port, username=proxy_user,
                          password=proxy_pass, timeout=timeout)
        except Exception as e:
            logger.warning(f"[SSH Proxy] Falha no jump host {proxy_ip}:{proxy_port}: {e}")
            _raise_ssh_error(e, proxy_ip, proxy_port)
        logger.info(f"[SSH Proxy] Conectado no jump host {proxy_ip}:{proxy_port}")

        # 2. Criar canal direto (túnel) do proxy até o equipamento alvo
        transport = proxy.get_transport()
        channel = transport.open_channel(
            "direct-tcpip", (target_ip, target_port), ("127.0.0.1", 0)
        )

        # 3. Conectar no equipamento alvo via túnel
        try:
            target.connect(target_ip, port=target_port, username=target_user,
                           password=target_pass, sock=channel, timeout=timeout)
        except Exception as e:
            logger.warning(f"[SSH Proxy] Falha no alvo {target_ip}:{target_port}: {e}")
            _raise_ssh_error(e, target_ip, target_port)
        logger.info(f"[SSH Proxy] Túnel aberto para {target_ip}:{target_port}")

        # 4. Executar setup (desativar paginação) se necessário
        if setup_cmd:
            target.exec_command(setup_cmd)
            import time
            time.sleep(0.5)  # Aguarda o setup ser aplicado

        # 5. Executar comando de config
        _, stdout, _ = target.exec_command(config_cmd, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        return output

    except (SSHAuthError, SSHTimeoutError):
        raise
    except Exception as e:
        logger.warning(f"[SSH Proxy] Falha na conexão {proxy_ip} → {target_ip}: {e}")
        raise BCConnectionError(
            f"SSH via proxy falhou ({proxy_ip} → {target_ip}:{target_port}): {e}"
        ) from e
    finally:
        target.close()
        proxy.close()


def ssh_execute_direct(target_ip, target_port, target_user, target_pass,
                       setup_cmd, config_cmd):
    """
    Conexão SSH direta (sem proxy) ao equipamento.
    Executa setup_cmd + config_cmd e retorna o output.
    """
    ssh = paramiko.SSHClient()
    _apply_host_key_policy(ssh)
    timeout = _ssh_timeout()
    try:
        ssh.connect(target_ip, port=target_port, username=target_user,
                    password=target_pass, timeout=timeout)
        logger.info(f"[SSH Direto] Conectado em {target_ip}:{target_port}")

        if setup_cmd:
            ssh.exec_command(setup_cmd)
            import time
            time.sleep(0.5)

        _, stdout, _ = ssh.exec_command(config_cmd, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        return output

    except Exception as e:
        logger.warning(f"[SSH Direto] Falha na conexão com {target_ip}:{target_port}: {e}")
        _raise_ssh_error(e, target_ip, target_port, "SSH direto falhou")
    finally:
        ssh.close()


async def run_ssh_task(ip, user, pwd, command, port=22):
    """Executa um comando SSH de forma assíncrona com controle de concorrência."""
    async with _ssh_semaphore:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            executor, ssh_execute_sync, ip, user, pwd, command, port
        )


async def run_ssh_extract(target_ip, target_port, target_user, target_pass,
                          setup_cmd, config_cmd,
                          proxy_ip=None, proxy_port=None,
                          proxy_user=None, proxy_pass=None):
    """
    Extrai configuração de um equipamento via SSH (direto ou via proxy).
    Versão async com controle de concorrência.
    """
    async with _ssh_semaphore:
        loop = asyncio.get_event_loop()
        if proxy_ip and proxy_user:
            return await loop.run_in_executor(
                executor,
                ssh_execute_with_proxy,
                target_ip, target_port, target_user, target_pass,
                proxy_ip, proxy_port, proxy_user, proxy_pass,
                setup_cmd, config_cmd
            )
        else:
            return await loop.run_in_executor(
                executor,
                ssh_execute_direct,
                target_ip, target_port, target_user, target_pass,
                setup_cmd, config_cmd
            )


def ssh_test_sync(target_ip, target_port, target_user, target_pass,
                  proxy_ip=None, proxy_port=None,
                  proxy_user=None, proxy_pass=None):
    """Testa conectividade/autenticacao SSH sem coletar configuracao."""
    if proxy_ip and proxy_user:
        proxy = paramiko.SSHClient()
        _apply_host_key_policy(proxy)
        target = paramiko.SSHClient()
        _apply_host_key_policy(target)
        timeout = _ssh_timeout()
        try:
            try:
                proxy.connect(proxy_ip, port=proxy_port, username=proxy_user,
                              password=proxy_pass, timeout=timeout)
            except Exception as e:
                _raise_ssh_error(e, proxy_ip, proxy_port)
            channel = proxy.get_transport().open_channel(
                "direct-tcpip", (target_ip, target_port), ("127.0.0.1", 0)
            )
            try:
                target.connect(target_ip, port=target_port, username=target_user,
                               password=target_pass, sock=channel, timeout=timeout)
            except Exception as e:
                _raise_ssh_error(e, target_ip, target_port)
            return True
        finally:
            target.close()
            proxy.close()

    ssh = paramiko.SSHClient()
    _apply_host_key_policy(ssh)
    timeout = _ssh_timeout()
    try:
        ssh.connect(target_ip, port=target_port, username=target_user,
                    password=target_pass, timeout=timeout)
        return True
    except Exception as e:
        _raise_ssh_error(e, target_ip, target_port)
    finally:
        ssh.close()


async def run_ssh_test(target_ip, target_port, target_user, target_pass,
                       proxy_ip=None, proxy_port=None,
                       proxy_user=None, proxy_pass=None):
    """Executa teste SSH de forma assíncrona com controle de concorrência."""
    async with _ssh_semaphore:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            executor,
            ssh_test_sync,
            target_ip, target_port, target_user, target_pass,
            proxy_ip, proxy_port, proxy_user, proxy_pass,
        )


def get_driver_class(vendor: str):
    """
    Retorna a classe do driver correto baseado no fabricante.
    Se o driver não existir, retorna um DummyDriver para não quebrar a API.
    """
    vendor = vendor.lower()

    if vendor == "cisco":
        try:
            from drivers.cisco import CiscoDriver
            return CiscoDriver
        except ImportError:
            logger.warning("Driver Cisco não encontrado.")
    elif vendor == "datacom":
        try:
            from drivers.datacom import DatacomDriver
            return DatacomDriver
        except ImportError:
            logger.warning("Driver Datacom não encontrado.")
    elif vendor == "huawei":
        try:
            from drivers.huawei import HuaweiDriver
            return HuaweiDriver
        except ImportError:
            logger.warning("Driver Huawei não encontrado.")
    elif vendor == "mikrotik":
        try:
            from drivers.mikrotik import MikrotikDriver
            return MikrotikDriver
        except ImportError:
            logger.warning("Driver MikroTik não encontrado.")
    elif vendor == "juniper":
        try:
            from drivers.juniper import JuniperDriver
            return JuniperDriver
        except ImportError:
            logger.warning("Driver Juniper não encontrado.")
    elif vendor == "vsol":
        try:
            from drivers.vsol import VsolDriver
            return VsolDriver
        except ImportError:
            logger.warning("Driver V-SOL não encontrado.")
    elif vendor == "fiberhome":
        try:
            from drivers.fiberhome import FiberHomeDriver
            return FiberHomeDriver
        except ImportError:
            logger.warning("Driver FiberHome não encontrado.")
    elif vendor == "zte":
        try:
            from drivers.zte import ZteDriver
            return ZteDriver
        except ImportError:
            logger.warning("Driver ZTE não encontrado.")
    elif vendor == "intelbras":
        try:
            from drivers.intelbras import IntelbrasDriver
            return IntelbrasDriver
        except ImportError:
            logger.warning("Driver Intelbras não encontrado.")
    elif vendor == "hillstone":
        try:
            from drivers.hillstone import HillstoneDriver
            return HillstoneDriver
        except ImportError:
            logger.warning("Driver Hillstone não encontrado.")
    else:
        logger.info(f"Vendor desconhecido: '{vendor}'. Usando DummyDriver.")

    # Fallback de segurança (Driver Fantasma)
    class DummyDriver:
        def __init__(self, *args, **kwargs):
            pass
        def parse_vlans(self, config_text):
            return []
        def parse_subnets(self, config_text):
            return []
        def parse_device_info(self, config_text):
            return {"model": None, "serial_number": None}

    return DummyDriver
