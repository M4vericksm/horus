"""Testes dos fluxos SSH em network_logic sem conexoes reais."""
import pytest

import network_logic
from exceptions import BCConnectionError, SSHAuthError, SSHTimeoutError


class FakeStdout:
    def __init__(self, text):
        self.text = text

    def read(self):
        return self.text.encode()


class FakeTransport:
    def open_channel(self, kind, target, source):
        return {"kind": kind, "target": target, "source": source}


class FakeSSHClient:
    fail_on_connect = False
    fail_exception = OSError("sem rota")
    instances = []

    def __init__(self):
        self.commands = []
        self.closed = False
        FakeSSHClient.instances.append(self)

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, *args, **kwargs):
        self.connect_args = args
        self.connect_kwargs = kwargs
        if FakeSSHClient.fail_on_connect:
            raise FakeSSHClient.fail_exception

    def exec_command(self, command, *args, **kwargs):
        self.commands.append(command)
        return None, FakeStdout(f"output:{command}"), FakeStdout("")

    def get_transport(self):
        return FakeTransport()

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def fake_paramiko(monkeypatch):
    FakeSSHClient.fail_on_connect = False
    FakeSSHClient.fail_exception = OSError("sem rota")
    FakeSSHClient.instances = []
    monkeypatch.setattr(network_logic.paramiko, "SSHClient", FakeSSHClient)


def test_ssh_execute_sync_success():
    output = network_logic.ssh_execute_sync("10.0.0.1", "u", "p", "show version", port=2222)

    assert output == "output:show version"
    assert FakeSSHClient.instances[0].connect_kwargs["port"] == 2222
    assert FakeSSHClient.instances[0].closed is True


def test_ssh_execute_sync_wraps_connection_error():
    FakeSSHClient.fail_on_connect = True

    with pytest.raises(BCConnectionError, match="SSH falhou"):
        network_logic.ssh_execute_sync("10.0.0.1", "u", "p", "cmd")

    assert FakeSSHClient.instances[0].closed is True


def test_ssh_execute_sync_uses_configured_timeout(monkeypatch):
    monkeypatch.setenv("SSH_TIMEOUT", "44")

    network_logic.ssh_execute_sync("10.0.0.1", "u", "p", "show version", port=2222)

    ssh = FakeSSHClient.instances[0]
    assert ssh.connect_kwargs["timeout"] == 44


def test_ssh_execute_sync_maps_auth_failure():
    FakeSSHClient.fail_on_connect = True
    FakeSSHClient.fail_exception = network_logic.paramiko.AuthenticationException("bad password")

    with pytest.raises(SSHAuthError, match="Falha de autenticação SSH em 10.0.0.1:22"):
        network_logic.ssh_execute_sync("10.0.0.1", "u", "p", "cmd")

    assert FakeSSHClient.instances[0].closed is True


def test_ssh_execute_direct_runs_setup_before_config(monkeypatch):
    monkeypatch.setattr(network_logic, "time", None, raising=False)
    output = network_logic.ssh_execute_direct(
        "10.0.0.2",
        22,
        "admin",
        "secret",
        "terminal length 0",
        "show running-config",
    )

    ssh = FakeSSHClient.instances[0]
    assert output == "output:show running-config"
    assert ssh.commands == ["terminal length 0", "show running-config"]
    assert ssh.closed is True


def test_ssh_execute_direct_allows_empty_setup():
    output = network_logic.ssh_execute_direct(
        "10.0.0.2",
        22,
        "admin",
        "secret",
        "",
        "show running-config",
    )

    assert output == "output:show running-config"
    assert FakeSSHClient.instances[0].commands == ["show running-config"]


def test_ssh_execute_direct_wraps_error():
    FakeSSHClient.fail_on_connect = True

    with pytest.raises(BCConnectionError, match="SSH direto falhou"):
        network_logic.ssh_execute_direct("10.0.0.2", 22, "admin", "secret", "", "show")

    assert FakeSSHClient.instances[0].closed is True


def test_ssh_execute_direct_maps_timeout():
    FakeSSHClient.fail_on_connect = True
    FakeSSHClient.fail_exception = TimeoutError("slow")

    with pytest.raises(SSHTimeoutError, match="Timeout SSH em 10.0.0.2:22"):
        network_logic.ssh_execute_direct("10.0.0.2", 22, "admin", "secret", "", "show")

    assert FakeSSHClient.instances[0].closed is True


def test_ssh_execute_with_proxy_success():
    output = network_logic.ssh_execute_with_proxy(
        target_ip="10.0.0.3",
        target_port=22,
        target_user="target",
        target_pass="target-pass",
        proxy_ip="192.0.2.10",
        proxy_port=2200,
        proxy_user="proxy",
        proxy_pass="proxy-pass",
        setup_cmd="screen-length 0 temporary",
        config_cmd="display current-configuration",
    )

    proxy, target = FakeSSHClient.instances
    assert output == "output:display current-configuration"
    assert proxy.connect_args[0] == "192.0.2.10"
    assert target.connect_kwargs["sock"]["target"] == ("10.0.0.3", 22)
    assert target.commands == ["screen-length 0 temporary", "display current-configuration"]
    assert proxy.closed is True
    assert target.closed is True


def test_ssh_execute_with_proxy_wraps_error():
    FakeSSHClient.fail_on_connect = True

    with pytest.raises(BCConnectionError, match="SSH via proxy falhou"):
        network_logic.ssh_execute_with_proxy(
            "10.0.0.3", 22, "target", "pass", "192.0.2.10", 2200, "proxy", "pass", "", "show"
        )

    assert all(client.closed for client in FakeSSHClient.instances)


def test_ssh_test_sync_direct_success():
    assert network_logic.ssh_test_sync("10.0.0.4", 22, "admin", "secret") is True
    ssh = FakeSSHClient.instances[0]
    assert ssh.connect_args[0] == "10.0.0.4"
    assert ssh.closed is True


def test_ssh_test_sync_proxy_success():
    assert network_logic.ssh_test_sync(
        "10.0.0.5",
        22,
        "target",
        "target-pass",
        proxy_ip="192.0.2.20",
        proxy_port=2200,
        proxy_user="proxy",
        proxy_pass="proxy-pass",
    ) is True

    proxy, target = FakeSSHClient.instances
    assert proxy.connect_args[0] == "192.0.2.20"
    assert target.connect_kwargs["sock"]["target"] == ("10.0.0.5", 22)
    assert proxy.closed is True
    assert target.closed is True


async def test_run_ssh_task_uses_sync_executor(monkeypatch):
    def fake_sync(ip, user, pwd, command, port=22):
        return f"{ip}:{port}:{command}"

    monkeypatch.setattr(network_logic, "ssh_execute_sync", fake_sync)

    assert await network_logic.run_ssh_task("1.1.1.1", "u", "p", "cmd", 2022) == "1.1.1.1:2022:cmd"


async def test_run_ssh_extract_selects_direct(monkeypatch):
    def fake_direct(*args):
        return "direct"

    monkeypatch.setattr(network_logic, "ssh_execute_direct", fake_direct)

    result = await network_logic.run_ssh_extract("1.1.1.1", 22, "u", "p", "", "cmd")
    assert result == "direct"


async def test_run_ssh_extract_selects_proxy(monkeypatch):
    def fake_proxy(*args):
        return "proxy"

    monkeypatch.setattr(network_logic, "ssh_execute_with_proxy", fake_proxy)

    result = await network_logic.run_ssh_extract(
        "1.1.1.1", 22, "u", "p", "", "cmd", proxy_ip="2.2.2.2", proxy_port=22, proxy_user="jump", proxy_pass="p"
    )
    assert result == "proxy"


async def test_run_ssh_test_uses_executor(monkeypatch):
    def fake_test(*args):
        return True

    monkeypatch.setattr(network_logic, "ssh_test_sync", fake_test)

    result = await network_logic.run_ssh_test("1.1.1.1", 22, "u", "p")
    assert result is True
