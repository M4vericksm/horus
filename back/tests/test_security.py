"""Testes de validação anti-SSRF (back/security.py)."""
import pytest
from security import validate_external_url


# ──────────────────────────────────────────
# Bloqueios permanentes — loopback, link-local/metadata
# ──────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "https://127.0.0.1:8080/api",
    "http://127.5.5.5/",
])
def test_loopback_ipv4_is_blocked(url):
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url(url)


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/",
    "https://169.254.0.1/metadata",
])
def test_link_local_ipv4_is_blocked(url):
    """169.254/16 — usado pelo AWS metadata service. SSRF clássico."""
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url(url)


def test_ipv6_loopback_is_blocked():
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url("http://[::1]/")


def test_ipv6_link_local_is_blocked():
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url("http://[fe80::1]/")


# ──────────────────────────────────────────
# Redes internas/VPN — liberadas por default, bloqueáveis por env
# ──────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://192.168.0.10:8080",
    "http://10.0.0.5",
    "http://172.16.0.1",
])
def test_private_ipv4_is_accepted_by_default(monkeypatch, url):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    validate_external_url(url)


def test_cgnat_tailscale_is_accepted_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    validate_external_url("http://100.64.1.1")


def test_metadata_is_always_blocked_even_when_private_targets_allowed(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url("http://169.254.169.254/latest/meta-data/")


def test_loopback_is_always_blocked_even_when_private_targets_allowed(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url("http://127.0.0.1")


@pytest.mark.parametrize("url", [
    "http://192.168.0.10",
    "http://10.1.2.3",
])
def test_private_ipv4_is_blocked_when_toggle_off(monkeypatch, url):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url(url)


def test_public_ipv4_is_accepted_when_toggle_off(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    validate_external_url("http://8.8.8.8")


# ──────────────────────────────────────────
# Schemes inválidos
# ──────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/",
    "gopher://example.com/",
    "ldap://example.com/",
])
def test_invalid_scheme_rejected(url):
    with pytest.raises(ValueError, match="Esquema"):
        validate_external_url(url)


# ──────────────────────────────────────────
# Host ausente / inválido
# ──────────────────────────────────────────

def test_missing_host_rejected():
    with pytest.raises(ValueError, match="Host"):
        validate_external_url("http://")


def test_unresolvable_host_rejected():
    with pytest.raises(ValueError, match="resolvível|Host"):
        validate_external_url("http://this-host-must-not-exist-12345.invalid/")


# ──────────────────────────────────────────
# URLs válidas (público) — não devem levantar
# ──────────────────────────────────────────

def test_public_ipv4_is_accepted():
    # 8.8.8.8 é público; não levanta exceção
    validate_external_url("https://8.8.8.8/")


def test_public_domain_is_accepted_when_resolvable(monkeypatch):
    """Mocka getaddrinfo para evitar dependência de rede no CI."""
    import socket
    def fake_getaddrinfo(host, port, type=None):
        return [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    validate_external_url("https://example.com/path")


def test_blocked_domain_when_resolves_to_private(monkeypatch):
    """Domínio que resolve para IP de loopback é bloqueado (DNS rebinding defense)."""
    import socket
    def fake_getaddrinfo(host, port, type=None):
        return [(socket.AF_INET, None, None, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError, match="bloqueado"):
        validate_external_url("https://localhost.evil.com/")
