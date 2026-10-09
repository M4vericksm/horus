import ipaddress
import os
import socket
from urllib.parse import urlparse

# Redes que nunca são alvo externo legítimo.
ALWAYS_BLOCKED = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),  # APIPA / AWS metadata (169.254.169.254)
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
]

# Redes internas/VPN. Bloqueadas apenas quando ALLOW_PRIVATE_TARGETS estiver off.
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT / Tailscale
    ipaddress.ip_network("fc00::/7"),       # ULA IPv6 (VPN/interno)
]


def validate_external_url(url: str) -> None:
    allow_private_targets = os.getenv("ALLOW_PRIVATE_TARGETS", "true").lower() in ("1", "true", "yes", "on")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Esquema inválido; use http ou https.")
    host = parsed.hostname
    if not host:
        raise ValueError("Host ausente.")

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError("Host inválido ou não resolvível.") from exc
        addresses = []
        for info in infos:
            addr = info[4][0]
            try:
                addresses.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
        if not addresses:
            raise ValueError("Host inválido ou não resolvível.")

    for ip in addresses:
        for net in ALWAYS_BLOCKED:
            if ip in net:
                raise ValueError(f"IP destino bloqueado por segurança: {ip}")
        if not allow_private_targets:
            for net in PRIVATE_NETS:
                if ip in net:
                    raise ValueError(f"IP destino bloqueado por segurança: {ip}")
