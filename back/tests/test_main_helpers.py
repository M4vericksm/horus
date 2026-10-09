"""Testes unitários de helpers puros de main.py — sem TestClient."""
import time

import pytest

from main import (
    api_error,
    _rate_limit_for,
    _rate_limited,
    _normalize_url,
    _encrypt_payload,
    _decrypt_attrs,
    _hash_password,
    _verify_password,
    RATE_BUCKETS,
)


# ──────────────────────────────────────────
# api_error
# ──────────────────────────────────────────

def test_api_error_with_hint():
    err = api_error("not_found", "Item não encontrado.", "Atualize a página.")
    assert err == {
        "code": "not_found",
        "message": "Item não encontrado.",
        "hint": "Atualize a página.",
    }


def test_api_error_without_hint():
    err = api_error("err", "msg")
    assert err["hint"] is None


# ──────────────────────────────────────────
# _rate_limit_for — limites por path
# ──────────────────────────────────────────

@pytest.mark.parametrize("path,limite", [
    ("/api/login", 5),
    ("/api/backupcenter/servers/test", 10),
    ("/api/netbox/probe", 10),
    ("/api/phpipam/probe", 10),
    ("/api/clients/1/discover-assets", 2),
    ("/api/clients/1/sync-phpipam", 5),
    ("/api/qualquer-outro", 120),
])
def test_rate_limit_for(path, limite):
    assert _rate_limit_for(path) == limite


# ──────────────────────────────────────────
# _rate_limited — controle de janela
# ──────────────────────────────────────────

def test_rate_limited_allows_below_limit():
    RATE_BUCKETS.clear()
    path = "/api/qualquer"  # limite 120
    now = time.monotonic()
    for i in range(10):
        assert _rate_limited("ip-test", path, now=now + i * 0.01) is False


def test_rate_limited_blocks_at_limit():
    RATE_BUCKETS.clear()
    path = "/api/login"  # limite 5
    now = time.monotonic()
    # Preenche 5 requisições
    for i in range(5):
        assert _rate_limited("ip-x", path, now=now + i * 0.1) is False
    # 6ª deve ser bloqueada
    assert _rate_limited("ip-x", path, now=now + 0.6) is True


def test_rate_limited_releases_after_window():
    RATE_BUCKETS.clear()
    path = "/api/login"
    now = time.monotonic()
    for i in range(5):
        _rate_limited("ip-y", path, now=now + i * 0.1)
    # Após 61s a janela expira
    assert _rate_limited("ip-y", path, now=now + 61) is False


def test_rate_limited_isolates_by_client_id():
    RATE_BUCKETS.clear()
    path = "/api/login"
    now = time.monotonic()
    for i in range(5):
        _rate_limited("ip-A", path, now=now + i * 0.1)
    # Cliente diferente continua livre
    assert _rate_limited("ip-B", path, now=now + 0.6) is False


# ──────────────────────────────────────────
# _normalize_url
# ──────────────────────────────────────────

@pytest.mark.parametrize("entrada,esperado", [
    ("http://10.0.0.1", "http://10.0.0.1"),
    ("https://exemplo.com/", "https://exemplo.com"),
    ("10.0.0.1", "https://10.0.0.1"),
    ("exemplo.com/", "https://exemplo.com"),
])
def test_normalize_url(entrada, esperado):
    assert _normalize_url(entrada) == esperado


# ──────────────────────────────────────────
# _encrypt_payload / _decrypt_attrs
# ──────────────────────────────────────────

class _Obj:
    """Objeto simples para simular um ORM com atributos."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_encrypt_payload_encrypts_only_listed_fields():
    payload = {"name": "X", "token": "secret-token", "other": "v"}
    out = _encrypt_payload(payload, {"token"})
    assert out["name"] == "X"
    assert out["other"] == "v"
    assert out["token"] != "secret-token"
    assert out["token"].startswith("gAAAA")  # Fernet prefix


def test_encrypt_payload_skips_empty_values():
    out = _encrypt_payload({"token": None, "other": ""}, {"token", "other"})
    assert out["token"] is None
    assert out["other"] == ""


def test_decrypt_attrs_roundtrip():
    payload = {"token": "segredo-original"}
    encrypted = _encrypt_payload(payload, {"token"})
    obj = _Obj(**encrypted)
    _decrypt_attrs(obj, {"token"})
    assert obj.token == "segredo-original"


# ──────────────────────────────────────────
# _hash_password / _verify_password
# ──────────────────────────────────────────

def test_hash_password_returns_salt_and_key():
    h = _hash_password("Senha123")
    salt, key = h.split(":")
    assert len(salt) == 64  # 32 bytes hex
    assert len(key) == 64


def test_hash_password_is_different_each_time():
    """Salt aleatório garante hashes distintos para a mesma senha."""
    assert _hash_password("Senha123") != _hash_password("Senha123")


def test_verify_password_accepts_correct_password():
    h = _hash_password("MinhaSenha")
    assert _verify_password("MinhaSenha", h) is True


def test_verify_password_rejects_wrong_password():
    h = _hash_password("MinhaSenha")
    assert _verify_password("OutraSenha", h) is False


def test_verify_password_returns_false_for_malformed_hash():
    assert _verify_password("qualquer", "hash-invalido-sem-colon") is False
    assert _verify_password("qualquer", "") is False
