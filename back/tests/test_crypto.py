import os
import sys

from cryptography.fernet import Fernet
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto import decrypt_secret, encrypt_secret
from exceptions import BackupSyncError


def test_encrypt_decrypt_round_trip(monkeypatch):
    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())

    encrypted = encrypt_secret("segredo")

    assert encrypted != "segredo"
    assert encrypted.startswith("gAAAA")
    assert decrypt_secret(encrypted) == "segredo"


def test_empty_secret_round_trip(monkeypatch):
    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())

    assert encrypt_secret(None) is None
    assert encrypt_secret("") == ""
    assert decrypt_secret(None) is None
    assert decrypt_secret("") == ""


def test_plain_legacy_secret_is_returned_without_key(monkeypatch):
    monkeypatch.delenv("FERNET_KEY", raising=False)

    assert decrypt_secret("plain-token") == "plain-token"


def test_corrupted_encrypted_secret_raises(monkeypatch):
    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())

    with pytest.raises(BackupSyncError):
        decrypt_secret("gAAAAcorrompido")
