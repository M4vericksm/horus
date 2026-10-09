import os

from cryptography.fernet import Fernet, InvalidToken

from exceptions import HorusError


def _looks_encrypted(value: str | None) -> bool:
    return bool(value and value.startswith("gAAAA"))


def _fernet() -> Fernet:
    key = os.getenv("FERNET_KEY")
    if not key:
        raise HorusError("FERNET_KEY não definido no ambiente.")
    return Fernet(key.encode())


def encrypt_secret(plain: str | None) -> str | None:
    if not plain or _looks_encrypted(plain):
        return plain
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(value: str | None) -> str | None:
    if not value:
        return value
    if not _looks_encrypted(value):
        return value
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise HorusError("Token criptografado inválido ou chave FERNET_KEY incorreta.") from exc
