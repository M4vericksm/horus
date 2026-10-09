"""Criptografa tokens e senhas sensiveis com Fernet

Revision ID: 009_encrypt_secrets
Revises: 008_asset_sync_status
Create Date: 2026-05-18
"""
from typing import Sequence, Union
import os

from alembic import op
from sqlalchemy import text
from cryptography.fernet import Fernet

revision: str = '009_encrypt_secrets'
down_revision: Union[str, None] = '008_asset_sync_status'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SECRET_FIELDS = {
    "bc_servers": ("token",),
    "clients": ("token", "phpipam_pass", "netbox_token", "vpn_pass"),
    "assets": ("ssh_pass", "override_vpn_pass"),
}


def _fernet() -> Fernet:
    key = os.getenv("FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY precisa estar definido para executar a migration 009.")
    return Fernet(key.encode())


def _encrypt(value: str | None, f: Fernet) -> str | None:
    if not value or value.startswith("gAAAA"):
        return value
    return f.encrypt(value.encode()).decode()


def _decrypt(value: str | None, f: Fernet) -> str | None:
    if not value or not value.startswith("gAAAA"):
        return value
    return f.decrypt(value.encode()).decode()


def _rewrite(encrypting: bool) -> None:
    f = _fernet()
    bind = op.get_bind()
    for table, columns in SECRET_FIELDS.items():
        rows = bind.execute(
            text(f"SELECT id, {', '.join(columns)} FROM {table}")
        ).mappings().all()
        for row in rows:
            updates = {}
            for column in columns:
                current = row[column]
                new_value = _encrypt(current, f) if encrypting else _decrypt(current, f)
                if new_value != current:
                    updates[column] = new_value
            if not updates:
                continue
            set_clause = ", ".join(f"{column} = :{column}" for column in updates)
            params = dict(updates)
            params["id"] = row["id"]
            bind.execute(text(f"UPDATE {table} SET {set_clause} WHERE id = :id"), params)


def upgrade() -> None:
    _rewrite(encrypting=True)


def downgrade() -> None:
    _rewrite(encrypting=False)
