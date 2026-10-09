"""Adiciona email + MFA (TOTP) a User — login por e-mail com senha forte e MFA

Revision ID: 015_user_email_mfa
Revises: 014_vlan_config
Create Date: 2026-06-17
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '015_user_email_mfa'
down_revision: Union[str, None] = '014_vlan_config'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    if not _has_column('users', 'email'):
        op.add_column('users', sa.Column('email', sa.String(), nullable=True))
    if not _has_column('users', 'mfa_secret'):
        op.add_column('users', sa.Column('mfa_secret', sa.String(), nullable=True))
    if not _has_column('users', 'mfa_enabled'):
        op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), nullable=True))


def downgrade() -> None:
    for col in ('mfa_enabled', 'mfa_secret', 'email'):
        if _has_column('users', col):
            op.drop_column('users', col)
