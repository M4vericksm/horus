"""Cria tabela de usuários do sistema

Revision ID: 010_users
Revises: 009_encrypt_secrets
Create Date: 2026-05-18
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '010_users'
down_revision: Union[str, None] = '009_encrypt_secrets'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('full_name', sa.String(), nullable=True),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint('username', name='uq_users_username'),
    )
    op.create_index('ix_users_id', 'users', ['id'])
    op.create_index('ix_users_username', 'users', ['username'])


def downgrade() -> None:
    op.drop_index('ix_users_username', table_name='users')
    op.drop_index('ix_users_id', table_name='users')
    op.drop_table('users')
