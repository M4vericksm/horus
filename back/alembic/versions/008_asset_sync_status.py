"""Adiciona status de ultima sincronizacao ao Asset

Revision ID: 008_asset_sync_status
Revises: 007_bc_device_id
Create Date: 2026-05-18
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '008_asset_sync_status'
down_revision: Union[str, None] = '007_bc_device_id'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('assets', sa.Column('last_sync_status', sa.String(), nullable=True))
    op.add_column('assets', sa.Column('last_sync_at', sa.DateTime(), nullable=True))
    op.add_column('assets', sa.Column('last_sync_error', sa.String(length=500), nullable=True))


def downgrade() -> None:
    op.drop_column('assets', 'last_sync_error')
    op.drop_column('assets', 'last_sync_at')
    op.drop_column('assets', 'last_sync_status')
