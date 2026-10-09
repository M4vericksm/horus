"""Adiciona bc_device_id (UUID imutável do equipamento na Backup API) ao Asset

Revision ID: 007_bc_device_id
Revises: 006_netbox_fields
Create Date: 2026-05-14
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '007_bc_device_id'
down_revision: Union[str, None] = '006_netbox_fields'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('assets', sa.Column('bc_device_id', sa.String(), nullable=True))
    op.create_index('ix_assets_bc_device_id', 'assets', ['bc_device_id'])


def downgrade() -> None:
    op.drop_index('ix_assets_bc_device_id', table_name='assets')
    op.drop_column('assets', 'bc_device_id')
