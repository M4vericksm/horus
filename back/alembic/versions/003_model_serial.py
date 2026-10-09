"""Adiciona campos model e serial_number ao Asset

Revision ID: 003_model_serial
Revises: 002_ignore_vlan_conflict
Create Date: 2026-04-27
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '003_model_serial'
down_revision: Union[str, None] = '002_ignore_vlan_conflict'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # IF NOT EXISTS: colunas podem ter sido adicionadas manualmente antes desta migration
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS model VARCHAR")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS serial_number VARCHAR")


def downgrade() -> None:
    op.drop_column('assets', 'serial_number')
    op.drop_column('assets', 'model')
