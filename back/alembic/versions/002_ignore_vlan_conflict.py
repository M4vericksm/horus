"""Adiciona campo ignore_vlan_conflict ao Asset

Revision ID: 002_ignore_vlan_conflict
Revises: 001_vpn_ssh
Create Date: 2026-04-20
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '002_ignore_vlan_conflict'
down_revision: Union[str, None] = '001_vpn_ssh'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('assets', sa.Column('ignore_vlan_conflict', sa.Boolean(), server_default='0', nullable=True))


def downgrade() -> None:
    op.drop_column('assets', 'ignore_vlan_conflict')
