"""Adiciona vlan_type a Vlan (para diferenciar L2/VSI/L2VC/routed)

Revision ID: 013_vlan_type
Revises: 012_subnet_host_ip
Create Date: 2026-06-16
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '013_vlan_type'
down_revision: Union[str, None] = '012_subnet_host_ip'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    # Idempotente
    if not _has_column('vlans', 'vlan_type'):
        op.add_column('vlans', sa.Column('vlan_type', sa.String(), nullable=True))


def downgrade() -> None:
    if _has_column('vlans', 'vlan_type'):
        op.drop_column('vlans', 'vlan_type')
