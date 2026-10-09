"""Adiciona config (bloco bruto) a Vlan — para exibir a configuração (vsi/l2vc/routed)

Revision ID: 014_vlan_config
Revises: 013_vlan_type
Create Date: 2026-06-17
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '014_vlan_config'
down_revision: Union[str, None] = '013_vlan_type'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    # Idempotente
    if not _has_column('vlans', 'config'):
        op.add_column('vlans', sa.Column('config', sa.String(), nullable=True))


def downgrade() -> None:
    if _has_column('vlans', 'config'):
        op.drop_column('vlans', 'config')
