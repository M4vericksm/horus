"""Adiciona vlan_id ao Subnet para linkar subnet à VLAN no phpIPAM

Revision ID: 004_subnet_vlan_link
Revises: 003_model_serial
Create Date: 2026-04-27
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '004_subnet_vlan_link'
down_revision: Union[str, None] = '003_model_serial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('subnets', sa.Column('vlan_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_subnets_vlan_id',
        'subnets', 'vlans',
        ['vlan_id'], ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint('fk_subnets_vlan_id', 'subnets', type_='foreignkey')
    op.drop_column('subnets', 'vlan_id')
