"""Adiciona campos NetBox dedicados ao Client

Revision ID: 006_netbox_fields
Revises: 005_phpipam_credentials
Create Date: 2026-05-10
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '006_netbox_fields'
down_revision: Union[str, None] = '005_phpipam_credentials'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('clients', sa.Column('netbox_url', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('netbox_token', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('netbox_vlan_group_id', sa.Integer(), nullable=True))
    op.add_column('clients', sa.Column('netbox_site_id', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('clients', 'netbox_site_id')
    op.drop_column('clients', 'netbox_vlan_group_id')
    op.drop_column('clients', 'netbox_token')
    op.drop_column('clients', 'netbox_url')
