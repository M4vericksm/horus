"""Adiciona phpipam_user e phpipam_pass ao Client para re-autenticação automática

Revision ID: 005_phpipam_credentials
Revises: 004_subnet_vlan_link
Create Date: 2026-04-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '005_phpipam_credentials'
down_revision: Union[str, None] = '004_subnet_vlan_link'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('clients', sa.Column('phpipam_user', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('phpipam_pass', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('clients', 'phpipam_pass')
    op.drop_column('clients', 'phpipam_user')
