"""Adiciona campos VPN ao Client e SSH + VPN override ao Asset

Revision ID: 001_vpn_ssh
Revises: None
Create Date: 2026-04-20
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_vpn_ssh'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Client: VPN / Jump Host global
    op.add_column('clients', sa.Column('vpn_host', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('vpn_port', sa.Integer(), server_default='22', nullable=True))
    op.add_column('clients', sa.Column('vpn_user', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('vpn_pass', sa.String(), nullable=True))

    # Asset: credenciais SSH
    op.add_column('assets', sa.Column('ssh_user', sa.String(), nullable=True))
    op.add_column('assets', sa.Column('ssh_pass', sa.String(), nullable=True))

    # Asset: VPN override por equipamento
    op.add_column('assets', sa.Column('override_vpn_host', sa.String(), nullable=True))
    op.add_column('assets', sa.Column('override_vpn_port', sa.Integer(), nullable=True))
    op.add_column('assets', sa.Column('override_vpn_user', sa.String(), nullable=True))
    op.add_column('assets', sa.Column('override_vpn_pass', sa.String(), nullable=True))


def downgrade() -> None:
    # Asset: remover VPN override
    op.drop_column('assets', 'override_vpn_pass')
    op.drop_column('assets', 'override_vpn_user')
    op.drop_column('assets', 'override_vpn_port')
    op.drop_column('assets', 'override_vpn_host')

    # Asset: remover SSH
    op.drop_column('assets', 'ssh_pass')
    op.drop_column('assets', 'ssh_user')

    # Client: remover VPN
    op.drop_column('clients', 'vpn_pass')
    op.drop_column('clients', 'vpn_user')
    op.drop_column('clients', 'vpn_port')
    op.drop_column('clients', 'vpn_host')
