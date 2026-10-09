"""Cria tabelas de topologia: asset_interfaces, vlan_interfaces e coluna interface_id em subnets

Revision ID: 011_topology_tables
Revises: 010_users
Create Date: 2026-05-25
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '011_topology_tables'
down_revision: Union[str, None] = '010_users'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Tabela: asset_interfaces ──────────────────────────────────────────────
    # Representa interfaces físicas e lógicas de cada ativo de rede.
    # Populada pelo topology_parser.py durante a extração de configurações.
    op.create_table(
        'asset_interfaces',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        # physical | vlan | bridge | lag | loopback | tunnel | unknown
        sa.Column('type', sa.String(), nullable=False, server_default='physical'),
        sa.Column('description', sa.String(), nullable=True),
        # True se esta interface carrega o IP de gerência do ativo
        sa.Column('is_management', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.create_index('ix_asset_interfaces_id', 'asset_interfaces', ['id'])
    op.create_index('ix_asset_interfaces_asset_id', 'asset_interfaces', ['asset_id'])
    op.create_index('ix_asset_interfaces_name', 'asset_interfaces', ['name'])
    # Unicidade: um ativo não pode ter duas interfaces com o mesmo nome
    op.create_unique_constraint(
        'uq_asset_interfaces_asset_name',
        'asset_interfaces',
        ['asset_id', 'name'],
    )

    # ── Tabela: vlan_interfaces ───────────────────────────────────────────────
    # Mapeamento M:N entre VLANs e interfaces de um ativo.
    # Indica por quais interfaces físicas cada VLAN trafega e em qual modo
    # (access, trunk, tagged, native, routed).
    op.create_table(
        'vlan_interfaces',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('vlan_id', sa.Integer(), sa.ForeignKey('vlans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('interface_id', sa.Integer(), sa.ForeignKey('asset_interfaces.id', ondelete='CASCADE'), nullable=False),
        # access | trunk | tagged | native | routed
        sa.Column('mode', sa.String(), nullable=False, server_default='trunk'),
    )
    op.create_index('ix_vlan_interfaces_id', 'vlan_interfaces', ['id'])
    op.create_index('ix_vlan_interfaces_vlan_id', 'vlan_interfaces', ['vlan_id'])
    op.create_index('ix_vlan_interfaces_interface_id', 'vlan_interfaces', ['interface_id'])
    # Unicidade: a mesma VLAN não aparece duas vezes na mesma interface
    op.create_unique_constraint(
        'uq_vlan_interfaces_vlan_interface',
        'vlan_interfaces',
        ['vlan_id', 'interface_id'],
    )

    # ── Coluna: subnets.interface_id ─────────────────────────────────────────
    # FK nullable para a interface física onde o IP da subnet está configurado.
    op.add_column('subnets', sa.Column('interface_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_subnets_interface_id',
        'subnets', 'asset_interfaces',
        ['interface_id'], ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint('fk_subnets_interface_id', 'subnets', type_='foreignkey')
    op.drop_column('subnets', 'interface_id')

    op.drop_constraint('uq_vlan_interfaces_vlan_interface', 'vlan_interfaces', type_='unique')
    op.drop_index('ix_vlan_interfaces_interface_id', table_name='vlan_interfaces')
    op.drop_index('ix_vlan_interfaces_vlan_id', table_name='vlan_interfaces')
    op.drop_index('ix_vlan_interfaces_id', table_name='vlan_interfaces')
    op.drop_table('vlan_interfaces')

    op.drop_constraint('uq_asset_interfaces_asset_name', 'asset_interfaces', type_='unique')
    op.drop_index('ix_asset_interfaces_name', table_name='asset_interfaces')
    op.drop_index('ix_asset_interfaces_asset_id', table_name='asset_interfaces')
    op.drop_index('ix_asset_interfaces_id', table_name='asset_interfaces')
    op.drop_table('asset_interfaces')
