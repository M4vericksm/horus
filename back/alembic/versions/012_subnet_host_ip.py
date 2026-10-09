"""Adiciona host_ip a Subnet (IP da interface para sync de addresses no phpIPAM)

Revision ID: 012_subnet_host_ip
Revises: 011_topology_tables
Create Date: 2026-06-04
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '012_subnet_host_ip'
down_revision: Union[str, None] = '011_topology_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    # Idempotente: o schema costuma vir de create_all (alembic é decorativo aqui),
    # então só adiciona a coluna se ela ainda não existir — evita falha em Postgres
    # já provisionado ou onde o ALTER TABLE manual já foi aplicado no deploy.
    if not _has_column('subnets', 'host_ip'):
        op.add_column('subnets', sa.Column('host_ip', sa.String(), nullable=True))


def downgrade() -> None:
    if _has_column('subnets', 'host_ip'):
        op.drop_column('subnets', 'host_ip')
