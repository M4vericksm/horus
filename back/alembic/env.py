"""
Alembic Environment — Configurado para SQLAlchemy Async (asyncpg).
Usa a mesma DATABASE_URL do projeto para conectar ao PostgreSQL.
"""
import os
import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

# Importa os models para que o Alembic conheça todas as tabelas
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# MetaData do projeto — é isso que o autogenerate usa como referência
target_metadata = models.Base.metadata

# URL do banco vem da variável de ambiente (mesmo lugar que o database.py usa)
DATABASE_URL = os.environ.get("DATABASE_URL", "")


def run_migrations_offline() -> None:
    """Gera SQL sem conectar no banco (modo offline)."""
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    """Executa as migrations usando uma conexão síncrona."""
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Conecta de forma assíncrona e executa as migrations."""
    connectable = create_async_engine(DATABASE_URL, poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Modo online — conecta no banco e executa."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
