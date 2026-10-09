from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
import os

# Lê a URL do banco exclusivamente via variável de ambiente.
# Se não estiver definida, o erro é explícito — nunca sobe com credencial hardcoded.
DATABASE_URL = os.environ["DATABASE_URL"]

# SQLite (usado em testes) não suporta pool_size/max_overflow e exige StaticPool
# para que conexões in-memory compartilhem o mesmo banco.
if DATABASE_URL.startswith("sqlite"):
    engine = create_async_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
else:
    engine = create_async_engine(
        DATABASE_URL,
        pool_size=20,
        max_overflow=10,
        echo=False,
    )

# Cria a fábrica de sessões assíncronas
AsyncSessionLocal = sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)


# Dependência do FastAPI para injetar a sessão do banco de dados nas rotas
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()