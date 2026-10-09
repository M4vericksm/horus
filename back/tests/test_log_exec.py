"""Testes do context manager log_exec (back/log_exec.py)."""
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.future import select

import models
from log_exec import log_exec


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


# ──────────────────────────────────────────
# Caminho de sucesso
# ──────────────────────────────────────────

async def test_log_exec_success_persists_log(session):
    async with log_exec(session, client_id=42, operation="sync_assets") as ctx:
        ctx["message"] = "5 ativos sincronizados"

    res = await session.execute(select(models.ExecutionLog))
    logs = res.scalars().all()
    assert len(logs) == 1
    assert logs[0].operation == "sync_assets"
    assert logs[0].status == "success"
    assert logs[0].message == "5 ativos sincronizados"
    assert logs[0].client_id == 42


async def test_log_exec_records_duration_ms(session):
    async with log_exec(session, client_id=None, operation="quick") as ctx:
        ctx["message"] = "ok"

    res = await session.execute(select(models.ExecutionLog))
    log = res.scalars().first()
    assert log.duration_ms is not None
    assert log.duration_ms >= 0


async def test_log_exec_accepts_none_client_id(session):
    async with log_exec(session, client_id=None, operation="global") as ctx:
        ctx["message"] = "operação global"
    res = await session.execute(select(models.ExecutionLog))
    log = res.scalars().first()
    assert log.client_id is None
    assert log.status == "success"


# ──────────────────────────────────────────
# Caminho de erro — exceção dentro do with
# ──────────────────────────────────────────

async def test_log_exec_persists_error_on_exception(session):
    with pytest.raises(RuntimeError, match="boom"):
        async with log_exec(session, client_id=1, operation="failing_op"):
            raise RuntimeError("boom")

    res = await session.execute(select(models.ExecutionLog))
    logs = res.scalars().all()
    assert len(logs) == 1
    assert logs[0].status == "error"
    assert logs[0].message == "boom"
    assert "RuntimeError" in (logs[0].detail or "")
    assert "boom" in (logs[0].detail or "")


async def test_log_exec_reraises_original_exception(session):
    class CustomError(Exception):
        pass

    with pytest.raises(CustomError):
        async with log_exec(session, client_id=7, operation="custom"):
            raise CustomError("falha custom")

    res = await session.execute(select(models.ExecutionLog))
    log = res.scalars().first()
    assert log.status == "error"
    assert log.client_id == 7
