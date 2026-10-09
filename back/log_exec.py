"""
Context manager para registrar execuções de operações no banco.

Uso:
    async with log_exec(db, client_id=1, operation="sync_assets") as ctx:
        # ... lógica ...
        ctx["message"] = "5 ativos sincronizados"

Se uma exceção for lançada, status=error é gravado automaticamente com o
traceback no campo detail. Se não houver exceção, status=success.
"""

import time
import traceback
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession

import models


@asynccontextmanager
async def log_exec(db: AsyncSession, *, client_id: int | None, operation: str):
    ctx = {"message": None, "status": "success", "detail": None}
    started = time.monotonic()
    try:
        yield ctx
        duration_ms = int((time.monotonic() - started) * 1000)
        log = models.ExecutionLog(
            client_id=client_id,
            operation=operation,
            status=ctx.get("status") or "success",
            message=ctx.get("message"),
            detail=ctx.get("detail"),
            duration_ms=duration_ms,
        )
        db.add(log)
        await db.commit()
    except Exception as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        log = models.ExecutionLog(
            client_id=client_id,
            operation=operation,
            status="error",
            message=str(exc),
            detail=traceback.format_exc(),
            duration_ms=duration_ms,
        )
        db.add(log)
        await db.commit()
        raise
