"""Cobertura dos jobs e scheduler declarados em main.py."""

import asyncio

import main


class _ScalarResult:
    def __init__(self, values):
        self.values = list(values)

    def scalars(self):
        return self

    def all(self):
        return self.values


class _FakeDB:
    def __init__(self, clients=None):
        self.clients = list(clients or [])

    async def execute(self, stmt):
        return _ScalarResult(self.clients)


class _AsyncContext:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _SessionFactory:
    def __init__(self, *sessions):
        self.sessions = list(sessions)

    def __call__(self):
        value = self.sessions.pop(0) if self.sessions else _FakeDB()
        return _AsyncContext(value)


def _run(coro):
    return asyncio.run(coro)


def test_run_global_extract_job_marks_success(monkeypatch):
    job_id = "job-ok"
    main.GLOBAL_JOBS[job_id] = {"id": job_id, "status": "queued"}

    monkeypatch.setattr(main.database, "AsyncSessionLocal", _SessionFactory(_FakeDB()))

    async def fake_sync(db, *, extract_configs=False, job=None):
        assert extract_configs is True
        job["progress"] = {"groups_seen": 1}
        return {"status": "success", "message": "Tudo sincronizado"}

    monkeypatch.setattr(main, "_sync_bc_groups_and_assets", fake_sync)

    _run(main._run_global_extract_job(job_id))

    assert main.GLOBAL_JOBS[job_id]["status"] == "completed"
    assert main.GLOBAL_JOBS[job_id]["phase"] == "completed"
    assert main.GLOBAL_JOBS[job_id]["message"] == "Tudo sincronizado"


def test_run_global_extract_job_marks_error(monkeypatch):
    job_id = "job-error"
    main.GLOBAL_JOBS[job_id] = {"id": job_id, "status": "queued"}
    monkeypatch.setattr(main.database, "AsyncSessionLocal", _SessionFactory(_FakeDB()))

    async def fake_sync(db, *, extract_configs=False, job=None):
        raise RuntimeError("BC indisponivel")

    monkeypatch.setattr(main, "_sync_bc_groups_and_assets", fake_sync)

    _run(main._run_global_extract_job(job_id))

    assert main.GLOBAL_JOBS[job_id]["status"] == "error"
    assert main.GLOBAL_JOBS[job_id]["phase"] == "failed"
    assert "BC indisponivel" in main.GLOBAL_JOBS[job_id]["message"]


def test_run_daily_sync_delegates_to_full_pipeline(monkeypatch):
    """O job diário agora delega ao pipeline completo (descoberta + ativos +
    extração + push IPAM), o mesmo do botão 'Extrair tudo'."""
    monkeypatch.setattr(main.database, "AsyncSessionLocal", _SessionFactory(_FakeDB()))
    calls = []

    async def fake_sync(db, *, extract_configs=False, job=None):
        calls.append((extract_configs, job))
        return {"status": "success", "message": "pipeline diário ok"}

    monkeypatch.setattr(main, "_sync_bc_groups_and_assets", fake_sync)

    _run(main._run_daily_sync())

    # Chamado exatamente uma vez, com extração ligada e sem job de progresso.
    assert calls == [(True, None)]


def test_run_daily_sync_survives_pipeline_exception(monkeypatch):
    """Falha do pipeline não pode propagar — senão o loop infinito do
    scheduler (_daily_sync_loop) morreria."""
    monkeypatch.setattr(main.database, "AsyncSessionLocal", _SessionFactory(_FakeDB()))

    async def fake_sync(db, *, extract_configs=False, job=None):
        raise RuntimeError("BC indisponivel")

    monkeypatch.setattr(main, "_sync_bc_groups_and_assets", fake_sync)

    # Não deve levantar.
    _run(main._run_daily_sync())
