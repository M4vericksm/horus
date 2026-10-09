from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import desc, and_, delete, func, or_
from sqlalchemy.exc import IntegrityError
from typing import List, Optional
from pydantic import BaseModel
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import asyncio
import base64
import hashlib
import hmac
import httpx
import json
import os
import secrets
import time
import uuid
from types import SimpleNamespace

import models
import database
import mailer
import auto_discovery
import sync_jobs
import topology_links
from bc_client import bc_headers, bc_url
from crypto import decrypt_secret, encrypt_secret
from exceptions import BCConnectionError, SSHAuthError, SSHTimeoutError
from logger import logger
from network_logic import run_ssh_test
from retry import RetryingAsyncClient
from security import validate_external_url
import zabbix_client
from drivers.cisco import CiscoDriver
from drivers.datacom import DatacomDriver
from drivers.huawei import HuaweiDriver
from drivers.juniper import JuniperDriver
from drivers.mikrotik import MikrotikDriver
from drivers.vsol import VsolDriver
from drivers.fiberhome import FiberHomeDriver
from drivers.zte import ZteDriver
from drivers.intelbras import IntelbrasDriver
from drivers.hillstone import HillstoneDriver
import hashlib

_CONCRETE_DRIVERS = [
    CiscoDriver, DatacomDriver, HuaweiDriver, MikrotikDriver, JuniperDriver,
    VsolDriver, FiberHomeDriver, ZteDriver, IntelbrasDriver, HillstoneDriver,
]


def _hash_password(plain: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, 260_000)
    return salt.hex() + ":" + key.hex()


def _verify_password(plain: str, stored: str) -> bool:
    try:
        salt_hex, key_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, 260_000)
        return secrets.compare_digest(key.hex(), key_hex)
    except Exception:
        return False

GLOBAL_JOBS = sync_jobs.GLOBAL_JOBS
RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}

# ── Sessões autenticadas (token assinado → stateless) ───────────────────────
# Gerado no login, validado pelo middleware; nunca expõe o HORUS_API_KEY ao front.
# Stateless e assinado por HMAC-SHA256: sobrevive a restart e vale em qualquer
# worker, pois todos compartilham o mesmo segredo. Sem store em memória — elimina
# o risco de perder/dessincronizar sessões em deploy multi-worker.
SESSION_TTL_HOURS: int = 8


def _session_secret() -> bytes:
    """Segredo usado para assinar tokens de sessão. Reaproveita o HORUS_API_KEY
    (já obrigatório); o HMAC é unidirecional, então a chave nunca vaza no token."""
    return os.getenv("HORUS_API_KEY", "").encode()


def _create_session(username: str, token_version: int = 0) -> str:
    """Gera um token de sessão assinado (HMAC-SHA256) com TTL de SESSION_TTL_HOURS
    horas. Formato: base64url(payload).hexdigest — stateless, sem persistência.
    `token_version` (campo "v") é a versão da sessão do usuário no momento do
    login; o logout a incrementa no banco e invalida todos os tokens antigos."""
    expires_at = int((datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).timestamp())
    raw = json.dumps({"u": username, "v": int(token_version or 0), "exp": expires_at}, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sig = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _session_claims(token: str) -> dict | None:
    """Valida assinatura + expiração e devolve os claims ({u, v, exp}) do token,
    ou None se inválido/expirado. Base para a checagem de revogação no middleware."""
    try:
        payload, sig = token.rsplit(".", 1)
    except (ValueError, AttributeError):
        return None
    expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = payload + "=" * (-len(payload) % 4)
        meta = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except Exception:
        return None
    if float(meta.get("exp", 0)) <= datetime.now(timezone.utc).timestamp():
        return None
    return meta


def _purge_expired_sessions() -> None:
    """No-op: sessões são stateless (assinadas), não há store a purgar.
    Mantido por compatibilidade com os call sites do middleware."""
    return None


def _validate_session(token: str) -> bool:
    """Retorna True se a assinatura conferir e o token não estiver expirado."""
    try:
        payload, sig = token.rsplit(".", 1)
    except ValueError:
        return False
    expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        padded = payload + "=" * (-len(payload) % 4)
        meta = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except Exception:
        return False
    return float(meta.get("exp", 0)) > datetime.now(timezone.utc).timestamp()


def api_error(code: str, message: str, hint: str | None = None) -> dict:
    return {"code": code, "message": message, "hint": hint}


# ── Identidade do usuário logado e papel de administrador ──────────────────────
# O administrador é designado pelo e-mail (HORUS_ADMIN_EMAIL). A coluna
# users.is_admin é honrada como reforço, mas o e-mail é a fonte canônica — assim
# uma conta antiga sem a flag, ou recriada, continua sendo reconhecida.
ADMIN_EMAIL = os.getenv("HORUS_ADMIN_EMAIL", "admin@example.com").strip().lower()


def _username_from_token(token: str) -> str | None:
    """Extrai o username de um token de sessão válido (assinatura + expiração)."""
    try:
        payload, sig = token.rsplit(".", 1)
    except (ValueError, AttributeError):
        return None
    expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = payload + "=" * (-len(payload) % 4)
        meta = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except Exception:
        return None
    if float(meta.get("exp", 0)) <= datetime.now(timezone.utc).timestamp():
        return None
    return meta.get("u")


def _is_admin_user(user) -> bool:
    if user is None:
        return False
    if getattr(user, "is_admin", False):
        return True
    email = (getattr(user, "email", None) or "").strip().lower()
    return bool(email and ADMIN_EMAIL and email == ADMIN_EMAIL)


# ── Auth self-service: e-mail corporativo, política de senha e MFA (TOTP) ──────
import re as _re_auth

# Domínios de e-mail permitidos no auto-cadastro (vírgula-separado). Por padrão, só o domínio da empresa;
# depois é só adicionar os domínios dos provedores aqui (env ALLOWED_EMAIL_DOMAINS).
ALLOWED_EMAIL_DOMAINS = [d.strip().lower() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "example.com").split(",") if d.strip()]
_EMAIL_RE = _re_auth.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match((email or "").strip()))


def _email_domain_ok(email: str) -> bool:
    email = (email or "").strip().lower()
    if "@" not in email:
        return False
    if not ALLOWED_EMAIL_DOMAINS:
        return True
    return email.rsplit("@", 1)[-1] in ALLOWED_EMAIL_DOMAINS


def _password_problem(pwd: str) -> str | None:
    """None se a senha for forte; senão a mensagem do problema."""
    p = pwd or ""
    if len(p) < 8:
        return "A senha deve ter ao menos 8 caracteres."
    if not _re_auth.search(r"[a-z]", p):
        return "A senha deve conter letra minúscula."
    if not _re_auth.search(r"[A-Z]", p):
        return "A senha deve conter letra maiúscula."
    if not _re_auth.search(r"[0-9]", p):
        return "A senha deve conter número."
    if not _re_auth.search(r"[^A-Za-z0-9]", p):
        return "A senha deve conter caractere especial."
    return None


# TOTP (RFC 6238) em Python puro — sem dependência externa.
def _totp_new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _totp_at(secret: str, counter: int) -> str:
    pad = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret + pad, casefold=True)
    h = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = ((h[o] & 0x7F) << 24 | (h[o + 1] & 0xFF) << 16 | (h[o + 2] & 0xFF) << 8 | (h[o + 3] & 0xFF)) % 1_000_000
    return f"{code:06d}"


def _totp_verify(secret: str, code: str, window: int = 1) -> bool:
    if not secret or not code:
        return False
    code = str(code).strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    counter = int(time.time()) // 30
    for off in range(-window, window + 1):
        if hmac.compare_digest(_totp_at(secret, counter + off), code):
            return True
    return False


def _otpauth_uri(email: str, secret: str, issuer: str = "Horus") -> str:
    import urllib.parse as _u
    label = _u.quote(f"{issuer}:{email}")
    params = _u.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": "6", "period": "30"})
    return f"otpauth://totp/{label}?{params}"


def _create_preauth(username: str) -> str:
    """Token curto (5 min) entre a etapa de senha e a etapa de MFA no login."""
    exp = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
    raw = json.dumps({"pa": username, "exp": exp}, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sig = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify_preauth(token: str) -> str | None:
    try:
        payload, sig = token.rsplit(".", 1)
    except (ValueError, AttributeError):
        return None
    expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = payload + "=" * (-len(payload) % 4)
        meta = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except Exception:
        return None
    if float(meta.get("exp", 0)) <= datetime.now(timezone.utc).timestamp():
        return None
    return meta.get("pa")


def _rate_limit_for(path: str) -> int:
    if path == "/api/login":
        return 5
    if path in ("/api/login/mfa", "/api/register", "/api/register/confirm"):
        return 8
    if path.endswith("/test") or path in {"/api/netbox/probe", "/api/phpipam/probe"}:
        return 10
    if path.endswith("/discover-assets") or "/bc-links/" in path and path.endswith("/discover"):
        return 2
    if "/sync-" in path:
        return 5
    return 120


_RATE_WINDOW = 60  # janela do rate limit, em segundos (inalterada)
_RATE_GC_INTERVAL = 60.0  # frequência máxima do GC de chaves ociosas
_LAST_RATE_GC = 0.0


def _gc_rate_buckets(now: float) -> None:
    """Remove do RATE_BUCKETS as chaves cujos timestamps estão TODOS fora da
    janela — evita o crescimento indefinido do dict em memória. Não altera a
    semântica do limite: só descarta entradas que já não contam para nenhum
    cliente/rota."""
    window_start = now - _RATE_WINDOW
    stale = [
        k for k, timestamps in RATE_BUCKETS.items()
        if not any(ts >= window_start for ts in timestamps)
    ]
    for k in stale:
        RATE_BUCKETS.pop(k, None)


def _client_ip(request: Request) -> str:
    """Identidade do cliente para o rate limit.

    Default (TRUST_PROXY ausente/≠ "true"): usa request.client.host — EXATAMENTE
    o comportamento atual. Só quando TRUST_PROXY=true (app atrás de um proxy
    confiável) o primeiro IP do X-Forwarded-For é usado. Isso evita que o IP do
    proxy seja usado como chave única (o que anularia o limite por cliente) sem
    mudar nada no deploy sem proxy."""
    if os.getenv("TRUST_PROXY", "").strip().lower() == "true":
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
    return request.client.host if request.client else "unknown"


def _rate_limited(client_id: str, path: str, now: float | None = None) -> bool:
    now = now or time.monotonic()
    # GC barato e amortizado: roda no máximo uma vez a cada _RATE_GC_INTERVAL s,
    # independentemente do volume de requisições.
    global _LAST_RATE_GC
    if now - _LAST_RATE_GC >= _RATE_GC_INTERVAL:
        _gc_rate_buckets(now)
        _LAST_RATE_GC = now
    key = (client_id, path)
    window_start = now - _RATE_WINDOW
    bucket = [ts for ts in RATE_BUCKETS.get(key, []) if ts >= window_start]
    limit = _rate_limit_for(path)
    if len(bucket) >= limit:
        RATE_BUCKETS[key] = bucket
        return True
    bucket.append(now)
    RATE_BUCKETS[key] = bucket
    return False


CLIENT_SECRET_FIELDS = {"token", "phpipam_pass", "netbox_token", "vpn_pass", "zabbix_token"}
ASSET_SECRET_FIELDS = {"ssh_pass", "override_vpn_pass"}


def _encrypt_payload(data: dict, secret_fields: set[str]) -> dict:
    payload = dict(data)
    for field in secret_fields:
        if field in payload and payload[field]:
            payload[field] = encrypt_secret(payload[field])
    return payload


def _decrypt_attrs(obj, fields: set[str]):
    for field in fields:
        if hasattr(obj, field):
            setattr(obj, field, decrypt_secret(getattr(obj, field)))
    return obj


# Segredos nunca saem do backend: respostas trazem a máscara e o frontend a
# devolve intacta quando o campo não foi alterado — _strip_masked descarta o
# valor mascarado no create/update, preservando o que está no banco.
SECRET_MASK = "********"


def _mask_attrs(obj, fields: set[str]):
    for field in fields:
        if hasattr(obj, field) and getattr(obj, field):
            setattr(obj, field, SECRET_MASK)
    return obj


def _strip_masked(data: dict, secret_fields: set[str]) -> dict:
    return {k: v for k, v in data.items() if not (k in secret_fields and v == SECRET_MASK)}


def _normalize_url(value: str) -> str:
    base = value.rstrip("/")
    # Default seguro: sem scheme assume https:// para não vazar token em http claro.
    # Quem opera serviço interno só-http precisa informar http:// explicitamente.
    return base if base.startswith("http") else f"https://{base}"


def _validate_external_url_or_400(url: str):
    try:
        validate_external_url(url)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=api_error("url_blocked", "URL bloqueada por política de segurança.", str(e)),
        ) from e


async def _unique_client_name(db: AsyncSession, desired: str, *, exclude_id: int | None = None) -> str:
    return await sync_jobs.unique_client_name(db, desired, exclude_id=exclude_id)


async def _run_extract_bg(client_id: int):
    """Fluxo completo em background: descoberta de ativos → extração de configs → VLANs/subnets.

    Cada etapa usa sessão própria: se a descoberta falhar a sessão fecha limpa
    e a extração ainda roda com os ativos já existentes.
    """
    async with database.AsyncSessionLocal() as db:
        try:
            await auto_discovery.sync_discovered_assets(client_id, db)
        except Exception as e:
            logger.warning(f"[extract_bg] Erro na descoberta para cliente {client_id}: {e}")

    async with database.AsyncSessionLocal() as db:
        try:
            await auto_discovery.extract_client_configs_bc(client_id, db)
        except Exception as e:
            logger.warning(f"[extract_bg] Erro na extração para cliente {client_id}: {e}")


async def _sync_bc_groups_and_assets(db: AsyncSession, *, extract_configs: bool = False, job: dict | None = None) -> dict:
    return await sync_jobs.sync_bc_groups_and_assets(
        db,
        extract_configs=extract_configs,
        job=job,
        http_client_factory=httpx.AsyncClient,
        unique_name_fn=_unique_client_name,
    )


async def _run_global_extract_job(job_id: str):
    await sync_jobs.run_global_extract_job(
        job_id,
        jobs=GLOBAL_JOBS,
        session_factory=database.AsyncSessionLocal,
        sync_fn=_sync_bc_groups_and_assets,
    )


async def _run_daily_sync():
    await sync_jobs.run_daily_sync(
        session_factory=database.AsyncSessionLocal,
        sync_fn=_sync_bc_groups_and_assets,
    )


async def _daily_sync_loop():
    await sync_jobs.daily_sync_loop(run_sync=_run_daily_sync)


# --- Lifespan (substitui o deprecado @app.on_event) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: aplica migrações e garante que tabelas existam
    logger.info("Iniciando Horus API...")
    if os.getenv("APP_ENV", "development").lower() in ("prod", "production"):
        missing = [name for name in ("HORUS_API_KEY", "FERNET_KEY", "ALLOWED_ORIGINS") if not os.getenv(name)]
        if missing:
            raise RuntimeError(f"Variáveis obrigatórias ausentes em produção: {', '.join(missing)}")

    # 1. Alembic em subprocesso: env.py usa asyncio.run(), incompatível com o loop do Uvicorn
    try:
        import subprocess
        import sys
        back_dir = os.path.dirname(os.path.abspath(__file__))
        alembic_ini = os.path.join(back_dir, "alembic.ini")
        if os.path.exists(alembic_ini):
            proc = subprocess.run(
                [sys.executable, "-m", "alembic", "-c", alembic_ini, "upgrade", "head"],
                cwd=back_dir,
                env=os.environ.copy(),
                capture_output=True,
                text=True,
                timeout=180,
            )
            if proc.returncode != 0:
                logger.warning(
                    "Alembic upgrade falhou (exit %s): %s",
                    proc.returncode,
                    (proc.stderr or proc.stdout or "").strip()[:2000],
                )
            else:
                logger.info("Migrações Alembic aplicadas com sucesso.")
    except Exception as e:
        logger.warning(f"Alembic não conseguiu rodar (banco novo?): {e}")

    # 2. create_all garante que tabelas existam (seguro: não altera tabelas que já existem)
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

    # 2b. Schema-guard: create_all NÃO altera tabelas existentes e o Alembic é
    #     decorativo (a cadeia morre na 001 em banco já provisionado, então
    #     migrações novas como a 012 nunca rodam). Sem isso, coluna nova em model
    #     antigo (ex.: subnets.host_ip) derruba qualquer SELECT com 500.
    #     Adiciona como nullable as colunas dos models que faltarem nas tabelas.
    def _ensure_model_columns(sync_conn):
        from sqlalchemy import inspect as sa_inspect, text as sa_text
        insp = sa_inspect(sync_conn)
        # Schema guard: adiciona colunas que podem não existir em bancos antigos (já criados pelo 001)
        # Ex.: subnets.host_ip foi adicionada na migration 012
        # Ex.: vlans.vlan_type foi adicionada na migration 013
        if "subnets" in insp.get_table_names():
            columns = [c["name"] for c in insp.get_columns("subnets")]
            if "host_ip" not in columns:
                sync_conn.execute(sa_text("ALTER TABLE subnets ADD COLUMN host_ip VARCHAR"))
        if "vlans" in insp.get_table_names():
            columns = [c["name"] for c in insp.get_columns("vlans")]
            if "vlan_type" not in columns:
                sync_conn.execute(sa_text("ALTER TABLE vlans ADD COLUMN vlan_type VARCHAR"))
            if "config" not in columns:
                sync_conn.execute(sa_text("ALTER TABLE vlans ADD COLUMN config VARCHAR"))
        
        for table in models.Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {col["name"] for col in insp.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                coltype = column.type.compile(sync_conn.dialect)
                sync_conn.execute(sa_text(
                    f'ALTER TABLE {table.name} ADD COLUMN {column.name} {coltype}'
                ))
                logger.warning("Schema-guard: coluna %s.%s criada (faltava no banco).",
                               table.name, column.name)

    async with database.engine.begin() as conn:
        await conn.run_sync(_ensure_model_columns)
    logger.info("Banco de dados pronto.")

    # 3. Seed de usuários padrão (cria apenas se não existirem).
    #    Senhas NUNCA são hardcoded: vêm de HORUS_SEED_<USERNAME>_PASSWORD.
    #    Se a env estiver ausente, gera uma senha aleatória e a registra no log
    #    (uma vez) para o operador trocar no primeiro acesso.
    #    E-mail corporativo: habilita login por e-mail E o reconhecimento de admin
    #    (_is_admin_user compara user.email == ADMIN_EMAIL). O maverick recebe
    #    exatamente ADMIN_EMAIL; os demais, <username>@<domínio autorizado>.
    _seed_domain = (ALLOWED_EMAIL_DOMAINS[0] if ALLOWED_EMAIL_DOMAINS else "example.com")
    _SEED_USERS = [
        ("maverick",  "Maverick Martins", ADMIN_EMAIL),
        ("operador",  "Operador",         f"operador@{_seed_domain}"),
        ("demo",      "Demo",             f"demo@{_seed_domain}"),
    ]
    async with database.AsyncSessionLocal() as db:
        for uname, fname, seed_email in _SEED_USERS:
            exists = (await db.execute(
                select(models.User).where(models.User.username == uname)
            )).scalars().first()
            if exists:
                # Backfill: usuários seed antigos foram criados sem e-mail, então o
                # login por e-mail falhava e o admin não era reconhecido. Preenche
                # se estiver vazio e o e-mail ainda não estiver em uso por outra conta.
                if not exists.email and seed_email:
                    clash = (await db.execute(
                        select(models.User).where(models.User.email == seed_email)
                    )).scalars().first()
                    if not clash:
                        exists.email = seed_email
                        logger.info("E-mail preenchido para usuário existente: %s -> %s", uname, seed_email)
                continue
            pwd = os.getenv(f"HORUS_SEED_{uname.upper()}_PASSWORD", "")
            if not pwd:
                pwd = secrets.token_urlsafe(16)
                logger.warning(
                    "Senha de '%s' não definida (HORUS_SEED_%s_PASSWORD). "
                    "Gerada aleatoriamente: %s — troque após o primeiro login.",
                    uname, uname.upper(), pwd,
                )
            db.add(models.User(
                username=uname,
                email=seed_email,
                full_name=fname,
                password_hash=_hash_password(pwd),
            ))
            logger.info("Usuário criado: %s (%s)", uname, seed_email)
        await db.commit()

    # Job de retenção: purge de logs com mais de 90 dias
    async with database.AsyncSessionLocal() as db:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=90)
        await db.execute(
            delete(models.ExecutionLog).where(models.ExecutionLog.created_at < cutoff)
        )
        await db.commit()
    logger.info("Retenção de logs executada.")

    asyncio.create_task(_daily_sync_loop())
    logger.info("[scheduler] Agendamento diário às 8h ativado.")

    yield
    # Shutdown: libera conexões do pool corretamente
    await database.engine.dispose()
    logger.info("Conexões encerradas. Bye!")

# --- Origens permitidas no CORS via variável de ambiente ---
APP_ENV = os.getenv("APP_ENV", "development").lower()
_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
if _raw_origins.strip():
    ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
elif APP_ENV in ("prod", "production"):
    raise RuntimeError("ALLOWED_ORIGINS precisa estar definido em produção.")
else:
    ALLOWED_ORIGINS = ["http://localhost:80", "http://localhost:5173"]

app = FastAPI(
    title="Horus API v5 - IPAM Orchestrator (VLAN & Subnet)",
    lifespan=lifespan
)


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    public_paths = {"/healthz", "/api/login", "/api/login/mfa", "/api/register", "/api/register/confirm", "/api/drivers", "/api/forgot-password", "/api/reset-password"}
    path = request.url.path
    # Preflight CORS (OPTIONS) deve passar direto — o browser não envia X-API-Key nessas
    if request.method == "OPTIONS":
        return await call_next(request)
    if path.startswith("/api"):
        client_host = _client_ip(request)
        if _rate_limited(client_host, path):
            return JSONResponse(
                status_code=429,
                content={"detail": api_error("rate_limited", "Muitas requisições em curto período.", "Aguarde alguns segundos e tente novamente.")},
            )
    if path.startswith("/api") and path not in public_paths:
        # Garante que HORUS_API_KEY está configurado (necessário para o servidor funcionar)
        if not os.getenv("HORUS_API_KEY", ""):
            return JSONResponse(
                status_code=500,
                content={"detail": api_error("api_key_not_configured", "HORUS_API_KEY não configurado.", "Defina HORUS_API_KEY no .env do backend.")},
            )
        provided = request.headers.get("X-API-Key", "")
        # 1) Assinatura + expiração (stateless, sem I/O).
        claims = _session_claims(provided) if provided else None
        if claims is None:
            return JSONResponse(
                status_code=401,
                content={"detail": api_error("session_invalid", "Sessão inválida ou expirada.", "Faça login novamente.")},
            )
        # 2) Revogação server-side: o token carrega a versão da sessão ("v") do
        #    momento do login; o logout incrementa users.token_version, então um
        #    token antigo passa a não casar e é recusado mesmo dentro do TTL.
        #    Também barra usuário inexistente/desativado. Em banco antigo a coluna
        #    pode ser NULL — tratada como 0.
        try:
            async with database.AsyncSessionLocal() as _db:
                _user = (await _db.execute(
                    select(models.User).where(
                        models.User.username == claims.get("u"),
                        models.User.is_active == True,
                    )
                )).scalars().first()
        except Exception:
            # Falha de banco: deixa seguir para o handler normal tratar/retornar
            # o erro apropriado, em vez de derrubar toda a API no middleware.
            _user = None
            return await call_next(request)
        if _user is None or int(getattr(_user, "token_version", 0) or 0) != int(claims.get("v", 0) or 0):
            return JSONResponse(
                status_code=401,
                content={"detail": api_error("session_invalid", "Sessão inválida ou expirada.", "Faça login novamente.")},
            )
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    # Expõe o header de paginação para o JS do front poder lê-lo (cross-origin).
    expose_headers=["X-Has-More"],
)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/drivers")
async def list_drivers():
    """Lista drivers de vendor disponíveis com metadata para o frontend."""
    return [
        {
            "vendor_key": cls.vendor_key,
            "display_name": cls.display_name,
            "supports_ssh_extract": cls.supports_ssh_extract,
            "supports_bc_extract": cls.supports_bc_extract,
        }
        for cls in _CONCRETE_DRIVERS
    ]


# ==========================================
# SCHEMAS (Pydantic) - AGORA À PROVA DE ERROS NULL
# ==========================================

class BCServerSchema(BaseModel):
    name: str
    url: str
    token: str

class BCServerTestSchema(BaseModel):
    url: str
    token: str

class PhpIPAMTestSchema(BaseModel):
    url: str
    token_name: str
    token: str
    phpipam_user: Optional[str] = None
    phpipam_pass: Optional[str] = None

class ZabbixTestSchema(BaseModel):
    url: str
    token: Optional[str] = None      # ausente quando o front reusa o token salvo (máscara)
    verify_tls: Optional[bool] = True
    client_id: Optional[int] = None  # se informado, usa o token salvo do cliente quando `token` vier mascarado

class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str


class RegisterConfirmRequest(BaseModel):
    email: str
    code: str


class MfaRequest(BaseModel):
    pre_auth: str
    code: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    is_active: bool
    is_admin: bool
    mfa_enabled: bool
    created_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    is_active: Optional[bool] = None

class BCServerResponse(BCServerSchema):
    id: int
    model_config = {"from_attributes": True}

class ClientSchema(BaseModel):
    name: str
    system: Optional[str] = "phpIPAM"
    ip: Optional[str] = None
    token_name: Optional[str] = None
    token: Optional[str] = None
    bc_server_id: Optional[int] = None       
    external_group_id: Optional[str] = None 
    l2_domain_id: Optional[int] = 1
    section_id: Optional[int] = 1            
    vlan_prefix: Optional[str] = None
    auto_approve_assets: Optional[bool] = False
    phpipam_user: Optional[str] = None
    phpipam_pass: Optional[str] = None
    netbox_url: Optional[str] = None
    netbox_token: Optional[str] = None
    netbox_vlan_group_id: Optional[int] = None
    netbox_site_id: Optional[int] = None
    vpn_host: Optional[str] = None
    vpn_port: Optional[int] = 22
    vpn_user: Optional[str] = None
    vpn_pass: Optional[str] = None
    zabbix_url: Optional[str] = None
    zabbix_token: Optional[str] = None
    zabbix_verify_tls: Optional[bool] = True

class ClientListResponse(ClientSchema):
    id: int
    status: Optional[str] = "success"
    asset_count: Optional[int] = 0
    vlan_count: Optional[int] = 0  
    subnet_count: Optional[int] = 0
    bc_server_name: Optional[str] = None
    has_bc_link: Optional[bool] = False   # tem vínculo em client_bc_links (origem Backup API)
    model_config = {"from_attributes": True}

# A CORREÇÃO ESTÁ AQUI: Tudo o que pode vir vazio do DB está como Optional
class AssetSchema(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    vendor: Optional[str] = None             # Antes exigia string e causava o Crash!
    model: Optional[str] = None
    serial_number: Optional[str] = None
    category: Optional[str] = "acesso"
    authority_level: Optional[int] = 5
    port: Optional[int] = 22
    is_approved: Optional[bool] = False
    is_edge_router: Optional[bool] = False
    sync_mode: Optional[str] = "auto"
    backup_id: Optional[str] = None          
    override_l2_domain_id: Optional[int] = None
    ignore_vlan_conflict: Optional[bool] = False
    client_id: Optional[int] = None          
    ssh_user: Optional[str] = None
    ssh_pass: Optional[str] = None
    override_vpn_host: Optional[str] = None
    override_vpn_port: Optional[int] = None
    override_vpn_user: Optional[str] = None
    override_vpn_pass: Optional[str] = None
    last_sync_status: Optional[str] = None
    last_sync_at: Optional[datetime] = None
    last_sync_error: Optional[str] = None

class AssetUpdateSchema(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    category: Optional[str] = None
    authority_level: Optional[int] = None
    is_edge_router: Optional[bool] = None
    sync_mode: Optional[str] = None
    backup_id: Optional[str] = None
    override_l2_domain_id: Optional[int] = None
    ignore_vlan_conflict: Optional[bool] = None
    is_approved: Optional[bool] = None
    ssh_user: Optional[str] = None
    ssh_pass: Optional[str] = None
    override_vpn_host: Optional[str] = None
    override_vpn_port: Optional[int] = None
    override_vpn_user: Optional[str] = None
    override_vpn_pass: Optional[str] = None
    last_sync_status: Optional[str] = None
    last_sync_at: Optional[datetime] = None
    last_sync_error: Optional[str] = None

class AssetResponse(AssetSchema):
    id: int
    client_id: int
    # Origem do ativo, somente leitura: preenchido = descoberto pela Backup API.
    # Fica fora do schema de entrada de propósito, para que a origem não possa ser
    # forjada num POST/PUT e liberar a exclusão de um ativo gerenciado.
    bc_device_id: Optional[str] = None
    model_config = {"from_attributes": True}

class VlanResponse(BaseModel):
    id: int
    vid: int
    name: str
    description: Optional[str] = ""
    vlan_type: Optional[str] = None
    asset_id: Optional[int] = None
    model_config = {"from_attributes": True}

class SubnetResponse(BaseModel):
    id: int
    network: str
    mask: int
    description: Optional[str] = ""
    asset_id: Optional[int] = None
    model_config = {"from_attributes": True}

class ClientBCLinkSchema(BaseModel):
    bc_server_id: int
    external_group_id: str
    label: Optional[str] = None

class ClientBCLinkResponse(ClientBCLinkSchema):
    id: int
    bc_server_name: Optional[str] = None
    model_config = {"from_attributes": True}

class VlanConflictResolutionItem(BaseModel):
    vid: int
    asset_id: int
    domain_id: int
    vlan_ipam_id: Optional[str] = None
    local_vlan_id: Optional[int] = None
    action: str  # "update_name" | "create_l2" | "create_group"
    new_l2_name: Optional[str] = None
    existing_l2_id: Optional[int] = None
    new_group_name: Optional[str] = None
    new_name: Optional[str] = None

class VlanConflictResolutionRequest(BaseModel):
    resolutions: List[VlanConflictResolutionItem]

class CreateL2DomainRequest(BaseModel):
    name: str

class SSHTestRequest(BaseModel):
    asset_id: int

class ExecutionLogResponse(BaseModel):
    id: int
    client_id: Optional[int] = None
    operation: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None
    detail: Optional[str] = None
    duration_ms: Optional[int] = None
    created_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


# ==========================================
# INICIALIZAÇÃO
# ==========================================
# (movida para o lifespan acima)


# ==========================================
# ROTAS: SERVIDORES BACKUP_API
# ==========================================
def _session_payload(user) -> dict:
    return {
        "session_token": _create_session(user.username, getattr(user, "token_version", 0) or 0),
        "expires_in": SESSION_TTL_HOURS * 3600,
        "username": user.username,
        "email": user.email,
    }


@app.post("/api/login")
async def login(data: LoginRequest, db: AsyncSession = Depends(database.get_db)):
    if not os.getenv("HORUS_API_KEY", ""):
        raise HTTPException(
            status_code=500,
            detail=api_error("api_key_not_configured", "HORUS_API_KEY não configurado.", "Defina HORUS_API_KEY no .env do backend."),
        )
    ident = (data.email or data.username or "").strip()
    if not ident or not data.password:
        raise HTTPException(status_code=401, detail=api_error("login_invalid", "Informe e-mail e senha.", "Preencha os dois campos."))
    if "@" in ident:
        user = (await db.execute(select(models.User).where(models.User.email == ident.lower(), models.User.is_active == True))).scalars().first()
    else:
        user = (await db.execute(select(models.User).where(models.User.username == ident, models.User.is_active == True))).scalars().first()
    if not user or not _verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail=api_error("login_invalid", "E-mail ou senha inválidos.", "Verifique suas credenciais."),
        )
    # MFA é obrigatório para todos. Conta sem enrolamento (seed antigo ou criada
    # pelo admin) recebe o segredo aqui e só entra após confirmar o 1º código —
    # o segredo vai junto do pre_auth, que exige senha correta para ser emitido.
    if not (user.mfa_enabled and user.mfa_secret):
        if not user.mfa_secret:
            user.mfa_secret = _totp_new_secret()
            await db.commit()
        return {
            "mfa_enrollment_required": True,
            "pre_auth": _create_preauth(user.username),
            "otpauth_uri": _otpauth_uri(user.email or user.username, user.mfa_secret),
            "secret": user.mfa_secret,
        }
    return {"mfa_required": True, "pre_auth": _create_preauth(user.username)}


@app.post("/api/login/mfa")
async def login_mfa(data: MfaRequest, db: AsyncSession = Depends(database.get_db)):
    username = _verify_preauth(data.pre_auth)
    if not username:
        raise HTTPException(status_code=401, detail=api_error("mfa_preauth_invalid", "Etapa de login expirada.", "Faça login novamente."))
    user = (await db.execute(select(models.User).where(models.User.username == username, models.User.is_active == True))).scalars().first()
    if not user or not user.mfa_secret or not _totp_verify(user.mfa_secret, data.code):
        raise HTTPException(status_code=401, detail=api_error("mfa_invalid", "Código de verificação inválido.", "Confira o código de 6 dígitos no app autenticador."))
    # Primeiro código válido de uma conta sem enrolamento conclui a ativação do MFA.
    if not user.mfa_enabled:
        user.mfa_enabled = True
        await db.commit()
    return _session_payload(user)


@app.post("/api/register")
async def register(data: RegisterRequest, db: AsyncSession = Depends(database.get_db)):
    """Auto-cadastro: e-mail corporativo + senha forte → devolve o QR (otpauth) do MFA."""
    email = (data.email or "").strip().lower()
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail=api_error("email_invalid", "E-mail inválido.", "Use seu e-mail corporativo."))
    if not _email_domain_ok(email):
        dom = ALLOWED_EMAIL_DOMAINS[0] if ALLOWED_EMAIL_DOMAINS else ""
        raise HTTPException(status_code=403, detail=api_error("email_domain_blocked", f"Domínio não autorizado. Use um e-mail @{dom}.", "Cadastro restrito à equipe autorizada."))
    problem = _password_problem(data.password)
    if problem:
        raise HTTPException(status_code=400, detail=api_error("password_weak", problem, "8+ caracteres com maiúscula, minúscula, número e caractere especial."))

    # NUNCA sobrescrever credencial de conta existente. A versão anterior só
    # barrava quando o MFA já estava ativo, então um auto-cadastro com o e-mail
    # de uma conta sem MFA (os usuários de seed, inclusive o administrador)
    # trocava a senha e o segredo dessa conta e devolvia o QR a quem pedisse —
    # tomada de conta sem precisar de credencial nenhuma.
    existing = (await db.execute(select(models.User).where(models.User.email == email))).scalars().first()
    if existing:
        raise HTTPException(status_code=409, detail=api_error(
            "email_taken", "Já existe conta com esse e-mail.",
            "Faça login. Se esqueceu a senha, use 'Esqueci minha senha'."))

    # Auto-cadastro do domínio corporativo entra ATIVO e segue direto para o
    # enrolamento do MFA — sem aprovação manual. A barreira é: domínio restrito
    # (@example.com) + senha forte + segundo fator obrigatório.
    username = email.split("@", 1)[0] + "_" + secrets.token_hex(3)
    secret = _totp_new_secret()
    user = models.User(username=username, email=email, full_name=email.split("@", 1)[0],
                       password_hash=_hash_password(data.password),
                       mfa_secret=secret, mfa_enabled=False, is_active=True)
    db.add(user)
    await db.commit()
    logger.info("Cadastro self-service ativo: %s (%s)", username, email)
    # Mesmo payload do login para conta sem MFA: o front mostra o QR e o 1º código
    # válido conclui o enrolamento e já emite a sessão (via /login/mfa).
    return {
        "mfa_enrollment_required": True,
        "pre_auth": _create_preauth(username),
        "otpauth_uri": _otpauth_uri(email, secret),
        "secret": secret,
    }


@app.post("/api/register/confirm")
async def register_confirm(data: RegisterConfirmRequest, db: AsyncSession = Depends(database.get_db)):
    """Enrolamento de MFA do cadastro self-service.

    Mantido por compatibilidade com o fluxo antigo. Como o cadastro agora nasce
    inativo, a conta continua sem acesso até a aprovação: aqui não se emite
    sessão. O enrolamento definitivo acontece no primeiro login aprovado.
    """
    email = (data.email or "").strip().lower()
    user = (await db.execute(select(models.User).where(models.User.email == email))).scalars().first()
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=404, detail=api_error("register_not_found", "Cadastro não encontrado.", "Refaça o cadastro."))
    if not _totp_verify(user.mfa_secret, data.code):
        raise HTTPException(status_code=401, detail=api_error("mfa_invalid", "Código inválido.", "Confira o código no app autenticador."))
    user.mfa_enabled = True
    await db.commit()
    if not user.is_active:
        return {"pending_approval": True,
                "message": "MFA confirmado. Aguardando aprovação de um administrador."}
    return _session_payload(user)


# ==========================================
# ROTAS: RESET / DEFINIÇÃO DE SENHA (esqueci minha senha + convite)
# ==========================================
def _hash_reset_token(token: str) -> str:
    """SHA-256 hex do token — só o hash é persistido; o token cru vai no e-mail."""
    return hashlib.sha256((token or "").encode()).hexdigest()


def _issue_reset_token(user, hours: int = 2) -> str:
    """Gera um token de reset, grava o hash+validade no usuário e devolve o cru."""
    raw = secrets.token_urlsafe(32)
    user.password_reset_token = _hash_reset_token(raw)
    # A coluna é TIMESTAMP WITHOUT TIME ZONE (naive, como created_at); gravamos
    # UTC sem tzinfo para o asyncpg não recusar (não dá para misturar naive/aware).
    user.password_reset_expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).replace(tzinfo=None)
    return raw


@app.post("/api/forgot-password")
async def forgot_password(data: ForgotPasswordRequest, db: AsyncSession = Depends(database.get_db)):
    """Inicia a recuperação de senha. Resposta SEMPRE genérica (não revela se o
    e-mail existe). Para conta ativa existente, gera token e envia o link."""
    email = (data.email or "").strip().lower()
    generic = {"ok": True, "message": "Se houver uma conta com esse e-mail, enviamos as instruções de redefinição."}
    if not _valid_email(email):
        return generic
    user = (await db.execute(select(models.User).where(
        models.User.email == email, models.User.is_active == True))).scalars().first()
    if not user:
        return generic
    raw = _issue_reset_token(user, hours=2)
    await db.commit()
    link = f"{mailer.public_base_url()}/login.html?reset={raw}"
    nome = user.full_name or user.username
    corpo = (
        f"Olá, {nome}.\n\n"
        f"Recebemos um pedido para redefinir a senha da sua conta no Horus.\n"
        f"Para criar uma nova senha, acesse o link abaixo (válido por 2 horas):\n\n"
        f"{link}\n\n"
        f"Se você não solicitou, ignore este e-mail — sua senha atual continua valendo.\n"
    )
    mailer.send_email(email, "Horus — redefinição de senha", corpo)
    return generic


@app.post("/api/reset-password")
async def reset_password(data: ResetPasswordRequest, db: AsyncSession = Depends(database.get_db)):
    """Conclui a redefinição: valida token+validade, aplica a senha nova, limpa o
    token e incrementa token_version (revoga sessões antigas)."""
    token = (data.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail=api_error("reset_token_invalid", "Link inválido.", "Solicite um novo link de redefinição."))
    problem = _password_problem(data.password)
    if problem:
        raise HTTPException(status_code=400, detail=api_error("password_weak", problem, "8+ caracteres com maiúscula, minúscula, número e caractere especial."))
    th = _hash_reset_token(token)
    user = (await db.execute(select(models.User).where(
        models.User.password_reset_token == th, models.User.is_active == True))).scalars().first()
    exp = getattr(user, "password_reset_expires", None) if user else None
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if not user or exp is None or exp <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail=api_error("reset_token_invalid", "Link expirado ou inválido.", "Solicite um novo link de redefinição."))
    user.password_hash = _hash_password(data.password)
    user.password_reset_token = None
    user.password_reset_expires = None
    user.token_version = int(getattr(user, "token_version", 0) or 0) + 1
    await db.commit()
    return {"ok": True, "message": "Senha redefinida com sucesso. Faça login com a nova senha."}


# ==========================================
# ROTAS: GESTÃO DE USUÁRIOS (restrita ao administrador)
# ==========================================
async def _current_user(request: Request, db: AsyncSession = Depends(database.get_db)) -> models.User:
    """Resolve o usuário logado a partir do X-API-Key (já validado pelo middleware)."""
    uname = _username_from_token(request.headers.get("X-API-Key", ""))
    user = None
    if uname:
        user = (await db.execute(
            select(models.User).where(models.User.username == uname, models.User.is_active == True)
        )).scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail=api_error("session_invalid", "Sessão inválida ou expirada.", "Faça login novamente."))
    return user


async def _require_admin(user: models.User = Depends(_current_user)) -> models.User:
    if not _is_admin_user(user):
        raise HTTPException(status_code=403, detail=api_error("admin_only", "Acesso restrito ao administrador.", "Esta área é exclusiva do administrador do sistema."))
    return user


@app.get("/api/me")
async def get_me(user: models.User = Depends(_current_user)):
    """Perfil do usuário logado — o front usa is_admin para exibir a gestão."""
    return {"username": user.username, "email": user.email, "full_name": user.full_name, "is_admin": _is_admin_user(user)}


@app.post("/api/logout")
async def logout(user: models.User = Depends(_current_user), db: AsyncSession = Depends(database.get_db)):
    """Encerra a sessão: incrementa users.token_version, o que revoga server-side
    TODOS os tokens emitidos para este usuário (inclusive em outros dispositivos),
    mesmo antes do fim do TTL. O front ainda limpa o token do localStorage."""
    user.token_version = int(getattr(user, "token_version", 0) or 0) + 1
    await db.commit()
    return {"ok": True}


@app.get("/api/users", response_model=List[UserResponse])
async def list_users(_: models.User = Depends(_require_admin), db: AsyncSession = Depends(database.get_db)):
    res = await db.execute(select(models.User).order_by(models.User.created_at.desc().nullslast(), models.User.id.desc()))
    return [
        UserResponse(
            id=u.id, username=u.username, email=u.email, full_name=u.full_name,
            is_active=bool(u.is_active), is_admin=_is_admin_user(u),
            mfa_enabled=bool(u.mfa_enabled), created_at=u.created_at,
        )
        for u in res.scalars().all()
    ]


@app.patch("/api/users/{user_id}")
async def update_user(user_id: int, data: UserUpdateRequest, admin: models.User = Depends(_require_admin), db: AsyncSession = Depends(database.get_db)):
    target = await db.get(models.User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail=api_error("user_not_found", "Usuário não encontrado.", "Atualize a lista."))
    if data.is_active is not None:
        if _is_admin_user(target) and not data.is_active:
            raise HTTPException(status_code=400, detail=api_error("cannot_disable_admin", "Não é possível desativar o administrador.", "A conta admin precisa permanecer ativa."))
        target.is_active = data.is_active
    await db.commit()
    return {"id": target.id, "username": target.username, "is_active": bool(target.is_active)}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, admin: models.User = Depends(_require_admin), db: AsyncSession = Depends(database.get_db)):
    target = await db.get(models.User, user_id)
    if not target:
        return {"message": "Usuário já removido."}
    if target.id == admin.id or _is_admin_user(target):
        raise HTTPException(status_code=400, detail=api_error("cannot_delete_admin", "Não é possível excluir o administrador.", "A conta admin não pode ser removida."))
    await db.delete(target)
    await db.commit()
    return {"message": "Usuário removido com sucesso."}


@app.get("/api/backup/servers", response_model=List[BCServerResponse])
async def get_bc_servers(db: AsyncSession = Depends(database.get_db)):
    res = await db.execute(select(models.BCServer))
    return [_mask_attrs(server, {"token"}) for server in res.scalars().all()]

@app.post("/api/backup/servers", response_model=BCServerResponse)
async def create_bc_server(server: BCServerSchema, db: AsyncSession = Depends(database.get_db)):
    db_server = models.BCServer(**_encrypt_payload(server.model_dump(), {"token"}))
    db.add(db_server)
    await db.commit()
    await db.refresh(db_server)
    return _mask_attrs(db_server, {"token"})

@app.delete("/api/backup/servers/{server_id}")
async def delete_bc_server(server_id: int, db: AsyncSession = Depends(database.get_db)):
    server = await db.get(models.BCServer, server_id)
    if server:
        await db.delete(server)
        await db.commit()
    return {"message": "Servidor removido com sucesso"}


# ==========================================
# ROTAS: TESTE DE CONECTIVIDADE (sem persistência)
# ==========================================
@app.post("/api/backup/servers/test")
async def test_bc_server_connection(data: BCServerTestSchema):
    """Testa conectividade com um servidor Backup API antes de salvar."""
    _validate_external_url_or_400(_normalize_url(data.url))
    server = SimpleNamespace(id="test", url=data.url, token=data.token)
    try:
        async with httpx.AsyncClient(verify=True) as client_http:
            res = await client_http.get(bc_url(server, "groups"), headers=bc_headers(server), timeout=8)
        if res.status_code == 200:
            return {"ok": True, "message": "Conexão estabelecida com sucesso.", "ssl_error": False, "auth_error": False}
        if res.status_code in (401, 403):
            return {"ok": False, "message": f"Token inválido ou sem permissão (HTTP {res.status_code}). Verifique o token de autenticação.", "ssl_error": False, "auth_error": True}
        return {"ok": False, "message": f"Servidor respondeu com HTTP {res.status_code}. Verifique a URL e a configuração da API.", "ssl_error": False, "auth_error": False}
    except httpx.ConnectError as e:
        is_ssl = "ssl" in str(e).lower() or "certificate" in str(e).lower()
        logger.warning(f"[BC Test] Connect error (ssl={is_ssl}): {e}")
        if is_ssl:
            return {"ok": False, "message": "Erro de SSL: o certificado do servidor não é válido ou não é confiável. A maioria das APIs Backup API exige HTTPS com certificado válido.", "ssl_error": True, "auth_error": False}
        return {"ok": False, "message": "Não foi possível conectar ao servidor. Verifique se a URL está correta e se o servidor está acessível na rede.", "ssl_error": False, "auth_error": False}
    except httpx.TimeoutException:
        return {"ok": False, "message": "Timeout: o servidor demorou demais para responder (>8s). Verifique a URL e a disponibilidade do servidor.", "ssl_error": False, "auth_error": False}
    except Exception as e:
        logger.warning(f"[BC Test] Erro inesperado: {e}")
        return {"ok": False, "message": f"Erro inesperado ao testar conexão: {e}", "ssl_error": False, "auth_error": False}


@app.post("/api/phpipam/test")
async def test_phpipam_connection(data: PhpIPAMTestSchema):
    """Testa conectividade com um servidor phpIPAM antes de salvar."""
    base = _normalize_url(data.url)
    _validate_external_url_or_400(base)
    url = f"{base}/api/{data.token_name}/sections/"
    auth_token = data.token
    if data.phpipam_user and data.phpipam_pass:
        try:
            fresh = await auto_discovery._get_phpipam_token(base, data.token_name, data.phpipam_user, data.phpipam_pass)
            if fresh:
                auth_token = fresh
        except Exception as e:
            logger.warning(f"[phpIPAM Test] Falha ao renovar token: {e}")
    headers = {"token": auth_token, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(verify=True) as client_http:
            res = await client_http.get(url, headers=headers, timeout=8)
        if res.status_code == 200:
            return {"ok": True, "message": "Conexão com phpIPAM estabelecida com sucesso.", "ssl_error": False, "auth_error": False}
        if res.status_code in (401, 403):
            return {"ok": False, "message": f"Token inválido ou App ID incorreto (HTTP {res.status_code}). Verifique as credenciais do phpIPAM.", "ssl_error": False, "auth_error": True}
        if res.status_code == 404:
            return {"ok": False, "message": f"Endpoint não encontrado (HTTP 404). Verifique a URL e o App ID cadastrado no phpIPAM.", "ssl_error": False, "auth_error": False}
        return {"ok": False, "message": f"phpIPAM respondeu com HTTP {res.status_code}. Verifique a URL, App ID e token.", "ssl_error": False, "auth_error": False}
    except httpx.ConnectError as e:
        is_ssl = "ssl" in str(e).lower() or "certificate" in str(e).lower()
        logger.warning(f"[phpIPAM Test] Connect error (ssl={is_ssl}): {e}")
        if is_ssl:
            return {"ok": False, "message": "Erro de SSL: o certificado do servidor phpIPAM não é válido. A maioria das instâncias phpIPAM exige HTTPS com certificado confiável.", "ssl_error": True, "auth_error": False}
        return {"ok": False, "message": "Não foi possível conectar ao phpIPAM. Verifique se a URL está correta e se o servidor está acessível.", "ssl_error": False, "auth_error": False}
    except httpx.TimeoutException:
        return {"ok": False, "message": "Timeout: o phpIPAM demorou demais para responder (>8s). Verifique a URL e a disponibilidade.", "ssl_error": False, "auth_error": False}
    except Exception as e:
        logger.warning(f"[phpIPAM Test] Erro inesperado: {e}")
        return {"ok": False, "message": f"Erro inesperado ao testar conexão: {e}", "ssl_error": False, "auth_error": False}


# ==========================================
# ROTAS: INTEGRAÇÃO ZABBIX (monitoramento do provedor — modo A, somente leitura)
# ==========================================
async def _resolve_zabbix_creds(db: AsyncSession, client_id: int):
    """Carrega URL + token (decriptado) + verify_tls de um cliente. 404 se não
    houver Zabbix configurado. Centraliza a checagem usada pelas rotas /monitoring."""
    client = await db.get(models.Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail=api_error(
            "client_not_found", "Cliente não encontrado.", "Verifique o ID do cliente."))
    if not client.zabbix_url or not client.zabbix_token:
        raise HTTPException(status_code=404, detail=api_error(
            "zabbix_not_configured", "Zabbix não configurado para este cliente.",
            "Cadastre a URL e o token do Zabbix na configuração do cliente."))
    token = decrypt_secret(client.zabbix_token) or ""
    verify = client.zabbix_verify_tls if client.zabbix_verify_tls is not None else True
    return client.zabbix_url, token, verify


def _zabbix_error_response(e: Exception) -> dict:
    """Traduz exceção de rede/Zabbix para o payload {ok, message, ...} das telas."""
    if isinstance(e, zabbix_client.ZabbixError):
        return {"ok": False, "message": f"Zabbix recusou a requisição: {e}",
                "ssl_error": False, "auth_error": bool(getattr(e, "auth", False))}
    if isinstance(e, httpx.ConnectError):
        is_ssl = "ssl" in str(e).lower() or "certificate" in str(e).lower()
        return {"ok": False, "message": (
            "Erro de SSL: certificado do Zabbix inválido. Se for interno com certificado "
            "self-signed, desmarque a verificação de TLS." if is_ssl else
            "Não foi possível conectar ao Zabbix. Verifique a URL e o acesso de rede."),
            "ssl_error": is_ssl, "auth_error": False}
    if isinstance(e, httpx.TimeoutException):
        return {"ok": False, "message": "Timeout: o Zabbix demorou demais para responder.",
                "ssl_error": False, "auth_error": False}
    logger.warning(f"[Zabbix] Erro inesperado: {e}")
    return {"ok": False, "message": f"Erro inesperado ao consultar o Zabbix: {e}",
            "ssl_error": False, "auth_error": False}


@app.post("/api/zabbix/test")
async def test_zabbix_connection(data: ZabbixTestSchema, db: AsyncSession = Depends(database.get_db)):
    """Testa conectividade + autenticação com o Zabbix antes de salvar.
    Se o token vier mascarado e houver client_id, usa o token salvo do cliente."""
    token = data.token
    if (not token or token == SECRET_MASK) and data.client_id:
        existing = await db.get(models.Client, data.client_id)
        if existing and existing.zabbix_token:
            token = decrypt_secret(existing.zabbix_token) or ""
    try:
        _validate_external_url_or_400(_normalize_url(data.url))
    except HTTPException:
        raise
    try:
        async with zabbix_client.ZabbixClient(data.url, token or "", verify_tls=bool(data.verify_tls)) as z:
            version = await z.get_version()
            # host.get exige token válido — confirma a autenticação, não só a rede.
            hosts = await z.get_hosts()
        return {"ok": True, "message": f"Conectado ao Zabbix {version}.",
                "version": version, "host_count": len(hosts),
                "ssl_error": False, "auth_error": False}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=api_error(
            "url_blocked", "URL bloqueada por política de segurança.", str(e)))
    except Exception as e:
        return _zabbix_error_response(e)


@app.get("/api/clients/{client_id}/monitoring/summary")
async def zabbix_monitoring_summary(client_id: int, db: AsyncSession = Depends(database.get_db)):
    """Saúde do cliente: hosts up/down/unknown + problemas ativos por severidade.
    Alimenta o badge de saúde no dashboard e no portal do provedor."""
    url, token, verify = await _resolve_zabbix_creds(db, client_id)
    try:
        async with zabbix_client.ZabbixClient(url, token, verify_tls=verify) as z:
            hosts = await z.get_hosts()
            problems = await z.get_active_problems()
        return {"ok": True,
                "hosts": zabbix_client.summarize_hosts(hosts),
                "problems": zabbix_client.summarize_problems(problems)}
    except Exception as e:
        return _zabbix_error_response(e)


@app.get("/api/clients/{client_id}/monitoring/problems")
async def zabbix_monitoring_problems(client_id: int, db: AsyncSession = Depends(database.get_db)):
    """Lista de problemas ativos (trigger.get) com host e severidade."""
    url, token, verify = await _resolve_zabbix_creds(db, client_id)
    try:
        async with zabbix_client.ZabbixClient(url, token, verify_tls=verify) as z:
            problems = await z.get_active_problems()
        return {"ok": True, "problems": problems}
    except Exception as e:
        return _zabbix_error_response(e)


@app.get("/api/clients/{client_id}/monitoring/hosts")
async def zabbix_monitoring_hosts(client_id: int, db: AsyncSession = Depends(database.get_db)):
    """IPs observados no Zabbix (um por host+IP). É a fonte 'observada' do AUTO IPAM."""
    url, token, verify = await _resolve_zabbix_creds(db, client_id)
    try:
        async with zabbix_client.ZabbixClient(url, token, verify_tls=verify) as z:
            hosts = await z.get_hosts()
        return {"ok": True, "ips": zabbix_client.extract_host_ips(hosts)}
    except Exception as e:
        return _zabbix_error_response(e)


@app.post("/api/clients/{client_id}/sync-monitoring-ips")
async def sync_monitoring_ips(client_id: int, db: AsyncSession = Depends(database.get_db)):
    """AUTO IPAM: puxa IPs vivos do Zabbix e registra no phpIPAM na subnet certa.

    Reusa `_sync_phpipam_address` (idempotente). IPs fora de qualquer bloco
    declarado voltam como `orphans` (rede não documentada — não são gravados)."""
    url, token, verify = await _resolve_zabbix_creds(db, client_id)
    try:
        result = await auto_discovery.sync_zabbix_ips_to_phpipam(client_id, url, token, verify, db)
        return result
    except HTTPException:
        raise
    except Exception as e:
        return _zabbix_error_response(e)


# ==========================================
# ROTAS: INTEGRAÇÃO DIRETA COM A API DO BC
# ==========================================
@app.get("/api/backup/servers/{server_id}/groups")
async def fetch_bc_groups(server_id: int, db: AsyncSession = Depends(database.get_db)):
    server = await db.get(models.BCServer, server_id)
    if not server:
        raise HTTPException(
            status_code=404,
            detail=api_error("bc_server_not_found", "Servidor Backup API não encontrado.", "Verifique o ID do servidor em /admin/bc-servers."),
        )
    
    async with httpx.AsyncClient() as client_http:
        try:
            res = await client_http.get(bc_url(server, "groups"), headers=bc_headers(server), timeout=10)
            if res.status_code == 200:
                return res.json().get('groups', [])
        except Exception as e:
            logger.warning(f"[BC Groups] Falha ao buscar grupos do servidor {server_id}: {e}")
    return []

@app.get("/api/backup/groups/{ext_group_id}/assets")
async def fetch_bc_assets(ext_group_id: str, db: AsyncSession = Depends(database.get_db)):
    res_client = await db.execute(select(models.Client).where(models.Client.external_group_id == ext_group_id))
    client = res_client.scalars().first()
    
    if not client or not client.bc_server_id: return []
    server = await db.get(models.BCServer, client.bc_server_id)
    if not server: return []
    
    async with httpx.AsyncClient() as client_http:
        try:
            res = await client_http.get(
                bc_url(server, "groups", ext_group_id, "backups"),
                headers=bc_headers(server),
                params={"status": "success"},
                timeout=15,
            )
            if res.status_code == 200:
                return res.json().get('items', [])
        except Exception as e:
            logger.warning(f"[BC Assets] Falha ao buscar ativos do grupo {ext_group_id}: {e}")
    return []

@app.post("/api/backup/discover-all-groups")
async def discover_all_global_groups(db: AsyncSession = Depends(database.get_db)):
    result = await _sync_bc_groups_and_assets(db, extract_configs=False)
    if result.get("status") == "error":
        return JSONResponse(status_code=502, content=result)
    return result


@app.post("/api/backup/extract-all")
async def extract_all_backup(background_tasks: BackgroundTasks):
    for job in GLOBAL_JOBS.values():
        if job.get("type") == "backup_extract_all" and job.get("status") in ("queued", "running"):
            return {
                "job_id": job["id"],
                "status": job["status"],
                "message": "Já existe uma extração global em andamento.",
            }

    job_id = str(uuid.uuid4())
    GLOBAL_JOBS[job_id] = {
        "id": job_id,
        "type": "backup_extract_all",
        "status": "queued",
        "phase": "queued",
        "message": "Extração global adicionada à fila.",
        "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "result": None,
    }
    background_tasks.add_task(_run_global_extract_job, job_id)
    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Extração global iniciada. Acompanhe o progresso pelo job.",
    }


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str):
    job = GLOBAL_JOBS.get(job_id)
    if not job:
        raise HTTPException(
            status_code=404,
            detail=api_error("job_not_found", "Job não encontrado.", "Atualize a tela e tente iniciar a operação novamente."),
        )
    return job


# ==========================================
# ROTAS DE ORQUESTRAÇÃO & EXTRAÇÃO
# ==========================================
@app.post("/api/discovery/clients")
async def discovery_clients(db: AsyncSession = Depends(database.get_db)):
    return await auto_discovery.discover_all_clients(db)

@app.post("/api/clients/{client_id}/discover-assets")
async def discover_assets(client_id: int, db: AsyncSession = Depends(database.get_db)):
    try:
        result = await auto_discovery.sync_discovered_assets(client_id, db)
        # Extração automática logo após a descoberta
        await auto_discovery.extract_client_configs_bc(client_id, db)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[discover_assets] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("bc_unreachable", f"Falha na descoberta de ativos: {e}", "Verifique URL, token e vínculos Backup API do cliente."),
        )

@app.post("/api/clients/{client_id}/extract-configs")
async def extract_configs(client_id: int, background_tasks: BackgroundTasks):
    background_tasks.add_task(_run_extract_bg, client_id)
    return {"message": "Extração iniciada em segundo plano. Acompanhe nos logs."}

@app.post("/api/clients/{client_id}/sync-phpipam")
async def sync_phpipam(client_id: int, db: AsyncSession = Depends(database.get_db)):
    try:
        return await auto_discovery.sync_data_to_phpipam(client_id, db)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[sync_phpipam] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("ipam_sync_failed", f"Falha na sincronização com phpIPAM: {e}", "Verifique URL, App ID, token e permissões de escrita no phpIPAM."),
        )

@app.post("/api/clients/{client_id}/resolve-vlan-conflicts")
async def resolve_vlan_conflicts(client_id: int, data: VlanConflictResolutionRequest, db: AsyncSession = Depends(database.get_db)):
    try:
        return await auto_discovery.resolve_vlan_conflicts(client_id, [r.model_dump() for r in data.resolutions], db)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[resolve_conflicts] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("ipam_conflict_resolution_failed", f"Falha na resolução de conflitos: {e}", "Revise as resoluções enviadas e tente novamente."),
        )

@app.post("/api/clients/{client_id}/create-l2-domain")
async def create_l2_domain(client_id: int, data: CreateL2DomainRequest, db: AsyncSession = Depends(database.get_db)):
    try:
        result = await auto_discovery.create_l2_domain_phpipam(client_id, data.name, db)
        if "error" in result:
            raise HTTPException(
                status_code=400,
                detail=api_error("ipam_l2_domain_create_failed", result["error"], "Verifique permissões do App ID no phpIPAM."),
            )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[create_l2_domain] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("ipam_l2_domain_create_failed", f"Falha ao criar L2 Domain: {e}", "Verifique a conectividade e permissões do phpIPAM."),
        )

@app.post("/api/clients/{client_id}/extract-configs-bc")
async def extract_configs_bc(client_id: int, background_tasks: BackgroundTasks):
    background_tasks.add_task(_run_extract_bg, client_id)
    return {"message": "Extração BC iniciada em segundo plano. Acompanhe nos logs."}

@app.post("/api/clients/{client_id}/extract-configs-manual")
async def extract_configs_manual(client_id: int, db: AsyncSession = Depends(database.get_db)):
    try:
        if hasattr(auto_discovery, 'extract_client_configs_manual'):
            return await auto_discovery.extract_client_configs_manual(client_id, db)
        return {"message": "Extração SSH Manual em desenvolvimento."}
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[extract_configs_manual] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("ssh_extract_failed", f"Falha na extração SSH manual: {e}", "Verifique IP, porta, credenciais SSH e jump host do ativo."),
        )

@app.post("/api/clients/{client_id}/ssh-test")
async def test_client_asset_ssh(client_id: int, data: SSHTestRequest, db: AsyncSession = Depends(database.get_db)):
    client = await db.get(models.Client, client_id)
    asset = await db.get(models.Asset, data.asset_id)
    if not client or not asset or asset.client_id != client_id:
        raise HTTPException(
            status_code=404,
            detail=api_error("asset_not_found", "Ativo não encontrado para este grupo.", "Atualize a lista de ativos e tente novamente."),
        )
    if not asset.ip_address or not asset.ssh_user or not asset.ssh_pass:
        return {
            "ok": False,
            "latency_ms": 0,
            "error_code": "missing_ssh_credentials",
            "message": "IP, usuário e senha SSH do ativo são obrigatórios.",
            "hint": "Preencha IP, usuário e senha SSH no card do ativo.",
        }

    proxy_ip = asset.override_vpn_host or client.vpn_host
    proxy_port = asset.override_vpn_port or client.vpn_port or 22
    proxy_user = asset.override_vpn_user or client.vpn_user
    proxy_pass = decrypt_secret(asset.override_vpn_pass) or decrypt_secret(client.vpn_pass)
    started = time.monotonic()
    try:
        await run_ssh_test(
            target_ip=asset.ip_address,
            target_port=asset.port or 22,
            target_user=asset.ssh_user,
            target_pass=decrypt_secret(asset.ssh_pass) or "",
            proxy_ip=proxy_ip,
            proxy_port=proxy_port,
            proxy_user=proxy_user,
            proxy_pass=proxy_pass,
        )
        return {"ok": True, "latency_ms": int((time.monotonic() - started) * 1000)}
    except (SSHAuthError, SSHTimeoutError) as e:
        return {
            "ok": False,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "error_code": e.error_code,
            "message": str(e),
            "hint": e.hint,
        }
    except BCConnectionError as e:
        return {
            "ok": False,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "error_code": "ssh_connection_failed",
            "message": str(e),
            "hint": "Verifique IP, porta, rota/VPN e permissões SSH.",
        }

@app.post("/api/clients/{client_id}/extract-all")
async def extract_all(client_id: int, background_tasks: BackgroundTasks):
    background_tasks.add_task(_run_extract_bg, client_id)
    return {"message": "Extração completa iniciada em segundo plano. Acompanhe nos logs."}


# ==========================================
# ROTAS DE CONSULTA AO PHPIPAM
# ==========================================

class PhpIPAMProbeRequest(BaseModel):
    ip: str
    token_name: str
    token: str
    phpipam_user: Optional[str] = None
    phpipam_pass: Optional[str] = None

@app.post("/api/phpipam/probe")
async def probe_phpipam(data: PhpIPAMProbeRequest):
    """Consulta phpIPAM com credenciais do formulário sem persistir nada no banco."""
    base_ip = _normalize_url(data.ip)
    _validate_external_url_or_400(base_ip)

    auth_token = data.token
    if data.phpipam_user and data.phpipam_pass:
        fresh = await auto_discovery._get_phpipam_token(base_ip, data.token_name, data.phpipam_user, data.phpipam_pass)
        if fresh:
            auth_token = fresh

    headers = {"token": auth_token}
    result = {"l2_domains": [], "sections": [], "ok": False, "error": None}

    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"{base_ip}/api/{data.token_name}/l2domains/all/", headers=headers)
            if r.status_code == 200:
                result["l2_domains"] = r.json().get("data", []) or []
                result["ok"] = True
            else:
                result["error"] = f"phpIPAM retornou {r.status_code}"
        except Exception as e:
            result["error"] = str(e)
            return result
        try:
            r = await c.get(f"{base_ip}/api/{data.token_name}/sections/", headers=headers)
            if r.status_code == 200:
                result["sections"] = r.json().get("data", []) or []
        except Exception as e:
            logger.warning(f"[phpIPAM Probe] Falha ao buscar sections em {base_ip}: {e}")

    return result

@app.get("/api/clients/{client_id}/remote-l2-domains")
async def get_remote_l2_domains(client_id: int, db: AsyncSession = Depends(database.get_db)):
    client = await db.get(models.Client, client_id)
    if not client or not client.ip or not client.token: return []

    base_ip = client.ip.rstrip('/') if client.ip.startswith("http") else f"http://{client.ip.rstrip('/')}"

    auth_token = decrypt_secret(client.token)
    if client.phpipam_user and client.phpipam_pass:
        fresh = await auto_discovery._get_phpipam_token(base_ip, client.token_name, client.phpipam_user, decrypt_secret(client.phpipam_pass))
        if fresh:
            auth_token = fresh

    url = f"{base_ip}/api/{client.token_name}/l2domains/all/"
    async with httpx.AsyncClient() as client_http:
        try:
            res = await client_http.get(url, headers={"token": auth_token}, timeout=10)
            if res.status_code == 200: return res.json().get("data", [])
        except Exception as e:
            logger.warning(f"[L2 Domains] Falha para cliente {client_id}: {e}")
    return []

@app.get("/api/clients/{client_id}/remote-sections")
async def get_remote_sections(client_id: int, db: AsyncSession = Depends(database.get_db)):
    client = await db.get(models.Client, client_id)
    if not client or not client.ip or not client.token: return []

    base_ip = client.ip.rstrip('/') if client.ip.startswith("http") else f"http://{client.ip.rstrip('/')}"

    auth_token = decrypt_secret(client.token)
    if client.phpipam_user and client.phpipam_pass:
        fresh = await auto_discovery._get_phpipam_token(base_ip, client.token_name, client.phpipam_user, decrypt_secret(client.phpipam_pass))
        if fresh:
            auth_token = fresh

    url = f"{base_ip}/api/{client.token_name}/sections/"
    async with httpx.AsyncClient() as client_http:
        try:
            res = await client_http.get(url, headers={"token": auth_token}, timeout=10)
            if res.status_code == 200: return res.json().get("data", [])
        except Exception as e:
            logger.warning(f"[Sections] Falha para cliente {client_id}: {e}")
    return []


# ==========================================
# ROTAS: INTEGRAÇÃO NETBOX
# ==========================================

class NetBoxProbeRequest(BaseModel):
    ip: str
    token: str

@app.post("/api/netbox/probe")
async def probe_netbox(data: NetBoxProbeRequest):
    """Testa conexão com NetBox e retorna VLAN Groups e Sites disponíveis."""
    base_url = _normalize_url(data.ip)
    _validate_external_url_or_400(base_url)
    _scheme = "Bearer" if data.token.startswith("nbt_") else "Token"
    headers = {"Authorization": f"{_scheme} {data.token}", "Accept": "application/json"}
    result = {"vlan_groups": [], "sites": [], "ok": False, "error": None}
    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"{base_url}/api/ipam/vlan-groups/?limit=500", headers=headers)
            if r.status_code == 200:
                result["vlan_groups"] = r.json().get("results", [])
                result["ok"] = True
            else:
                result["error"] = f"NetBox retornou {r.status_code}"
        except Exception as e:
            result["error"] = str(e)
            return result
        try:
            r = await c.get(f"{base_url}/api/dcim/sites/?limit=500", headers=headers)
            if r.status_code == 200:
                result["sites"] = r.json().get("results", [])
        except Exception as e:
            logger.warning(f"[NetBox Probe] Falha ao buscar sites em {base_url}: {e}")
    return result

@app.post("/api/clients/{client_id}/sync-netbox")
async def sync_netbox(client_id: int, db: AsyncSession = Depends(database.get_db)):
    try:
        return await auto_discovery.sync_data_to_netbox(client_id, db)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[sync_netbox] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("netbox_sync_failed", f"Falha na sincronização com NetBox: {e}", "Verifique URL, token e permissões da API NetBox."),
        )

@app.post("/api/clients/{client_id}/resolve-netbox-conflicts")
async def resolve_netbox_conflicts(client_id: int, data: VlanConflictResolutionRequest, db: AsyncSession = Depends(database.get_db)):
    try:
        result = await auto_discovery.resolve_netbox_conflicts(client_id, [r.model_dump() for r in data.resolutions], db)
        if "error" in result:
            raise HTTPException(
                status_code=400,
                detail=api_error("netbox_conflict_resolution_failed", result["error"], "Revise URL, token e permissões da API NetBox."),
            )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[resolve_netbox_conflicts] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("netbox_conflict_resolution_failed", f"Falha na resolução de conflitos NetBox: {e}", "Revise as resoluções enviadas e tente novamente."),
        )

@app.get("/api/clients/{client_id}/remote-vlan-groups")
async def get_remote_vlan_groups(client_id: int, db: AsyncSession = Depends(database.get_db)):
    client = await db.get(models.Client, client_id)
    if not client or not client.netbox_url or not client.netbox_token:
        return []
    base_url = client.netbox_url.rstrip('/')
    if not base_url.startswith("http"):
        base_url = f"http://{base_url}"
    _validate_external_url_or_400(base_url)
    _tk = decrypt_secret(client.netbox_token) or ""
    _sc = "Bearer" if _tk.startswith("nbt_") else "Token"
    headers = {"Authorization": f"{_sc} {_tk}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=10) as raw_client:
        c = RetryingAsyncClient(raw_client)
        try:
            res = await c.get(f"{base_url}/api/ipam/vlan-groups/?limit=500", headers=headers)
            if res.status_code == 200:
                return res.json().get("results", [])
        except Exception as e:
            logger.warning(f"[VLAN Groups] Falha para cliente {client_id}: {e}")
    return []

@app.get("/api/clients/{client_id}/remote-sites")
async def get_remote_sites(client_id: int, db: AsyncSession = Depends(database.get_db)):
    client = await db.get(models.Client, client_id)
    if not client or not client.netbox_url or not client.netbox_token:
        return []
    base_url = client.netbox_url.rstrip('/')
    if not base_url.startswith("http"):
        base_url = f"http://{base_url}"
    _validate_external_url_or_400(base_url)
    _tk = decrypt_secret(client.netbox_token) or ""
    _sc = "Bearer" if _tk.startswith("nbt_") else "Token"
    headers = {"Authorization": f"{_sc} {_tk}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=10) as raw_client:
        c = RetryingAsyncClient(raw_client)
        try:
            res = await c.get(f"{base_url}/api/dcim/sites/?limit=500", headers=headers)
            if res.status_code == 200:
                return res.json().get("results", [])
        except Exception as e:
            logger.warning(f"[Sites] Falha para cliente {client_id}: {e}")
    return []

@app.post("/api/clients/{client_id}/create-vlan-group")
async def create_vlan_group(client_id: int, data: CreateL2DomainRequest, db: AsyncSession = Depends(database.get_db)):
    try:
        result = await auto_discovery.create_vlan_group_netbox(client_id, data.name, db)
        if "error" in result:
            raise HTTPException(
                status_code=400,
                detail=api_error("netbox_vlan_group_create_failed", result["error"], "Verifique permissões da API NetBox."),
            )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[create_vlan_group] Erro para cliente {client_id}: {e}")
        raise HTTPException(
            status_code=502,
            detail=api_error("netbox_vlan_group_create_failed", f"Falha ao criar VLAN Group: {e}", "Verifique conectividade e permissões da API NetBox."),
        )


# ==========================================
# ROTAS CRUD GERAIS
# ==========================================
def _client_count_subqueries():
    """Contagens por cliente como subqueries escalares.

    Antes as listagens usavam selectinload de assets/vlans/subnets só para fazer
    len() em Python — com ~92k VLANs no banco, abrir o dashboard trazia todas as
    linhas para a memória. Agora o banco devolve só os números."""
    def _count(model, *extra):
        return (
            select(func.count(model.id))
            .where(model.client_id == models.Client.id, *extra)
            .correlate(models.Client)
            .scalar_subquery()
        )
    return (
        _count(models.Asset, models.Asset.is_approved.is_(True)),
        _count(models.Vlan),
        _count(models.Subnet),
        _count(models.ClientBCLink),
    )


def _apply_client_counts(client, asset_ct, vlan_ct, subnet_ct, link_ct):
    client.asset_count = asset_ct or 0
    client.vlan_count = vlan_ct or 0
    client.subnet_count = subnet_ct or 0
    client.bc_server_name = client.bc_server.name if client.bc_server else None
    client.has_bc_link = bool(link_ct)
    client.status = "success"
    return _mask_attrs(client, CLIENT_SECRET_FIELDS)


@app.get("/api/clients", response_model=List[ClientListResponse])
async def list_clients(db: AsyncSession = Depends(database.get_db)):
    asset_ct, vlan_ct, subnet_ct, link_ct = _client_count_subqueries()
    res = await db.execute(
        select(models.Client, asset_ct, vlan_ct, subnet_ct, link_ct)
        .options(selectinload(models.Client.bc_server))
    )
    return [_apply_client_counts(*row) for row in res.all()]

@app.get("/api/clients/{client_id}", response_model=ClientListResponse)
async def get_client(client_id: int, db: AsyncSession = Depends(database.get_db)):
    asset_ct, vlan_ct, subnet_ct, link_ct = _client_count_subqueries()
    res = await db.execute(
        select(models.Client, asset_ct, vlan_ct, subnet_ct, link_ct)
        .options(selectinload(models.Client.bc_server))
        .where(models.Client.id == client_id)
    )
    row = res.first()
    if not row:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", "Cliente não encontrado.", "Verifique o ID do cliente e tente novamente."),
        )
    return _apply_client_counts(*row)

@app.post("/api/clients", response_model=ClientListResponse)
async def create_client(client_data: ClientSchema, db: AsyncSession = Depends(database.get_db)):
    new_client = models.Client(**_encrypt_payload(_strip_masked(client_data.model_dump(), CLIENT_SECRET_FIELDS), CLIENT_SECRET_FIELDS))
    db.add(new_client)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=api_error("client_name_conflict", "Já existe um cliente com este nome.", "Escolha um nome diferente."),
        )
    await db.refresh(new_client)
    new_client.status = "success"
    return _mask_attrs(new_client, CLIENT_SECRET_FIELDS)

@app.put("/api/clients/{client_id}")
async def update_client(client_id: int, data: ClientSchema, db: AsyncSession = Depends(database.get_db)):
    client = await db.get(models.Client, client_id)
    if not client:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", f"Cliente {client_id} não encontrado.", "Atualize a lista de clientes e tente novamente."),
        )
    update_payload = _strip_masked(data.model_dump(exclude_unset=True), CLIENT_SECRET_FIELDS)
    for key, value in _encrypt_payload(update_payload, CLIENT_SECRET_FIELDS).items(): setattr(client, key, value)
    await db.commit()
    return {"message": "Cliente atualizado"}

@app.get("/api/clients/{client_id}/assets", response_model=List[AssetResponse])
async def get_assets(client_id: int, db: AsyncSession = Depends(database.get_db)):
    res = await db.execute(select(models.Asset).where(models.Asset.client_id == client_id))
    return [_mask_attrs(asset, ASSET_SECRET_FIELDS) for asset in res.scalars().all()]

@app.post("/api/assets")
async def add_asset_manual_new(asset_data: AssetSchema, db: AsyncSession = Depends(database.get_db)):
    new_asset = models.Asset(**_encrypt_payload(_strip_masked(asset_data.model_dump(), ASSET_SECRET_FIELDS), ASSET_SECRET_FIELDS))
    new_asset.is_approved = True
    db.add(new_asset)
    await db.commit()
    return {"message": "Ativo manual adicionado"}

@app.put("/api/assets/{asset_id}")
async def update_asset(asset_id: int, data: AssetUpdateSchema, db: AsyncSession = Depends(database.get_db)):
    asset = await db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=api_error("asset_not_found", f"Ativo {asset_id} não encontrado.", "Atualize a lista de ativos e tente novamente."),
        )
    
    update_dict = _encrypt_payload(_strip_masked(data.model_dump(exclude_unset=True), ASSET_SECRET_FIELDS), ASSET_SECRET_FIELDS)
    if update_dict.get("hostname") in ["KEEP", "KEEP_SAME"]: update_dict.pop("hostname")
    for key, value in update_dict.items(): setattr(asset, key, value)
    await db.commit()
    return {"message": "Ativo atualizado"}

@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: int, db: AsyncSession = Depends(database.get_db)):
    client = await db.get(models.Client, client_id)
    if not client:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", "Grupo não encontrado.", "Atualize a lista de grupos e tente novamente."),
        )
    await db.delete(client)
    await db.commit()
    return {"message": "Grupo removido com sucesso"}

@app.put("/api/backup/servers/{server_id}", response_model=BCServerResponse)
async def update_bc_server(server_id: int, data: BCServerSchema, db: AsyncSession = Depends(database.get_db)):
    server = await db.get(models.BCServer, server_id)
    if not server:
        raise HTTPException(
            status_code=404,
            detail=api_error("bc_server_not_found", "Servidor Backup API não encontrado.", "Atualize a lista de servidores e tente novamente."),
        )
    server.name = data.name
    server.url = data.url
    if data.token != SECRET_MASK:
        server.token = encrypt_secret(data.token)
    await db.commit()
    await db.refresh(server)
    return _mask_attrs(server, {"token"})

@app.delete("/api/assets/{asset_id}")
async def delete_asset(asset_id: int, db: AsyncSession = Depends(database.get_db)):
    """Remove um ativo cadastrado manualmente.

    Ativo descoberto pela Backup API (`bc_device_id` preenchido) NÃO pode ser
    excluído: o próximo discover o recriaria, então a remoção seria só aparente,
    com a perda real das VLANs/subnets/interfaces dele no intervalo. Para tirar
    esses da operação, desative a aprovação (`is_approved`) ou remova o vínculo
    com o grupo na Backup API.
    """
    asset = await db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=api_error("asset_not_found", f"Ativo {asset_id} não encontrado.", "Atualize a lista de ativos e tente novamente."),
        )
    if asset.bc_device_id:
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "asset_from_backup",
                "Este ativo veio da Backup API e não pode ser excluído.",
                "O próximo discover o recriaria. Para tirá-lo da operação, desmarque a aprovação ou ajuste o grupo na Backup API.",
            ),
        )

    # A exclusão é em cascata (vlans, subnets, interfaces): informa o volume
    # removido para o operador conferir que apagou o que esperava.
    vlans = (await db.execute(select(func.count(models.Vlan.id)).where(models.Vlan.asset_id == asset_id))).scalar() or 0
    subnets = (await db.execute(select(func.count(models.Subnet.id)).where(models.Subnet.asset_id == asset_id))).scalar() or 0
    hostname = asset.hostname

    await db.delete(asset)
    await db.commit()
    logger.info("Ativo manual removido: %s (id=%s) — %s VLANs e %s subnets em cascata",
                hostname, asset_id, vlans, subnets)
    return {"message": "Ativo removido", "hostname": hostname,
            "vlans_removidas": vlans, "subnets_removidas": subnets}

@app.get("/api/clients/{client_id}/vlans", response_model=List[VlanResponse])
async def list_client_vlans(client_id: int, db: AsyncSession = Depends(database.get_db)):
    result = await db.execute(select(models.Vlan).where(models.Vlan.client_id == client_id))
    return result.scalars().all()

@app.get("/api/clients/{client_id}/subnets", response_model=List[SubnetResponse])
async def list_client_subnets(client_id: int, db: AsyncSession = Depends(database.get_db)):
    result = await db.execute(select(models.Subnet).where(models.Subnet.client_id == client_id))
    return result.scalars().all()


# ── Busca global de VLAN (rastreio entre provedores) ─────────────────────────

class VlanSearchOccurrence(BaseModel):
    """Uma aparição da VLAN num ativo específico."""
    vlan_id: int
    vid: int
    name: Optional[str] = None
    description: Optional[str] = None
    vlan_type: Optional[str] = None
    asset_id: Optional[int] = None
    asset_hostname: Optional[str] = None
    asset_vendor: Optional[str] = None
    asset_category: Optional[str] = None
    is_edge_router: Optional[bool] = False


class VlanSearchClientGroup(BaseModel):
    """Ocorrências da VLAN dentro de um provedor."""
    client_id: int
    client_name: str
    occurrence_count: int
    vids: List[int] = []
    occurrences: List[VlanSearchOccurrence] = []


class VlanSearchResponse(BaseModel):
    query: str
    total: int
    client_count: int
    truncated: bool = False
    results: List[VlanSearchClientGroup] = []


VLAN_SEARCH_MAX = 800


@app.get("/api/vlans/search", response_model=VlanSearchResponse)
async def search_vlans_global(
    q: str,
    clients: Optional[str] = None,
    db: AsyncSession = Depends(database.get_db),
):
    """Rastreia uma VLAN por TODOS os provedores.

    Responde a pergunta operacional 'onde essa VLAN passa': uma VLAN 100 que
    nasce num provedor, transita por outro e termina num terceiro aparece aqui
    agrupada por provedor, com os ativos onde foi extraída.

    `q` numérico casa o VID exato (e também texto, para nomes tipo "VLAN 100");
    `q` textual casa nome/descrição. Resultado ordenado por provedor."""
    term = (q or "").strip()
    if len(term) < 1:
        raise HTTPException(status_code=400, detail=api_error(
            "vlan_search_empty", "Informe um VID ou texto para buscar.",
            "Ex.: 100, ou parte do nome da VLAN."))

    if term.isdigit():
        # Termo numérico é SEMPRE o VID exato. Casar texto aqui traria toda VLAN
        # cujo nome contenha o número (buscar 500 devolvia 1500/2500/3500, porque
        # "VLAN_1500" contém "500") — inútil para operação.
        filters = [models.Vlan.vid == int(term)]
    else:
        like = f"%{term}%"
        filters = [models.Vlan.name.ilike(like), models.Vlan.description.ilike(like)]

    stmt = (
        select(models.Vlan, models.Asset, models.Client)
        .join(models.Client, models.Vlan.client_id == models.Client.id)
        .outerjoin(models.Asset, models.Vlan.asset_id == models.Asset.id)
        .where(or_(*filters))
    )

    # Rastreio de transporte: restringe aos provedores por onde o circuito passa
    # (ex.: clients=3,7,12 para ver a mesma VLAN só na PIX, Flash e i4).
    if clients:
        try:
            ids = [int(x) for x in clients.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail=api_error(
                "vlan_search_clients_invalid", "Lista de provedores inválida.",
                "Use IDs numéricos separados por vírgula, ex.: 3,7,12."))
        if ids:
            stmt = stmt.where(models.Client.id.in_(ids))

    res = await db.execute(
        stmt.order_by(models.Client.name, models.Vlan.vid).limit(VLAN_SEARCH_MAX + 1)
    )
    rows = res.all()
    truncated = len(rows) > VLAN_SEARCH_MAX
    rows = rows[:VLAN_SEARCH_MAX]

    grouped: dict[int, VlanSearchClientGroup] = {}
    for vlan, asset, client in rows:
        grp = grouped.get(client.id)
        if grp is None:
            grp = VlanSearchClientGroup(client_id=client.id, client_name=client.name or "",
                                        occurrence_count=0)
            grouped[client.id] = grp
        grp.occurrence_count += 1
        if vlan.vid not in grp.vids:
            grp.vids.append(vlan.vid)
        grp.occurrences.append(VlanSearchOccurrence(
            vlan_id=vlan.id, vid=vlan.vid, name=vlan.name, description=vlan.description,
            vlan_type=vlan.vlan_type,
            asset_id=asset.id if asset else None,
            asset_hostname=asset.hostname if asset else None,
            asset_vendor=asset.vendor if asset else None,
            asset_category=asset.category if asset else None,
            is_edge_router=bool(asset.is_edge_router) if asset else False,
        ))

    results = sorted(grouped.values(), key=lambda g: g.client_name.lower())
    return VlanSearchResponse(
        query=term, total=len(rows), client_count=len(results),
        truncated=truncated, results=results,
    )


# ==========================================
# ROTAS: TOPOLOGIA DE REDE
# Endpoints novos para visualização de interfaces físicas, VLANs enriquecidas,
# subnets enriquecidas e mapa topológico do grupo.
# Não alteram nenhum comportamento existente.
# ==========================================

# ── Schemas de resposta para topologia ────────────────────────────────────────

class VlanInterfaceInfo(BaseModel):
    """VLAN associada a uma interface — modo de operação incluído."""
    vid: int
    mode: str  # access | trunk | tagged | native | routed
    model_config = {"from_attributes": True}


class InterfaceResponse(BaseModel):
    """Detalhes de uma interface física ou lógica de um ativo."""
    id: int
    asset_id: int
    name: str
    type: str
    description: Optional[str] = None
    is_management: bool = False
    vlans: List[VlanInterfaceInfo] = []
    ip_address: Optional[str] = None  # IP da subnet configurada nesta interface (se houver)
    mask: Optional[int] = None
    model_config = {"from_attributes": True}


class VlanEnrichedResponse(BaseModel):
    """VLAN com lista de interfaces por onde trafega."""
    id: int
    vid: int
    name: str
    description: Optional[str] = ""
    vlan_type: Optional[str] = None
    asset_id: Optional[int] = None
    asset_hostname: Optional[str] = None
    interfaces: List[dict] = []  # [{name, type, mode}]
    subnets: List[dict] = []     # [{network, mask, description}]
    model_config = {"from_attributes": True}


class SubnetEnrichedResponse(BaseModel):
    """Subnet com interface e VLAN relacionadas."""
    id: int
    network: str
    mask: int
    host_ip: Optional[str] = None  # IP real configurado na interface (ocupação)
    description: Optional[str] = ""
    asset_id: Optional[int] = None
    asset_hostname: Optional[str] = None
    vlan_vid: Optional[int] = None
    vlan_name: Optional[str] = None
    interface_name: Optional[str] = None
    interface_type: Optional[str] = None
    model_config = {"from_attributes": True}


class TopologyNode(BaseModel):
    """Nó do grafo de topologia — representa um ativo de rede."""
    id: str           # "asset-{asset_id}"
    asset_id: int
    hostname: str
    vendor: Optional[str] = None
    category: Optional[str] = None
    ip_address: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    is_edge_router: bool = False
    authority_level: int = 1
    interfaces: List[dict] = []   # [{name, type, description, is_management, vlans:[{vid,mode}], ip_address, mask}]
    vlans: List[dict] = []        # [{vid, name, description}]
    subnets: List[dict] = []      # [{network, mask, description}]


class TopologyEdge(BaseModel):
    """Aresta do grafo — dois ativos compartilham VLANs."""
    source: str        # "asset-{id}"
    target: str        # "asset-{id}"
    shared_vlans: List[int] = []
    label: str = ""


class TopologyVlanSummary(BaseModel):
    """Resumo de uma VLAN no contexto do grupo."""
    vid: int
    name: str
    description: Optional[str] = ""
    vlan_type: Optional[str] = None
    asset_ids: List[int] = []
    asset_hostnames: List[str] = []
    interface_count: int = 0


class TopologyResponse(BaseModel):
    """Grafo topológico completo de um grupo."""
    client_id: int
    client_name: str
    nodes: List[TopologyNode] = []
    edges: List[TopologyEdge] = []
    vlan_summary: List[TopologyVlanSummary] = []
    subnet_summary: List[dict] = []  # [{network, mask, description, asset_hostname}]
    stats: dict = {}


class VlanTraceEndpoint(BaseModel):
    """Uma interface de um equipamento por onde a VLAN trafega (uma ponta)."""
    asset_id: int
    hostname: str
    vendor: Optional[str] = None
    category: Optional[str] = None
    interface: str
    interface_type: str = "physical"
    mode: str = "trunk"               # access | trunk | tagged | native | routed
    description: Optional[str] = None
    is_management: bool = False
    host_ip: Optional[str] = None     # IP real configurado na interface
    network: Optional[str] = None     # endereço de rede da subnet
    mask: Optional[int] = None
    vlan_type: Optional[str] = None   # None=L2 regular | routed | vsi | l2vc (deste ativo)
    vlan_config: Optional[str] = None # bloco de config bruto da VLAN neste ativo (se capturado)


class VlanTraceLink(BaseModel):
    """Enlace INFERIDO entre duas pontas (nunca determinístico — sem LLDP/CDP)."""
    a_asset_id: int
    a_hostname: str
    a_interface: str
    b_asset_id: int
    b_hostname: str
    b_interface: Optional[str] = None
    confidence: str                   # alta | media
    reason: str                       # p2p_subnet | descricao
    detail: str = ""


class VlanTraceResponse(BaseModel):
    """Caminho de uma VLAN: todas as pontas (com config) + enlaces inferidos."""
    client_id: int
    vid: int
    name: Optional[str] = None
    description: Optional[str] = None
    endpoints: List[VlanTraceEndpoint] = []
    links: List[VlanTraceLink] = []
    stats: dict = {}


# ── Endpoint: VLANs enriquecidas ─────────────────────────────────────────────

@app.get(
    "/api/clients/{client_id}/vlans-enriched",
    response_model=List[VlanEnrichedResponse],
    summary="VLANs com interfaces e subnets associadas",
    tags=["Topologia"],
)
async def list_client_vlans_enriched(
    client_id: int,
    limit: Optional[int] = Query(
        None, ge=1, le=50000,
        description="Máximo de VLANs a devolver. Sem valor = todas (padrão).",
    ),
    offset: int = Query(0, ge=0, description="Quantas VLANs pular (paginação)."),
    db: AsyncSession = Depends(database.get_db),
):
    """
    Retorna todas as VLANs do grupo com:
    - Hostname do ativo de origem.
    - Lista de interfaces físicas por onde a VLAN trafega (modo access/trunk/tagged).
    - Subnets configuradas em interfaces que carregam esta VLAN.

    `limit`/`offset` são opcionais e o padrão continua sendo devolver tudo: a tela
    de VLANs consome o conjunto inteiro para dizer quais VLANs têm subnet, então um
    teto silencioso faria toda VLAN cortada aparecer como "sem subnet" — a mesma
    mentira que o aviso de falha do `/vlans-enriched` existe para evitar. Quem
    quiser paginar, pagina de propósito.
    """
    client = await db.get(models.Client, client_id)
    if not client:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", "Cliente não encontrado.", "Verifique o ID do cliente."),
        )

    # BUG FIX: selectinload não é aplicado em select multi-entidade (select(Vlan, Asset))
    # no SQLAlchemy async. Usando query single-entity com eager load explícito.
    #
    # O encadeamento até VlanInterface.interface é o que mata o N+1: antes cada
    # associação VLAN↔interface custava um db.get(AssetInterface). No maior cliente
    # da base (19.496 VLANs) isso eram dezenas de milhares de idas ao
    # banco numa requisição só.
    stmt = (
        select(models.Vlan)
        .options(
            selectinload(models.Vlan.vlan_interfaces).selectinload(models.VlanInterface.interface),
            selectinload(models.Vlan.asset),     # eager load do ativo via relacionamento
        )
        .where(models.Vlan.client_id == client_id)
        # VLAN órfã é descartada logo abaixo de qualquer jeito; o filtro precisa vir
        # ANTES do LIMIT, senão limit=10 devolve 7 linhas e quem chama não distingue
        # página curta de fim de lista.
        .where(models.Vlan.asset_id.isnot(None))
        .order_by(models.Vlan.id)              # ordem estável: sem ela, paginar é loteria
    )
    if offset:
        stmt = stmt.offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)

    res = await db.execute(stmt)
    vlans = res.scalars().all()

    # Subnets de todas as VLANs do cliente numa consulta só, agrupadas pelo mesmo
    # par (vlan_id, asset_id) que a consulta por VLAN filtrava. O join é por
    # Vlan.client_id em vez de um IN com os ids da página: o custo não cresce com o
    # número de VLANs, e o volume é pequeno (480 subnets no maior cliente da base).
    res_subs = await db.execute(
        select(models.Subnet)
        .join(models.Vlan, models.Subnet.vlan_id == models.Vlan.id)
        .where(models.Vlan.client_id == client_id)
        .order_by(models.Subnet.id)
    )
    subnets_by_key: dict = {}
    for s in res_subs.scalars().all():
        subnets_by_key.setdefault((s.vlan_id, s.asset_id), []).append(s)

    result = []
    for vlan in vlans:
        asset = vlan.asset  # safe: carregado via selectinload acima
        if not asset:
            continue  # asset_id preenchido mas apontando para ativo removido

        # Interfaces associadas (vlan_interfaces e .interface já eager-loaded)
        interfaces_info = []
        for vi in vlan.vlan_interfaces:
            iface = vi.interface
            if iface:
                interfaces_info.append({
                    "id": iface.id,
                    "name": iface.name,
                    "type": iface.type,
                    "description": iface.description,
                    "mode": vi.mode,
                    "is_management": iface.is_management,
                })

        # Subnets associadas via VLANs (do lote acima, sem ida extra ao banco)
        subnets_info = [
            {"network": s.network, "mask": s.mask, "description": s.description}
            for s in subnets_by_key.get((vlan.id, asset.id), [])
        ]

        result.append(VlanEnrichedResponse(
            id=vlan.id,
            vid=vlan.vid,
            name=vlan.name,
            description=vlan.description,
            asset_id=asset.id,
            asset_hostname=asset.hostname,
            interfaces=interfaces_info,
            subnets=subnets_info,
        ))

    return result


# ── Endpoint: Subnets enriquecidas ───────────────────────────────────────────

@app.get(
    "/api/clients/{client_id}/subnets-enriched",
    response_model=List[SubnetEnrichedResponse],
    summary="Subnets com interface e VLAN associadas",
    tags=["Topologia"],
)
async def list_client_subnets_enriched(
    client_id: int,
    limit: Optional[int] = Query(
        None, ge=1, le=50000,
        description="Máximo de subnets a devolver. Sem valor = todas (padrão).",
    ),
    offset: int = Query(0, ge=0, description="Quantas subnets pular (paginação)."),
    db: AsyncSession = Depends(database.get_db),
):
    """
    Retorna todas as subnets do grupo com:
    - Hostname do ativo de origem.
    - Nome e tipo da interface onde o IP está configurado.
    - VID e nome da VLAN associada (se houver).

    Mesmo critério de `vlans-enriched`: `limit`/`offset` opcionais, padrão devolve tudo.
    """
    client = await db.get(models.Client, client_id)
    if not client:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", "Cliente não encontrado.", "Verifique o ID do cliente."),
        )

    # O join com Asset continua sendo INNER de propósito: subnet sem ativo não tem
    # hostname para mostrar e sempre ficou de fora. O selectinload é que substitui
    # o db.get por linha — Subnet.vlan_id é FK sem relationship, então a VLAN vem
    # num lote separado logo abaixo.
    stmt = (
        select(models.Subnet)
        .join(models.Asset, models.Subnet.asset_id == models.Asset.id)
        .options(
            selectinload(models.Subnet.asset),
            selectinload(models.Subnet.interface),
        )
        .where(models.Subnet.client_id == client_id)
        .order_by(models.Subnet.id)              # ordem estável: sem ela, paginar é loteria
    )
    if offset:
        stmt = stmt.offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)

    res = await db.execute(stmt)
    subnets = res.scalars().all()

    # Aqui o IN é seguro, ao contrário do que seria em vlans-enriched: o conjunto é
    # limitado pelo número de subnets da página (ou do cliente — 480 no maior da
    # base), não pelo de VLANs (19.496 no mesmo cliente, o que estouraria os bind
    # params do asyncpg).
    vlan_ids = {s.vlan_id for s in subnets if s.vlan_id}
    vlans_by_id: dict = {}
    if vlan_ids:
        res_vlans = await db.execute(
            select(models.Vlan).where(models.Vlan.id.in_(vlan_ids))
        )
        vlans_by_id = {v.id: v for v in res_vlans.scalars().all()}

    result = []
    for subnet in subnets:
        asset = subnet.asset  # safe: o INNER join garante que existe
        vlan_vid = None
        vlan_name = None
        vlan_obj = vlans_by_id.get(subnet.vlan_id) if subnet.vlan_id else None
        if vlan_obj:
            vlan_vid = vlan_obj.vid
            vlan_name = vlan_obj.name

        iface_obj = subnet.interface
        iface_name = iface_obj.name if iface_obj else None
        iface_type = iface_obj.type if iface_obj else None

        result.append(SubnetEnrichedResponse(
            id=subnet.id,
            network=subnet.network,
            mask=subnet.mask,
            host_ip=subnet.host_ip,
            description=subnet.description,
            asset_id=asset.id,
            asset_hostname=asset.hostname,
            vlan_vid=vlan_vid,
            vlan_name=vlan_name,
            interface_name=iface_name,
            interface_type=iface_type,
        ))

    return result


# ── Endpoint: Interfaces de um ativo ─────────────────────────────────────────

@app.get(
    "/api/assets/{asset_id}/interfaces",
    response_model=List[InterfaceResponse],
    summary="Interfaces físicas/lógicas de um ativo com VLANs e IPs",
    tags=["Topologia"],
)
async def list_asset_interfaces(asset_id: int, db: AsyncSession = Depends(database.get_db)):
    """
    Retorna todas as interfaces de um ativo com:
    - VLANs que trafegam por cada interface (mode: access/trunk/tagged/native).
    - IP e máscara da subnet configurada na interface (se houver).
    """
    asset = await db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=api_error("asset_not_found", "Ativo não encontrado.", "Verifique o ID do ativo."),
        )

    res_ifaces = await db.execute(
        select(models.AssetInterface)
        .options(selectinload(models.AssetInterface.vlan_interfaces))
        .where(models.AssetInterface.asset_id == asset_id)
        .order_by(models.AssetInterface.name)
    )
    ifaces = res_ifaces.scalars().all()

    result = []
    for iface in ifaces:
        # VLANs associadas
        vlans_info = []
        for vi in iface.vlan_interfaces:
            vlan_obj = await db.get(models.Vlan, vi.vlan_id)
            if vlan_obj:
                vlans_info.append(VlanInterfaceInfo(vid=vlan_obj.vid, mode=vi.mode))

        # IP da subnet configurada nesta interface
        iface_ip = None
        iface_mask = None
        res_sub = await db.execute(
            select(models.Subnet).where(
                models.Subnet.interface_id == iface.id
            ).limit(1)
        )
        sub = res_sub.scalars().first()
        if sub:
            # IP real configurado na interface (host_ip, ex.: 10.1.1.1); cai para
            # o endereço de rede só quando a subnet veio de rota estática (sem host).
            iface_ip = sub.host_ip or sub.network
            iface_mask = sub.mask

        result.append(InterfaceResponse(
            id=iface.id,
            asset_id=iface.asset_id,
            name=iface.name,
            type=iface.type,
            description=iface.description,
            is_management=iface.is_management,
            vlans=vlans_info,
            ip_address=iface_ip,
            mask=iface_mask,
        ))

    return result


# ── Endpoint: Mapa topológico do grupo ───────────────────────────────────────

@app.get(
    "/api/clients/{client_id}/topology",
    response_model=TopologyResponse,
    summary="Mapa topológico automático do grupo",
    tags=["Topologia"],
)
async def get_client_topology(client_id: int, db: AsyncSession = Depends(database.get_db)):
    """
    Gera automaticamente o grafo de topologia do grupo com base nos dados extraídos.

    **Nós**: Cada ativo aprovado do grupo é um nó, com suas interfaces, VLANs e subnets.

    **Arestas**: Dois ativos são conectados quando compartilham pelo menos uma VLAN
    em comum (mesmo VID no mesmo grupo). O label da aresta lista os VIDs compartilhados.

    **VLAN Summary**: Visão consolidada de cada VLAN — em quantos ativos aparece e
    por quantas interfaces trafega.

    **Subnet Summary**: Lista plana de todas as subnets do grupo com seu ativo de origem.

    Retorna estrutura JSON pronta para ser consumida por bibliotecas de grafos
    (vis.js, D3, Cytoscape, etc.).
    """
    client = await db.get(models.Client, client_id)
    if not client:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", "Cliente não encontrado.", "Verifique o ID do cliente."),
        )

    # ── Carrega ativos aprovados do grupo ────────────────────────────────────
    res_assets = await db.execute(
        select(models.Asset)
        .options(
            selectinload(models.Asset.vlans),
            selectinload(models.Asset.subnets),
            selectinload(models.Asset.interfaces).selectinload(models.AssetInterface.vlan_interfaces),
        )
        .where(
            models.Asset.client_id == client_id,
            models.Asset.is_approved == True,
        )
        .order_by(models.Asset.authority_level.desc(), models.Asset.hostname)
    )
    assets = res_assets.scalars().all()

    # ── Monta o mapa de VIDs por ativo (para calcular arestas) ──────────────
    asset_vid_map: dict[int, set[int]] = {}   # asset_id → set de VIDs
    nodes: list[TopologyNode] = []

    for asset in assets:
        vid_set = {v.vid for v in asset.vlans}
        asset_vid_map[asset.id] = vid_set

        # Interfaces com VLANs e IPs
        interfaces_data = []
        for iface in asset.interfaces:
            vlan_entries = []
            for vi in iface.vlan_interfaces:
                vlan_obj = await db.get(models.Vlan, vi.vlan_id)
                if vlan_obj:
                    vlan_entries.append({"vid": vlan_obj.vid, "mode": vi.mode})

            # Busca subnet com IP configurado nesta interface
            iface_ip = None
            iface_mask = None
            res_isub = await db.execute(
                select(models.Subnet).where(
                    models.Subnet.interface_id == iface.id
                ).limit(1)
            )
            isub = res_isub.scalars().first()
            if isub:
                # IP real da interface (host_ip); network é só o fallback para
                # subnets originadas de rota estática (sem IP de host).
                iface_ip = isub.host_ip or isub.network
                iface_mask = isub.mask

            interfaces_data.append({
                "name": iface.name,
                "type": iface.type,
                "description": iface.description,
                "is_management": iface.is_management,
                "vlans": vlan_entries,
                "ip_address": iface_ip,
                "mask": iface_mask,
            })

        nodes.append(TopologyNode(
            id=f"asset-{asset.id}",
            asset_id=asset.id,
            hostname=asset.hostname,
            vendor=asset.vendor,
            category=asset.category,
            ip_address=asset.ip_address,
            model=asset.model,
            serial_number=asset.serial_number,
            is_edge_router=asset.is_edge_router or False,
            authority_level=asset.authority_level or 1,
            interfaces=interfaces_data,
            vlans=[{"vid": v.vid, "name": v.name, "description": v.description} for v in asset.vlans],
            subnets=[{"network": s.network, "mask": s.mask, "description": s.description} for s in asset.subnets],
        ))

    # ── Calcula arestas (VLANs em comum entre pares de ativos) ──────────────
    edges: list[TopologyEdge] = []
    asset_ids = list(asset_vid_map.keys())
    for i in range(len(asset_ids)):
        for j in range(i + 1, len(asset_ids)):
            a_id = asset_ids[i]
            b_id = asset_ids[j]
            shared = sorted(asset_vid_map[a_id] & asset_vid_map[b_id])
            if shared:
                label = ", ".join(f"VLAN {v}" for v in shared[:5])
                if len(shared) > 5:
                    label += f" +{len(shared) - 5}"
                edges.append(TopologyEdge(
                    source=f"asset-{a_id}",
                    target=f"asset-{b_id}",
                    shared_vlans=shared,
                    label=label,
                ))

    # ── VLAN Summary ─────────────────────────────────────────────────────────
    # BUG FIX: evita acesso lazy a vlan.vlan_interfaces em query multi-entidade.
    # Usa query single-entity com selectinload explícito para acesso seguro em async.
    res_vlans = await db.execute(
        select(models.Vlan)
        .options(selectinload(models.Vlan.vlan_interfaces))
        .where(models.Vlan.client_id == client_id)
        .order_by(models.Vlan.vid)
    )
    all_vlans_objs = res_vlans.scalars().all()

    # Mapa asset_id → hostname para o summary (já temos os ativos carregados em `assets`)
    asset_hostname_map = {a.id: a.hostname for a in assets}

    # Agrupa por VID usando objetos Vlan com eager-loaded vlan_interfaces
    vlan_agg: dict[int, dict] = {}
    for vlan in all_vlans_objs:
        if vlan.vid not in vlan_agg:
            vlan_agg[vlan.vid] = {
                "vid": vlan.vid,
                "name": vlan.name,
                "description": vlan.description or "",
                "asset_ids": [],
                "asset_hostnames": [],
                "interface_count": 0,
            }
        if vlan.asset_id and vlan.asset_id not in vlan_agg[vlan.vid]["asset_ids"]:
            vlan_agg[vlan.vid]["asset_ids"].append(vlan.asset_id)
            hostname = asset_hostname_map.get(vlan.asset_id, f"asset-{vlan.asset_id}")
            vlan_agg[vlan.vid]["asset_hostnames"].append(hostname)
        vlan_agg[vlan.vid]["interface_count"] += len(vlan.vlan_interfaces)

    vlan_summary = [TopologyVlanSummary(**v) for v in vlan_agg.values()]

    # ── Subnet Summary ────────────────────────────────────────────────────────
    res_subs_all = await db.execute(
        select(models.Subnet, models.Asset)
        .join(models.Asset, models.Subnet.asset_id == models.Asset.id)
        .where(models.Subnet.client_id == client_id)
        .order_by(models.Subnet.network)
    )
    subnet_summary = [
        {
            "network": s.network,
            "mask": s.mask,
            "description": s.description or "",
            "asset_id": a.id,
            "asset_hostname": a.hostname,
        }
        for s, a in res_subs_all.all()
    ]

    # ── Stats ─────────────────────────────────────────────────────────────────
    stats = {
        "total_assets": len(nodes),
        "total_vlans": len(vlan_summary),
        "total_subnets": len(subnet_summary),
        "total_edges": len(edges),
        "total_interfaces": sum(len(n.interfaces) for n in nodes),
        "assets_with_interfaces": sum(1 for n in nodes if n.interfaces),
    }

    return TopologyResponse(
        client_id=client_id,
        client_name=client.name,
        nodes=nodes,
        edges=edges,
        vlan_summary=vlan_summary,
        subnet_summary=subnet_summary,
        stats=stats,
    )


# ── Endpoint: Caminho (trace) de uma VLAN ────────────────────────────────────

@app.get(
    "/api/clients/{client_id}/vlans/{vid}/trace",
    response_model=VlanTraceResponse,
    summary="Caminho de uma VLAN: pontas com config + enlaces inferidos",
    tags=["Topologia"],
)
async def get_vlan_trace(client_id: int, vid: int, db: AsyncSession = Depends(database.get_db)):
    """
    Rastreia por onde uma VLAN passa no grupo.

    **Endpoints (pontas)**: cada interface, de cada ativo aprovado, por onde a
    VLAN trafega — com o modo (access/trunk/tagged/native/routed), a descrição
    configurada e o IP real da interface (`host_ip`). É o dado de config bruto,
    100% determinístico.

    **Links (enlaces)**: por quais pares de ativos a VLAN fecha enlace. Como o
    sistema não captura LLDP/CDP (decisão de segurança), a adjacência é sempre
    **inferida** e vem rotulada com confiança e motivo:
    - `alta`  → subnet /30 ou /31 compartilhada (uplink L3 / fechamento de MPLS).
    - `media` → descrição da interface cita o hostname do vizinho.

    Use junto de `/topology` para desenhar o caminho realçado no grafo.
    """
    client = await db.get(models.Client, client_id)
    if not client:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", "Cliente não encontrado.", "Verifique o ID do cliente."),
        )

    # Todas as associações (vlan_interface) com VID alvo, dos ativos aprovados do grupo.
    res = await db.execute(
        select(models.VlanInterface, models.AssetInterface, models.Asset, models.Vlan)
        .join(models.AssetInterface, models.VlanInterface.interface_id == models.AssetInterface.id)
        .join(models.Asset, models.AssetInterface.asset_id == models.Asset.id)
        .join(models.Vlan, models.VlanInterface.vlan_id == models.Vlan.id)
        .where(
            models.Asset.client_id == client_id,
            models.Asset.is_approved == True,
            models.Vlan.vid == vid,
        )
        .order_by(models.Asset.hostname, models.AssetInterface.name)
    )
    rows = res.all()

    vlan_name = None
    vlan_desc = None
    endpoints: list[dict] = []
    seen_iface: set[int] = set()
    for vi, iface, asset, vlan in rows:
        if vlan_name is None and vlan.name:
            vlan_name = vlan.name
        if vlan_desc is None and vlan.description:
            vlan_desc = vlan.description
        # Evita duplicar a mesma interface (várias linhas de VlanInterface possíveis).
        if iface.id in seen_iface:
            continue
        seen_iface.add(iface.id)

        # Subnet (IP real) configurada nesta interface, se houver.
        res_sub = await db.execute(
            select(models.Subnet).where(models.Subnet.interface_id == iface.id).limit(1)
        )
        sub = res_sub.scalars().first()
        endpoints.append({
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "vendor": asset.vendor,
            "category": asset.category,
            "interface": iface.name,
            "interface_type": iface.type or "physical",
            "mode": vi.mode or "trunk",
            "description": iface.description,
            "is_management": bool(iface.is_management),
            "host_ip": sub.host_ip if sub else None,
            "network": sub.network if sub else None,
            "mask": sub.mask if sub else None,
            "vlan_type": vlan.vlan_type,
            "vlan_config": vlan.config,
        })

    links = topology_links.infer_links(endpoints)

    stats = {
        "asset_count": len({e["asset_id"] for e in endpoints}),
        "interface_count": len(endpoints),
        "link_count": len(links),
        "inferred_high": sum(1 for l in links if l["confidence"] == "alta"),
        "inferred_medium": sum(1 for l in links if l["confidence"] == "media"),
    }

    return VlanTraceResponse(
        client_id=client_id,
        vid=vid,
        name=vlan_name,
        description=vlan_desc,
        endpoints=[VlanTraceEndpoint(**e) for e in endpoints],
        links=[VlanTraceLink(**l) for l in links],
        stats=stats,
    )


@app.get("/api/clients/{client_id}/vlans/{vid}/configs")
async def get_vlan_configs(client_id: int, vid: int, db: AsyncSession = Depends(database.get_db)):
    """Config bruta da VLAN por ativo — direto das linhas Vlan (vsi/l2vc/routed/L2),
    sem depender de mapeamento VlanInterface (cobre l2vc/vsi em Vlanif/sub-interface
    que o topology_parser não vincula). Usado pelo "Ver config da VLAN" da UI."""
    res = await db.execute(
        select(models.Vlan, models.Asset)
        .join(models.Asset, models.Vlan.asset_id == models.Asset.id)
        .where(models.Asset.client_id == client_id, models.Asset.is_approved == True, models.Vlan.vid == vid)
        .order_by(models.Asset.hostname)
    )
    out = []
    for vlan, asset in res.all():
        out.append({
            "asset_id": asset.id, "hostname": asset.hostname, "vendor": asset.vendor,
            "category": asset.category, "vlan_type": vlan.vlan_type, "name": vlan.name,
            "config": vlan.config,
        })
    return out

# ==========================================
# ROTAS: VÍNCULOS BC POR GRUPO
# ==========================================
@app.get("/api/clients/{client_id}/bc-links", response_model=List[ClientBCLinkResponse])
async def list_bc_links(client_id: int, db: AsyncSession = Depends(database.get_db)):
    result = await db.execute(
        select(models.ClientBCLink)
        .options(selectinload(models.ClientBCLink.bc_server))
        .where(models.ClientBCLink.client_id == client_id)
    )
    links = result.scalars().all()
    for lnk in links:
        lnk.bc_server_name = lnk.bc_server.name if lnk.bc_server else None
    return links

@app.post("/api/clients/{client_id}/bc-links", response_model=ClientBCLinkResponse)
async def add_bc_link(client_id: int, data: ClientBCLinkSchema, db: AsyncSession = Depends(database.get_db)):
    # Evita duplicata do mesmo grupo no mesmo cliente
    check = await db.execute(
        select(models.ClientBCLink).where(
            models.ClientBCLink.client_id == client_id,
            models.ClientBCLink.external_group_id == data.external_group_id
        )
    )
    if check.scalars().first():
        raise HTTPException(
            status_code=409,
            detail=api_error("bc_link_duplicate", "Este grupo BC já está vinculado a este cliente.", "Escolha outro grupo ou remova o vínculo existente."),
        )
    link = models.ClientBCLink(client_id=client_id, **data.model_dump())
    db.add(link)
    await db.commit()
    await db.refresh(link)
    server = await db.get(models.BCServer, link.bc_server_id)
    link.bc_server_name = server.name if server else None
    return link

@app.delete("/api/clients/{client_id}/bc-links/{link_id}")
async def remove_bc_link(client_id: int, link_id: int, db: AsyncSession = Depends(database.get_db)):
    link = await db.get(models.ClientBCLink, link_id)
    if not link or link.client_id != client_id:
        raise HTTPException(
            status_code=404,
            detail=api_error("bc_link_not_found", "Vínculo Backup API não encontrado.", "Atualize a lista de vínculos e tente novamente."),
        )
    await db.delete(link)
    await db.commit()
    return {"message": "Vínculo removido."}

@app.post("/api/clients/{client_id}/bc-links/{link_id}/discover")
async def discover_from_link(client_id: int, link_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(database.get_db)):
    result = await auto_discovery.sync_discovered_assets(client_id, db, link_id=link_id)
    if result.get("status") == "error":
        return JSONResponse(status_code=502, content=result)
    background_tasks.add_task(_run_extract_bg, client_id)
    return result


# ==========================================
# ROTAS: LOGS DE EXECUÇÃO
# ==========================================
@app.get("/api/clients/{client_id}/logs", response_model=List[ExecutionLogResponse])
async def get_client_logs(
    client_id: int,
    page: int = 1,
    limit: int = 50,
    db: AsyncSession = Depends(database.get_db)
):
    # Validação de bounds para prevenir abuso de paginação
    page = max(1, min(page, 10_000))
    limit = max(1, min(limit, 200))
    offset = (page - 1) * limit
    result = await db.execute(
        select(models.ExecutionLog)
        .where(models.ExecutionLog.client_id == client_id)
        .order_by(desc(models.ExecutionLog.created_at))
        .offset(offset)
        .limit(limit)
    )
    return result.scalars().all()


# Valores permitidos nos filtros de log (allowlist)
_ALLOWED_LOG_OPERATIONS = {
    "sync_assets", "extract_bc", "sync_phpipam", "sync_netbox",
    "extract_manual", "discover_assets", "extract_all", "daily_sync",
}
_ALLOWED_LOG_STATUSES = {"success", "error", "warning", "running"}


@app.get("/api/logs", response_model=List[ExecutionLogResponse])
async def get_global_logs(
    response: Response,
    operation: Optional[str] = None,
    status: Optional[str] = None,
    client_id: Optional[int] = None,
    page: int = 1,
    limit: int = 50,
    db: AsyncSession = Depends(database.get_db)
):
    # Validação de bounds para prevenir abuso de paginação
    page = max(1, min(page, 10_000))
    limit = max(1, min(limit, 200))

    filters = []
    if operation:
        # Allowlist: ignora valores desconhecidos silenciosamente
        if operation in _ALLOWED_LOG_OPERATIONS:
            filters.append(models.ExecutionLog.operation == operation)
    if status:
        # Allowlist: ignora valores desconhecidos silenciosamente
        if status in _ALLOWED_LOG_STATUSES:
            filters.append(models.ExecutionLog.status == status)
    if client_id:
        filters.append(models.ExecutionLog.client_id == client_id)

    query = select(models.ExecutionLog)
    if filters:
        query = query.where(and_(*filters))
    # Busca um registro a mais que o limite só para saber se há próxima página
    # (sem custo de um COUNT): se vierem limit+1, há mais; devolvemos só limit.
    query = query.order_by(desc(models.ExecutionLog.created_at)).offset((page - 1) * limit).limit(limit + 1)

    result = await db.execute(query)
    rows = result.scalars().all()
    has_more = len(rows) > limit
    response.headers["X-Has-More"] = "true" if has_more else "false"
    return rows[:limit]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("API_PORT", "8000")))
