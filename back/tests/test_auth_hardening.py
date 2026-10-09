"""Endurecimento do cadastro e do login.

Cobre três decisões tomadas em 27/07/2026:

1. **Auto-cadastro não sobrescreve conta existente.** A versão anterior só
   barrava quando o MFA já estava ativo — como os usuários de seed (inclusive o
   administrador) nascem sem MFA, era possível registrar com o e-mail deles,
   trocar senha e segredo e receber o QR: tomada de conta sem credencial.
2. **Cadastro entra inativo**, dependendo de aprovação de um administrador —
   pertencer ao domínio corporativo prova pouco, já que basta conhecê-lo.
3. **MFA é obrigatório para todos**: conta sem enrolamento recebe o segredo no
   login e só entra depois de confirmar o primeiro código.
"""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient

import database
import models
from main import ADMIN_EMAIL, app, RATE_BUCKETS, _totp_at

SENHA_FORTE = "Horus@2026Seg"


def _codigo_atual(secret: str) -> str:
    """Código TOTP da janela corrente (passo de 30s), como o app autenticador."""
    return _totp_at(secret, int(time.time()) // 30)


def _run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


async def _buscar(email):
    from sqlalchemy import select
    async with database.AsyncSessionLocal() as db:
        return (await db.execute(
            select(models.User).where(models.User.email == email)
        )).scalars().first()


async def _aprovar(email):
    from sqlalchemy import select
    async with database.AsyncSessionLocal() as db:
        u = (await db.execute(
            select(models.User).where(models.User.email == email)
        )).scalars().first()
        u.is_active = True
        await db.commit()


# ──────────────────────────────────────────
# 1. Tomada de conta pelo auto-cadastro
# ──────────────────────────────────────────

def test_registro_nao_sobrescreve_conta_do_admin(client):
    """Regressão da falha crítica: registrar com o e-mail do administrador
    trocava a senha e o segredo de MFA dele e devolvia o QR ao atacante."""
    c, _ = client
    antes = _run(_buscar(ADMIN_EMAIL))
    assert antes is not None, "o seed deve ter criado o administrador"
    hash_antes, secret_antes = antes.password_hash, antes.mfa_secret

    r = c.post("/api/register", json={"email": ADMIN_EMAIL, "password": SENHA_FORTE})

    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "email_taken"
    corpo = r.text
    assert "otpauth" not in corpo and "secret" not in corpo, "não pode vazar segredo de MFA"

    depois = _run(_buscar(ADMIN_EMAIL))
    assert depois.password_hash == hash_antes, "a senha do admin não pode mudar"
    assert depois.mfa_secret == secret_antes, "o segredo de MFA do admin não pode mudar"


def test_registro_nao_sobrescreve_conta_comum(client):
    """Mesmo contrato para qualquer conta já existente, com ou sem MFA."""
    c, _ = client
    email = "conta.existente@example.com"
    r1 = c.post("/api/register", json={"email": email, "password": SENHA_FORTE})
    assert r1.status_code == 200
    hash_antes = _run(_buscar(email)).password_hash

    r2 = c.post("/api/register", json={"email": email, "password": "Outra@Senha9"})
    assert r2.status_code == 409
    assert _run(_buscar(email)).password_hash == hash_antes


# ──────────────────────────────────────────
# 2. Aprovação pelo administrador
# ──────────────────────────────────────────

def test_registro_nasce_inativo_e_nao_devolve_segredo(client):
    c, _ = client
    email = "novato@example.com"
    r = c.post("/api/register", json={"email": email, "password": SENHA_FORTE})
    body = r.json()

    assert r.status_code == 200
    assert body["pending_approval"] is True
    assert "secret" not in body and "otpauth_uri" not in body
    assert _run(_buscar(email)).is_active is False


def test_conta_pendente_nao_loga(client):
    c, _ = client
    email = "pendente@example.com"
    c.post("/api/register", json={"email": email, "password": SENHA_FORTE})

    r = c.post("/api/login", json={"email": email, "password": SENHA_FORTE})
    assert r.status_code == 401, "conta não aprovada não pode autenticar"


def test_apos_aprovacao_o_login_prossegue_para_o_mfa(client):
    c, _ = client
    email = "aprovado@example.com"
    c.post("/api/register", json={"email": email, "password": SENHA_FORTE})
    _run(_aprovar(email))

    r = c.post("/api/login", json={"email": email, "password": SENHA_FORTE})
    body = r.json()
    assert r.status_code == 200
    assert body.get("mfa_enrollment_required") is True
    assert "session_token" not in body, "não pode logar sem concluir o MFA"


def test_dominio_nao_autorizado_continua_bloqueado(client):
    c, _ = client
    r = c.post("/api/register", json={"email": "alguem@gmail.com", "password": SENHA_FORTE})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "email_domain_blocked"


# ──────────────────────────────────────────
# 3. MFA obrigatório para todos
# ──────────────────────────────────────────

def test_login_de_conta_sem_mfa_exige_enrolamento(client):
    """Usuário de seed não tinha MFA e entrava direto com senha."""
    c, _ = client
    r = c.post("/api/login", json={"username": "maverick", "password": "Seed@Teste-1234"})
    body = r.json()

    assert r.status_code == 200
    assert body.get("mfa_enrollment_required") is True
    assert "session_token" not in body, "senha sozinha não pode mais dar sessão"
    assert body.get("otpauth_uri", "").startswith("otpauth://")
    assert body.get("pre_auth")


def test_enrolamento_conclui_com_o_primeiro_codigo_e_persiste(client):
    c, _ = client
    r1 = c.post("/api/login", json={"username": "maverick", "password": "Seed@Teste-1234"}).json()

    r2 = c.post("/api/login/mfa", json={
        "pre_auth": r1["pre_auth"], "code": _codigo_atual(r1["secret"])})
    assert r2.status_code == 200
    assert r2.json().get("session_token"), "primeiro código válido deve logar"

    # A partir daí a conta exige o segundo fator, não mais o enrolamento.
    r3 = c.post("/api/login", json={"username": "maverick", "password": "Seed@Teste-1234"}).json()
    assert r3.get("mfa_required") is True
    assert "secret" not in r3, "segredo não pode ser reexposto depois de ativo"


def test_codigo_invalido_nao_ativa_mfa(client):
    c, _ = client
    r1 = c.post("/api/login", json={"username": "operador", "password": "x"}).json()
    # senha errada nem chega ao MFA
    assert "pre_auth" not in r1
