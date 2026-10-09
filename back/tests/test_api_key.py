"""Testes de autenticação, rate limiting e segurança."""

import main
from helpers import login_completo


def test_session_token_roundtrip():
    token = main._create_session("maverick")
    assert main._validate_session(token) is True


def test_session_token_tampered_signature_rejected():
    payload, sig = main._create_session("maverick").rsplit(".", 1)
    flipped = ("0" if sig[-1] != "0" else "1")
    assert main._validate_session(f"{payload}.{sig[:-1]}{flipped}") is False


def test_session_token_malformed_rejected():
    assert main._validate_session("sem-ponto") is False
    assert main._validate_session("") is False


def test_session_token_other_secret_rejected(monkeypatch):
    """Token assinado com um segredo não vale sob outro — é o que garante que
    todos os workers precisam compartilhar o mesmo HORUS_API_KEY (stateless)."""
    token = main._create_session("maverick")
    monkeypatch.setenv("HORUS_API_KEY", "outro-segredo-diferente")
    assert main._validate_session(token) is False


def test_session_token_expired_rejected(monkeypatch):
    monkeypatch.setattr(main, "SESSION_TTL_HOURS", -1)
    expired = main._create_session("maverick")
    monkeypatch.setattr(main, "SESSION_TTL_HOURS", 8)
    assert main._validate_session(expired) is False


def test_login_token_authorizes_protected_endpoint(api_client):
    token = login_completo(api_client, username="maverick",
                           password="Seed@Teste-1234")["session_token"]
    r = api_client.get("/api/clients", headers={"X-API-Key": token})
    assert r.status_code == 200


def test_api_requires_x_api_key(api_client):
    r = api_client.get("/api/clients")
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "session_invalid"


def test_login_returns_session_token(api_client):
    """A sessão sai do segundo fator — senha sozinha não autentica mais."""
    assert "session_token" in login_completo(
        api_client, username="maverick", password="Seed@Teste-1234")


def test_senha_correta_sozinha_nao_da_sessao(api_client):
    """Contrato de segurança: MFA obrigatório para todos."""
    body = api_client.post("/api/login",
                           json={"username": "maverick", "password": "Seed@Teste-1234"}).json()
    assert "session_token" not in body
    assert body.get("mfa_enrollment_required") or body.get("mfa_required")


def test_login_wrong_password_returns_401(api_client):
    r = api_client.post("/api/login", json={"username": "maverick", "password": "errada"})
    assert r.status_code == 401


def test_healthz_is_public(api_client):
    r = api_client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_login_is_rate_limited(api_client):
    responses = [
        api_client.post("/api/login", json={"username": "maverick", "password": "wrong"})
        for _ in range(6)
    ]
    assert [r.status_code for r in responses[:5]] == [401, 401, 401, 401, 401]
    assert responses[5].status_code == 429
    assert responses[5].json()["detail"]["code"] == "rate_limited"


def test_logout_revokes_existing_token(api_client):
    """Logout incrementa users.token_version → o token antigo é recusado pelo
    middleware mesmo dentro do TTL (revogação server-side de sessão stateless)."""
    token = login_completo(api_client, username="maverick",
                           password="Seed@Teste-1234")["session_token"]
    assert api_client.get("/api/clients", headers={"X-API-Key": token}).status_code == 200
    assert api_client.post("/api/logout", headers={"X-API-Key": token}).status_code == 200
    r = api_client.get("/api/clients", headers={"X-API-Key": token})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "session_invalid"


def test_fresh_login_after_logout_works(api_client):
    """Após o logout, um novo login emite token com a versão nova e volta a valer."""
    token = login_completo(api_client, username="maverick",
                           password="Seed@Teste-1234")["session_token"]
    api_client.post("/api/logout", headers={"X-API-Key": token})
    token2 = login_completo(api_client, username="maverick",
                            password="Seed@Teste-1234")["session_token"]
    assert api_client.get("/api/clients", headers={"X-API-Key": token2}).status_code == 200


def test_phpipam_test_blocks_link_local_ssrf(api_client, headers):
    r = api_client.post(
        "/api/phpipam/test",
        headers=headers,
        json={"url": "http://169.254.169.254/", "token_name": "app", "token": "tok"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "url_blocked"
