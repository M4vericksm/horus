"""Gestão de usuários restrita ao administrador.

Regras de aceite:
- Admin é designado pelo e-mail (HORUS_ADMIN_EMAIL, default admin@example.com).
- GET /api/me devolve is_admin para o front decidir exibir a gestão.
- GET/PATCH/DELETE /api/users só respondem ao admin (403 para os demais).
- Admin não pode se desativar nem ser excluído.
- Desativar um usuário bloqueia o login dele (filtro is_active).
"""
import os

from helpers import login_completo

SEED_PWD = os.environ["HORUS_SEED_MAVERICK_PASSWORD"]
ADMIN_MAIL = "admin@example.com"


def _auth(token):
    return {"X-API-Key": token}


def _admin_token(client):
    """O administrador vem do seed; o login completo já enrola o MFA dele."""
    return login_completo(client, username="maverick", password=SEED_PWD)["session_token"]


def _find_user(client, admin_token, email):
    r = client.get("/api/users", headers=_auth(admin_token))
    assert r.status_code == 200
    return next(u for u in r.json() if u["email"] == email)


def _register(client, email, password="Str0ng@Pass1"):
    """Cadastra, aprova pelo admin e conclui o login — devolve (token, email).

    Desde 27/07/2026 o auto-cadastro nasce inativo e não devolve segredo de MFA:
    quem libera é o administrador, e o enrolamento acontece no primeiro login.
    """
    r = client.post("/api/register", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    assert r.json().get("pending_approval") is True

    admin = _admin_token(client)
    alvo = _find_user(client, admin, email)
    ok = client.patch(f"/api/users/{alvo['id']}", json={"is_active": True}, headers=_auth(admin))
    assert ok.status_code == 200, ok.text

    body = login_completo(client, email=email, password=password)
    return body["session_token"], email


class TestAdminDesignation:
    def test_admin_email_is_admin(self, api_client):
        me = api_client.get("/api/me", headers=_auth(_admin_token(api_client))).json()
        assert me["is_admin"] is True
        assert me["email"] == ADMIN_MAIL

    def test_regular_user_is_not_admin(self, api_client):
        token, _ = _register(api_client, "joao@example.com")
        me = api_client.get("/api/me", headers=_auth(token)).json()
        assert me["is_admin"] is False


class TestUsersGuard:
    def test_list_users_forbidden_for_regular(self, api_client):
        token, _ = _register(api_client, "joao@example.com")
        r = api_client.get("/api/users", headers=_auth(token))
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "admin_only"

    def test_list_users_requires_auth(self, api_client):
        r = api_client.get("/api/users")
        assert r.status_code == 401

    def test_admin_lists_all_users(self, api_client):
        admin_token = _admin_token(api_client)
        _register(api_client, "joao@example.com")
        emails = {u["email"] for u in api_client.get("/api/users", headers=_auth(admin_token)).json()}
        assert {ADMIN_MAIL, "joao@example.com"} <= emails


class TestUserMutations:
    def test_deactivate_blocks_login(self, api_client):
        admin_token = _admin_token(api_client)
        _register(api_client, "joao@example.com")
        joao = _find_user(api_client, admin_token, "joao@example.com")

        r = api_client.patch(f"/api/users/{joao['id']}", json={"is_active": False}, headers=_auth(admin_token))
        assert r.status_code == 200 and r.json()["is_active"] is False

        # Login do joao agora falha (filtro is_active == True)
        login = api_client.post("/api/login", json={"email": "joao@example.com", "password": "Str0ng@Pass1"})
        assert login.status_code == 401

    def test_cannot_disable_admin(self, api_client):
        admin_token = _admin_token(api_client)
        admin = _find_user(api_client, admin_token, ADMIN_MAIL)
        r = api_client.patch(f"/api/users/{admin['id']}", json={"is_active": False}, headers=_auth(admin_token))
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "cannot_disable_admin"

    def test_delete_regular_user(self, api_client):
        admin_token = _admin_token(api_client)
        _register(api_client, "joao@example.com")
        joao = _find_user(api_client, admin_token, "joao@example.com")
        r = api_client.delete(f"/api/users/{joao['id']}", headers=_auth(admin_token))
        assert r.status_code == 200
        emails = {u["email"] for u in api_client.get("/api/users", headers=_auth(admin_token)).json()}
        assert "joao@example.com" not in emails

    def test_cannot_delete_admin(self, api_client):
        admin_token = _admin_token(api_client)
        admin = _find_user(api_client, admin_token, ADMIN_MAIL)
        r = api_client.delete(f"/api/users/{admin['id']}", headers=_auth(admin_token))
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "cannot_delete_admin"
