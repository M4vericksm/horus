"""Regressão: o usuário admin semeado precisa ter e-mail corporativo para
(1) logar por e-mail e (2) ser reconhecido como admin (_is_admin_user compara
user.email == ADMIN_EMAIL). Antes do fix o seed criava usuários sem e-mail."""
import os

from helpers import login_completo
from main import ADMIN_EMAIL

SEED_PWD = os.environ["ATLAS_SEED_MAVERICK_PASSWORD"]  # definido no conftest


def test_admin_loga_por_email_e_e_reconhecido_como_admin(api_client):
    token = login_completo(api_client, email=ADMIN_EMAIL, password=SEED_PWD)["session_token"]

    me = api_client.get("/api/me", headers={"X-API-Key": token})
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["username"] == "maverick"
    assert body["email"] == ADMIN_EMAIL
    assert body["is_admin"] is True


def test_admin_loga_por_username_e_traz_email_preenchido(api_client):
    token = login_completo(api_client, username="maverick", password=SEED_PWD)["session_token"]

    me = api_client.get("/api/me", headers={"X-API-Key": token}).json()
    assert me["email"] == ADMIN_EMAIL  # e-mail não pode ficar nulo
    assert me["is_admin"] is True
