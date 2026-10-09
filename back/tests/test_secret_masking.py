"""Máscara de segredos nas respostas da API e semântica keep-on-mask no update.

Segredos (token, phpipam_pass, netbox_token, vpn_pass, ssh_pass) nunca saem do
backend: as respostas trazem SECRET_MASK e, quando o frontend devolve a máscara
intacta no PUT/POST, o valor armazenado no banco é preservado.
"""
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from main import app, RATE_BUCKETS, SECRET_MASK


@pytest.fixture
def client(headers):
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c, headers


def _client_payload(**overrides):
    base = {
        "name": "Cliente Masc",
        "ip": "https://203.0.113.10",
        "token_name": "app1",
        "token": "sekret-token",
        "phpipam_pass": "sekret-pass",
        "vpn_pass": "sekret-vpn",
    }
    base.update(overrides)
    return base


def test_client_secrets_masked_in_all_responses(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json=_client_payload())
    assert r.status_code == 200
    body = r.json()
    assert body["token"] == SECRET_MASK
    assert body["phpipam_pass"] == SECRET_MASK
    assert body["vpn_pass"] == SECRET_MASK
    cid = body["id"]

    r = c.get(f"/api/clients/{cid}", headers=h)
    assert r.json()["token"] == SECRET_MASK

    r = c.get("/api/clients", headers=h)
    me = next(x for x in r.json() if x["id"] == cid)
    assert me["token"] == SECRET_MASK
    # Campo vazio não é mascarado (frontend distingue "sem valor" de "valor oculto")
    assert me["netbox_token"] in (None, "")


@respx.mock
def test_update_with_mask_keeps_stored_secret(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json=_client_payload(name="Cliente Keep"))
    cid = r.json()["id"]

    # Edição devolvendo a máscara (fluxo real do form): nome muda, token deve permanecer
    r = c.put(
        f"/api/clients/{cid}",
        headers=h,
        json=_client_payload(name="Cliente Keep 2", token=SECRET_MASK, phpipam_pass=SECRET_MASK, vpn_pass=SECRET_MASK),
    )
    assert r.status_code == 200

    # Prova fim-a-fim: remote-sections usa o token armazenado — deve ser o original
    route = respx.get(url__regex=r".*/sections/").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "1", "name": "S"}]})
    )
    r = c.get(f"/api/clients/{cid}/remote-sections", headers=h)
    assert r.status_code == 200
    assert route.called
    assert route.calls.last.request.headers["token"] == "sekret-token"


@respx.mock
def test_update_with_new_token_replaces_secret(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json=_client_payload(name="Cliente Troca"))
    cid = r.json()["id"]

    r = c.put(f"/api/clients/{cid}", headers=h, json=_client_payload(name="Cliente Troca", token="novo-token"))
    assert r.status_code == 200

    route = respx.get(url__regex=r".*/sections/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    c.get(f"/api/clients/{cid}/remote-sections", headers=h)
    assert route.calls.last.request.headers["token"] == "novo-token"


def test_update_with_empty_clears_secret(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json=_client_payload(name="Cliente Limpa"))
    cid = r.json()["id"]

    r = c.put(f"/api/clients/{cid}", headers=h, json=_client_payload(name="Cliente Limpa", token=None))
    assert r.status_code == 200
    # Token limpo: GET não mascara campo vazio
    r = c.get(f"/api/clients/{cid}", headers=h)
    assert r.json()["token"] in (None, "")


def test_bc_server_token_masked_and_kept_on_mask(client):
    c, h = client
    r = c.post(
        "/api/backup/servers",
        headers=h,
        json={"name": "BC-Masc", "url": "https://203.0.113.9", "token": "bc-sekret"},
    )
    assert r.status_code == 200
    assert r.json()["token"] == SECRET_MASK
    sid = r.json()["id"]

    r = c.get("/api/backup/servers", headers=h)
    assert next(s for s in r.json() if s["id"] == sid)["token"] == SECRET_MASK

    # PUT devolvendo a máscara não pode sobrescrever o token com "********"
    r = c.put(
        f"/api/backup/servers/{sid}",
        headers=h,
        json={"name": "BC-Masc-2", "url": "https://203.0.113.9", "token": SECRET_MASK},
    )
    assert r.status_code == 200
    assert r.json()["token"] == SECRET_MASK
    assert r.json()["name"] == "BC-Masc-2"


def test_asset_ssh_pass_masked_and_kept_on_mask(client):
    c, h = client
    r = c.post("/api/clients", headers=h, json={"name": "Grupo SSH"})
    gid = r.json()["id"]
    r = c.post(
        "/api/assets",
        headers=h,
        json={"hostname": "sw-01", "client_id": gid, "ip_address": "10.0.0.1",
              "vendor": "mikrotik", "ssh_user": "admin", "ssh_pass": "ssh-sekret"},
    )
    assert r.status_code == 200

    r = c.get(f"/api/clients/{gid}/assets", headers=h)
    asset = r.json()[0]
    assert asset["ssh_pass"] == SECRET_MASK
    aid = asset["id"]

    # PUT com máscara mantém a senha: o campo segue não-vazio (vazio não é mascarado)
    r = c.put(f"/api/assets/{aid}", headers=h, json={"ssh_pass": SECRET_MASK, "category": "core"})
    assert r.status_code == 200
    r = c.get(f"/api/clients/{gid}/assets", headers=h)
    updated = next(a for a in r.json() if a["id"] == aid)
    assert updated["ssh_pass"] == SECRET_MASK
    assert updated["category"] == "core"
