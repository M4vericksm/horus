"""Utilitários compartilhados entre os testes."""
import time

# Segredos de MFA já enrolados nesta execução, por identificador. Faz o papel do
# app autenticador: uma vez enrolada a conta, os logins seguintes reusam o mesmo
# segredo em vez de exigir novo enrolamento.
_SEGREDOS: dict[str, str] = {}


def limpar_segredos():
    _SEGREDOS.clear()


def login_completo(client, *, username=None, email=None, password):
    """Executa o login de ponta a ponta, incluindo o segundo fator.

    Desde 27/07/2026 o MFA é obrigatório: a senha nunca devolve sessão sozinha.
    Conta sem enrolamento recebe o segredo no login (`mfa_enrollment_required`) e
    conta já enrolada pede o código (`mfa_required`); nos dois casos a sessão sai
    do /api/login/mfa. Devolve o corpo final da resposta.
    """
    from main import _totp_at

    payload = {"password": password}
    if email:
        payload["email"] = email
    if username:
        payload["username"] = username

    chave = (username or email or "").lower()
    r1 = client.post("/api/login", json=payload)
    if r1.status_code != 200:
        return r1.json()
    body = r1.json()
    if body.get("session_token"):
        return body

    # No enrolamento o segredo vem na resposta; depois disso, vem da "memória
    # do autenticador" guardada aqui.
    secret = body.get("secret") or _SEGREDOS.get(chave)
    if not secret:
        raise AssertionError(
            f"login de '{chave}' pediu MFA já enrolado e o segredo é desconhecido")
    _SEGREDOS[chave] = secret

    code = _totp_at(secret, int(time.time()) // 30)
    return client.post("/api/login/mfa",
                       json={"pre_auth": body["pre_auth"], "code": code}).json()
