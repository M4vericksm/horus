import os
import sys

# Define antes de qualquer import da aplicação para que database.py use SQLite
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ.setdefault("ATLAS_API_KEY", "test-key")
# Chave Fernet fixa para testes (criptografia de tokens em BCServer/Client)
os.environ.setdefault("FERNET_KEY", "C5LxWEXjlFk89r0ftj0n861jF-axuxFRy_IYIL_B2Bs=")
# Senha de seed determinística para os testes de login (em produção vem do .env)
os.environ.setdefault("ATLAS_SEED_MAVERICK_PASSWORD", "Seed@Teste-1234")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
# Permite `from helpers import ...` entre os módulos de teste.
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient

from main import app, RATE_BUCKETS, _create_session


@pytest.fixture
def api_client():
    """TestClient com lifespan completo (cria tabelas, seed de usuários)."""
    RATE_BUCKETS.clear()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def headers():
    """Header de auth no modelo de sessão (anti-token-grab): o backend valida o
    X-API-Key contra o store de sessões em memória (SESSION_TOKENS), não contra a
    ATLAS_API_KEY bruta. Mintamos um token de sessão direto — equivale a um
    /api/login bem-sucedido, sem custo de HTTP/DB no setup."""
    return {"X-API-Key": _create_session("maverick")}
