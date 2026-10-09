# skill: adicionar endpoint

Tudo acontece em `back/main.py` (não há routers separados). Passos:

1. **Schema Pydantic**: declare perto dos demais (linhas ~400–560 de main.py), sufixo `Schema` (entrada) ou `Response` (saída).
2. **Rota**: função `async`, injete o banco com `Depends(database.get_db)`. Exemplo real (main.py:1183):

```python
@app.get("/api/clients/{client_id}", response_model=ClientListResponse)
async def get_client(client_id: int, db: AsyncSession = Depends(database.get_db)):
    res = await db.execute(
        select(models.Client).options(selectinload(models.Client.assets))
        .where(models.Client.id == client_id)
    )
    client = res.scalar_one_or_none()
    if not client:
        raise HTTPException(
            status_code=404,
            detail=api_error("client_not_found", "Cliente não encontrado.",
                             "Verifique o ID do cliente e tente novamente."),
        )
    return _decrypt_attrs(client, CLIENT_SECRET_FIELDS)
```

3. **Erros**: sempre `api_error("codigo_snake", "Mensagem pt-BR.", "Ação sugerida.")`; código novo entra em `docs/ERROR_CODES.md`. Conflito de unicidade → capture `IntegrityError`, rollback, 409.
4. **Segredos**: campos sensíveis usam `_encrypt_payload(...)` ao gravar e `_decrypt_attrs(...)` ao retornar.
5. **Operação longa por cliente**: envolva com `async with log_exec(db, client_id=..., operation="nome_op")`.
6. **Auth**: automática — o middleware exige `X-API-Key` (token de sessão HMAC) em tudo sob `/api/`, exceto `/api/login` e `/api/drivers` (`/healthz` também é público). Rota pública nova exige adicionar o path em `public_paths` no middleware (main.py ~338). Rate limit também é automático no middleware.
7. **Teste**: crie/estenda arquivo em `back/tests/` usando as fixtures `api_client` e `headers` do conftest:

```python
def test_get_client_404(api_client, headers):
    r = api_client.get("/api/clients/9999", headers=headers)
    assert r.status_code == 404
```

8. Rode da raiz: `PYTHONPATH='back:.' python -m pytest back/tests/ -q --no-cov` (envs: ver README.md).
9. Se o frontend consome: chamadas via `front/js/api.js` (fetch já injeta o token; não duplique lógica de auth).
