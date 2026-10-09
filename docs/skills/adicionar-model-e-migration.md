# skill: adicionar model / coluna + migration

ATENÇÃO: Alembic aqui é **decorativo**: o schema real vem do
`create_all` no lifespan. A migration existe para bancos Postgres já provisionados
e DEVE ser idempotente, senão falha silenciosa (warning no log) e a coluna não entra.

1. **Model**: edite `back/models.py` (classe existente ou nova herdando `Base`).
   Banco novo/teste já ganha o campo via `create_all` — nada mais necessário aí.
2. **Migration manual** (não use autogenerate): crie `back/alembic/versions/0NN_nome.py`
   copiando o padrão idempotente da `012_subnet_host_ip.py`:

```python
revision: str = '013_minha_mudanca'
down_revision: Union[str, None] = '012_subnet_host_ip'   # encadeie na última

def _has_column(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}

def upgrade() -> None:
    if not _has_column('subnets', 'minha_coluna'):
        op.add_column('subnets', sa.Column('minha_coluna', sa.String(), nullable=True))

def downgrade() -> None:
    if _has_column('subnets', 'minha_coluna'):
        op.drop_column('subnets', 'minha_coluna')
```

3. Tabela nova: mesmo padrão com `insp.get_table_names()` em vez de `_has_column`.
4. **Schemas Pydantic** em `back/main.py`: adicione o campo nos Schema/Response afetados.
5. **Teste**: a suíte usa SQLite em memória + create_all, então o campo novo aparece
   automaticamente; cubra o comportamento, não a migration.
6. Em prod, a migration roda sozinha no startup (lifespan → alembic subprocess).
   Verifique no log do container: "Migrações Alembic aplicadas com sucesso."
