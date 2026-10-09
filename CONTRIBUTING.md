# Contribuindo com o Horus

Obrigado por contribuir. Este guia cobre a estrutura do projeto, como rodar
tudo localmente e o caminho para adicionar suporte a um novo fabricante.

## Estrutura do repositório

- `back/` — API FastAPI. Arquivos centrais: `main.py` (rotas), `models.py`
  (SQLAlchemy), `network_logic.py` (orquestração SSH/seleção de driver),
  `auto_discovery.py` (descoberta, identificação de vendor, sync phpIPAM/NetBox).
  Testes em `back/tests/`, migrations Alembic em `back/alembic/`.
- `drivers/` — drivers de vendor, **na raiz do repo** (não dentro de `back/`).
  Um arquivo por fabricante, todos subclasses de `NetworkDriver`
  (`drivers/base.py`).
- `front/` — HTML/JS estático (servido por nginx; apenas arquivos estáticos).
- `docs/` — planos de sprint, relatórios e documentação técnica.

## Rodando localmente

### Docker

```
docker compose up --build -d
```

### Testes

Os drivers moram na raiz e o `pytest.ini` fica em `back/`, então o `PYTHONPATH`
precisa conter **a raiz e `back/`**. Rode a partir da raiz do repositório:

Linux/macOS:
```
PYTHONPATH=back:. python -m pytest back/tests/ -q
```

Windows (PowerShell — o separador de PYTHONPATH é `;`):
```
$env:PYTHONPATH='back;.'; python -m pytest back/tests/ -q
```

Adicione `--no-cov` para iteração rápida (o `back/pytest.ini` liga cobertura por
padrão). **Não** invoque `pytest` direto — sem `python -m` + `PYTHONPATH` os
módulos não são encontrados.

Dependências:
```
pip install -r back/requirements.txt -r back/requirements-dev.txt
```

## Adicionando um driver de vendor novo

1. **Crie `drivers/<vendor>.py`** com uma classe `<Vendor>Driver(NetworkDriver)`.
   Importe `from .base import NetworkDriver` e `from logger import logger`
   (espelhe `drivers/cisco.py`).
2. **Defina os atributos de classe** `display_name` (ex.: `"Cisco IOS/IOS-XE"`)
   e `vendor_key` (ex.: `"cisco"`). Os booleans `supports_ssh_extract` e
   `supports_bc_extract` herdam `True` — só redefina se o driver não suportar
   um dos modos.
3. **Implemente os 4 métodos abstratos** + sobrescreva `parse_device_info`:
   - `get_ssh_command_setup() -> str` — comando que desliga paginação
     (ex.: `"terminal length 0"`), ou `""` se não houver.
   - `get_config_command() -> str` — comando que imprime a config completa.
   - `parse_vlans(config_text) -> list` — itens
     `{"id": int, "name": str, "description": str}`.
   - `parse_subnets(config_text) -> list` — itens
     `{"network": str, "mask": int (CIDR), "description": str}`.
   - `parse_device_info(config_text) -> dict` —
     `{"model": str|None, "serial_number": str|None}`.
   - **Os parsers degradam graciosamente:** config vazio/desconhecido →
     retornam `[]` / `None`. **Nunca** levantam exceção.
4. **Registre em `back/network_logic.py`**, dentro de `get_driver_class`,
   um ramo `elif vendor == "<vendor>": ... return <Vendor>Driver`.
5. **Adicione à lista `_CONCRETE_DRIVERS` em `back/main.py`** (com o import)
   para que o endpoint `GET /api/drivers` liste o driver.
6. **Adicione marcadores em `back/auto_discovery.py`**, na constante
   `VENDOR_MARKERS` (`{"<vendor>": ["marcador1", "marcador2"]}`), usando trechos
   distintivos da config daquele fabricante. Se houver um teste que trava a
   quantidade de vendors (`test_vendor_markers_table_has_*_vendors`), atualize-o.
7. **Crie `back/tests/test_drivers_<vendor>.py`** com configs sintéticos
   (nunca dumps reais — privacidade). Cubra: VLAN única, múltiplas VLANs +
   subnets, config malformado (retorna `[]`) e config vazio.

## Padrão de commits

- Prefixo `tipo(sprint)`: `feat(s11-01): ...`, `fix(s11-02): ...`,
  `refactor(s11-03): ...`, `docs(s11-05): ...`.
- Corpo com **"Mudança:"** (o que mudou) e **"Por quê:"**.
- **Nunca** inclua `Co-Authored-By`. **Nunca** dê `git push` sem pedido explícito.
- `git add` por nome de arquivo, não `git add .`.
