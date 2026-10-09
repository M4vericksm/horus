# NetworkAtlas

> Orquestrador de rede para provedores (ISP): lê a configuração dos equipamentos, extrai VLANs, subnets e interfaces, e mantém o IPAM (phpIPAM / NetBox) sincronizado — sem planilha e sem cadastro manual.

![Python](https://img.shields.io/badge/Python_3.11-111?style=flat-square&logo=python&logoColor=4C9AC9)
![FastAPI](https://img.shields.io/badge/FastAPI-111?style=flat-square&logo=fastapi&logoColor=4C9AC9)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL_15-111?style=flat-square&logo=postgresql&logoColor=4C9AC9)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy_async-111?style=flat-square&logo=sqlalchemy&logoColor=4C9AC9)
![Docker](https://img.shields.io/badge/Docker-111?style=flat-square&logo=docker&logoColor=4C9AC9)
![Tests](https://img.shields.io/badge/testes-500%2B-111?style=flat-square&logo=pytest&logoColor=4C9AC9)

---

## O problema

Em um provedor, a "verdade" da rede mora na configuração dos roteadores e switches — e o IPAM fica sempre atrasado em relação a ela. VLANs criadas às pressas, subnets sem documentação, conflitos de VID entre equipamentos: tudo isso só aparece quando algo quebra.

O NetworkAtlas fecha esse ciclo automaticamente:

```
equipamentos ──► coleta de configs ──► parse por fabricante ──► banco ──► phpIPAM / NetBox
 (backup/SSH)                          (10 drivers)                       + topologia, busca, monitoramento
```

## Funcionalidades

**Coleta**
- Descoberta de ativos a partir de um servidor de backup de configurações (BackupCenter, via REST, com paginação e retry)
- Extração direta por **SSH**, inclusive através de **jump host / VPN** (hierarquia ativo → cliente → direto), com verificação de host key em modo TOFU (anti-MITM)
- Job global "extrair tudo" com acompanhamento por `job_id` e **sync diário automático**

**Parse multi-fabricante** — um driver por vendor em [`drivers/`](drivers/)
- Cisco · Huawei · MikroTik · Juniper · Datacom · ZTE · Fiberhome · V-SOL · Intelbras · Hillstone
- Extrai VLANs, subnets, interfaces, rotas estáticas e IP de gerência; identifica o fabricante automaticamente

**IPAM**
- Sincronização com **phpIPAM** (sections, L2 domains, VLANs, subnets) e **NetBox** (sites, VLAN groups, VLANs, prefixos, interfaces)
- Detecção e resolução de **conflitos de VLAN** (mesmo VID com nomes diferentes entre ativos)
- **AUTO IPAM**: cruza os IPs vivos do **Zabbix** com os blocos declarados nas configs e documenta o que falta

**Visualização**
- Dashboard por provedor, **busca de VLAN entre provedores** ("onde essa VLAN passa?"), listagem de VLANs/IPs com filtros
- **Topologia** gerada a partir das configs, com enlaces classificados por nível de confiança
- Histórico de execuções com logs estruturados por operação

**Segurança**
- Login com **MFA (TOTP) obrigatório**, cadastro restrito por domínio de e-mail, "esqueci minha senha" com token por e-mail
- Sessões HMAC stateless com revogação, **rate limiting** nas rotas sensíveis, CORS restrito por ambiente
- Segredos (tokens, senhas de VPN/IPAM) criptografados no banco com **Fernet** e mascarados nas respostas da API
- Proteção **anti-SSRF** em toda URL externa cadastrada

## Stack

| Camada | Tecnologia |
|---|---|
| API | FastAPI · Pydantic v2 · uvicorn |
| Persistência | PostgreSQL 15 · SQLAlchemy 2 (async) · asyncpg · Alembic |
| Integrações | httpx (BackupCenter, phpIPAM, NetBox, Zabbix JSON-RPC) · Paramiko (SSH) |
| Segurança | cryptography (Fernet) · TOTP · PBKDF2-SHA256 |
| Front-end | HTML + JavaScript puro · Tailwind · Lucide, servido por nginx |
| Testes | pytest · pytest-asyncio · respx · SQLite em memória |
| Infra | Docker Compose · GitHub Actions |

## Arquitetura

```
back/
  main.py             # rotas FastAPI (~70 endpoints), schemas, auth, CORS, rate limit, lifespan
  auto_discovery.py   # regras de negócio: descoberta, extração, sync phpIPAM/NetBox, conflitos
  sync_jobs.py        # jobs globais + scheduler diário
  network_logic.py    # SSH com jump host e política de host key
  zabbix_client.py    # cliente Zabbix (JSON-RPC) e filtro de IPs documentáveis
  topology_*.py       # parse e montagem de enlaces da topologia
  models.py           # modelos SQLAlchemy
  security.py         # anti-SSRF · crypto.py: Fernet
drivers/              # um parser por fabricante (base.py + 10 drivers)
front/                # telas estáticas: dashboard, grupos, VLANs, IPs, topologia, logs, usuários
docs/                 # códigos de erro da API e guias (adicionar driver, endpoint, migration)
```

Fluxo de uma rota: `main.py` (fina) → função de negócio em `auto_discovery.py` / `sync_jobs.py` → `models.py`. Toda operação longa grava um registro em `execution_logs`.

## Como rodar

**Stack completa (Docker):**

```bash
cp .env.example .env      # preencha banco, FERNET_KEY e ATLAS_API_KEY (instruções no arquivo)
docker compose up --build -d
# front: http://localhost · API: http://localhost:8000 · docs: http://localhost:8000/docs
```

**API local, sem Docker** (rodar da raiz — `drivers/` fica na raiz):

```bash
pip install -r back/requirements.txt
PYTHONPATH='back:.' DATABASE_URL='sqlite+aiosqlite:///local_dev.db' \
  python -m uvicorn main:app --app-dir back --reload --port 8000
```

**Testes:**

```bash
pip install -r back/requirements.txt -r back/requirements-dev.txt
PYTHONPATH='back:.' DATABASE_URL='sqlite+aiosqlite:///:memory:' ATLAS_API_KEY=test-key \
  FERNET_KEY="$(python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')" \
  APP_ENV=test python -m pytest back/tests/ -q --no-cov
```

Para popular um ambiente de demonstração com dados fictícios: `back/_seed_demo.py`.

## Estendendo

- Novo fabricante: [`docs/skills/adicionar-driver.md`](docs/skills/adicionar-driver.md)
- Novo endpoint: [`docs/skills/adicionar-endpoint.md`](docs/skills/adicionar-endpoint.md)
- Nova coluna/model: [`docs/skills/adicionar-model-e-migration.md`](docs/skills/adicionar-model-e-migration.md)
- Códigos de erro da API: [`docs/ERROR_CODES.md`](docs/ERROR_CODES.md)

---

<sub>Projeto desenvolvido por [Maverick Martins](https://github.com/M4vericksm). Todos os nomes, IPs e dados presentes no código e nos testes são fictícios.</sub>
