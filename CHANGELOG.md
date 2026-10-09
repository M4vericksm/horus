# Changelog

## Unreleased

### Fixed

- Corrige a lentidao da listagem de clientes proporcional ao numero de VLANs: `GET /api/clients` e `GET /api/clients/{id}` carregavam assets, VLANs e subnets de todos os clientes apenas para contar em Python. As contagens passam a ser subqueries no banco (61,3ms -> 26,6ms e 4.043 -> 0 linhas filhas em base de teste; em producao o ganho escala porque a consulta deixa de crescer com o volume de VLANs).
- Corrige a montagem de URLs do BackupCenter para respeitar o contrato de que `BCServer.url` ja inclui `/api/v1/external`. O discover via `ClientBCLink` e o download de backups agora usam um helper centralizado, evitando URLs duplicadas como `/api/v1/external/api/v1/external/...`.
- Torna falhas da API BackupCenter visiveis no discover: respostas HTTP 4xx/5xx e timeouts agora gravam `execution_logs.status = "error"` com URL mascarada e a rota de discover por vinculo retorna erro claro, em vez de informar que todos os equipamentos ja estavam sincronizados.
- Preserva a paginacao do endpoint de backups do BackupCenter, percorrendo todas as paginas retornadas por `pages`.

### Added

- Busca de VLAN entre provedores (`GET /api/vlans/search?q=`): agrupa por provedor as ocorrencias de um VID ou nome, com os ativos onde a VLAN foi extraida. Responde "onde essa VLAN passa" quando ela atravessa varios provedores. No front, painel dedicado com atalho `/`.
- Seletor de provedor com busca digitavel (`js/provider-picker.js`) nas telas de VLANs, IPs e Topologia — com ~100 provedores, rolar o `<select>` nativo nao escalava.
- Filtro de provedores por nome no dashboard (sem nova requisicao) e atalhos diretos para VLANs/IPs/Topologia em cada cartao.
- Integracao Zabbix (modo A, leitura via API JSON-RPC) por cliente: colunas `zabbix_url`/`zabbix_token`/`zabbix_verify_tls`, cliente `zabbix_client` com fallback de auth Bearer->campo `auth`, e endpoints read-only `/api/zabbix/test` e `/api/clients/{id}/monitoring/{summary,problems,hosts}` (saude dos ativos e problemas por severidade). Config no front (clientes_config.html) com teste de conexao.
- AUTO IPAM: `/api/clients/{id}/sync-monitoring-ips` cruza os IPs vivos observados no Zabbix com os blocos declarados (Subnets extraidas das configs) e popula o phpIPAM automaticamente (idempotente); IPs fora de qualquer bloco declarado retornam como `orphans` (rede nao documentada).
- Adiciona tratamento de erros estruturado, retry com backoff em chamadas externas e status de ultima sincronizacao por ativo.
- Adiciona criptografia Fernet para tokens/senhas sensiveis, autenticação `X-API-Key`, rate limiting em rotas críticas, validação anti-SSRF e CORS restrito por ambiente.
- Sincroniza o IP host das interfaces como address dentro da subnet correspondente no phpIPAM (migration 012, idempotente).

### Security

- Sessões de auth agora são stateless (token HMAC-SHA256 assinado, TTL 8h): sobrevivem a restart e valem em qualquer worker.
- URLs de phpIPAM/NetBox sem scheme assumem `https://` por padrão e o sync real valida anti-SSRF antes de conectar.
- Segredos (token, senhas phpIPAM/NetBox/VPN/SSH) deixam de ser retornados pela API: respostas trazem a máscara `********` e updates que devolvem a máscara preservam o valor armazenado. Formulários passam a exibir `********` em campos preenchidos — comportamento esperado após o deploy.
