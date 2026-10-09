# Códigos de erro da API

As exceções HTTP expostas pelo backend usam `detail` estruturado:

```json
{
  "code": "client_not_found",
  "message": "Cliente não encontrado.",
  "hint": "Verifique o ID do cliente e tente novamente."
}
```

## Códigos atuais

| Código | Significado |
|---|---|
| `api_key_invalid` | Header `X-API-Key` ausente ou inválido. |
| `api_key_not_configured` | `HORUS_API_KEY` não está configurado no backend. |
| `asset_not_found` | Ativo não encontrado. |
| `bc_link_duplicate` | Vínculo Backup API duplicado para o mesmo cliente. |
| `bc_link_not_found` | Vínculo Backup API não encontrado. |
| `bc_server_not_found` | Servidor Backup API não encontrado. |
| `bc_unreachable` | Falha ao contatar ou processar dados da Backup API. |
| `client_not_found` | Cliente/grupo não encontrado. |
| `ipam_conflict_resolution_failed` | Falha ao aplicar resolução de conflito no phpIPAM. |
| `ipam_l2_domain_create_failed` | Falha ao criar L2 Domain no phpIPAM. |
| `ipam_sync_failed` | Falha na sincronização com phpIPAM. |
| `job_not_found` | Job assíncrono não encontrado. |
| `login_invalid` | Login operacional recusado. |
| `netbox_sync_failed` | Falha na sincronização com NetBox. |
| `netbox_vlan_group_create_failed` | Falha ao criar VLAN Group no NetBox. |
| `rate_limited` | Muitas requisições em curto período. |
| `ssh_extract_failed` | Falha na extração manual por SSH. |
| `url_blocked` | URL rejeitada pela política anti-SSRF. |
