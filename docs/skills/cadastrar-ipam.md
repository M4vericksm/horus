# skill: cadastrar IPAM (phpIPAM/NetBox) e testar conexão

O IPAM não é entidade própria: as credenciais moram no `Client` (models.py:22) —
`ip` (URL), `token_name` (App ID), `token`, `phpipam_user/pass` (opcionais, renovam
o token automaticamente antes de cada operação), `l2_domain_id`, `section_id`.
NetBox usa campos paralelos (`netbox_url/token/vlan_group_id/site_id`) e `system="netbox"`.

## Fluxo (frontend: admin_clients.html e clientes_config.html)
1. Botão testar → `POST /api/phpipam/probe` (main.py ~948): valida credenciais do
   formulário SEM persistir e retorna `l2_domains` + `sections` (populam os selects).
2. Submit → `POST /api/phpipam/test` (main.py ~657) primeiro; só salva se `ok:true`.
3. Salvar → `POST/PUT /api/clients`; segredos são criptografados (Fernet) via
   `_encrypt_payload` com `CLIENT_SECRET_FIELDS` (main.py ~141).

## Pipeline do /test e /probe (backend)
normaliza URL (prepende https:// se faltar scheme) → anti-SSRF
(`security.validate_external_url`; redes privadas liberadas com
`ALLOW_PRIVATE_TARGETS`, default on) → se user+pass: renova token via
`POST {base}/api/{app_id}/user/` Basic auth → `GET .../sections/` timeout 8s.
Resposta sempre HTTP 200 com `{ok, message, ssl_error, auth_error}` — erro é dado.

## Máscara de segredos
- Respostas da API NUNCA trazem segredos: campos não-vazios viram `"********"`
  (`SECRET_MASK`/`_mask_attrs` em main.py).
- PUT/POST com o valor `"********"` = "não alterado": `_strip_masked` descarta o
  campo e o valor do banco é mantido. Valor vazio/null limpa; valor novo substitui.
- Frontend: token mascarado pula o pré-teste do submit e bloqueia o probe manual
  (toast pede para reinserir); para popular selects usa os endpoints com credenciais
  salvas (`/api/clients/{id}/remote-l2-domains|remote-sections|remote-vlan-groups|remote-sites`).
- Testes do contrato: `back/tests/test_secret_masking.py`.

## Em uso contínuo
Sync/remote-* descriptografam `client.token` no backend (`decrypt_secret`) e renovam
via user/pass se cadastrados — cadastrar user+pass torna o sync resiliente à
expiração do token do phpIPAM.
