#!/bin/sh
# Reseta a senha de TODOS os usuarios da tabela users do Horus. Rodar como ROOT.
# Uso: sh reset_all.sh '<nova_senha>'
# Gera hash PBKDF2-SHA256 (260000 iter, salt unico por usuario) no esquema do app.
set -e
P="$1"
[ -n "$P" ] || { echo "Uso: sh reset_all.sh '<nova_senha>'"; exit 1; }

PGU=$(docker exec horus_db printenv POSTGRES_USER)
PGD=$(docker exec horus_db printenv POSTGRES_DB)

USERS=$(docker exec horus_db psql -U "$PGU" -d "$PGD" -tAc "SELECT username FROM users ORDER BY username;")
[ -n "$USERS" ] || { echo "ERRO: nenhum usuario encontrado"; exit 1; }

for U in $USERS; do
  HASH=$(docker exec -e PW="$P" horus_backend python -c "import os,hashlib; p=os.environ['PW']; s=os.urandom(32); k=hashlib.pbkdf2_hmac('sha256',p.encode(),s,260000); print(s.hex()+':'+k.hex())")
  [ -n "$HASH" ] || { echo "ERRO: falha ao gerar hash para '$U'"; exit 1; }
  docker exec horus_db psql -U "$PGU" -d "$PGD" -v ON_ERROR_STOP=1 -c "UPDATE users SET password_hash='$HASH' WHERE username='$U';" >/dev/null
  echo "OK: '$U' atualizado"
done
echo "CONCLUIDO: todos os usuarios com a nova senha."
