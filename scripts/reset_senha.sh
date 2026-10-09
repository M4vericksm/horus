#!/bin/sh
# Reset de senha de um usuario do Horus. Rodar como ROOT.
# Uso: sh reset_senha.sh <username> '<nova_senha>'
#
# Gera o hash no MESMO esquema do app (PBKDF2-SHA256, 260000 iteracoes, salt:hash)
# usando o proprio container do backend, e atualiza users.password_hash.
set -e
U="$1"; P="$2"
[ -n "$U" ] && [ -n "$P" ] || { echo "Uso: sh reset_senha.sh <username> '<nova_senha>'"; exit 1; }

PGU=$(docker exec horus_db printenv POSTGRES_USER)
PGD=$(docker exec horus_db printenv POSTGRES_DB)

# Confere se o usuario existe
EXISTS=$(docker exec horus_db psql -U "$PGU" -d "$PGD" -tAc "SELECT 1 FROM users WHERE username='$U';")
[ "$EXISTS" = "1" ] || { echo "ERRO: usuario '$U' nao existe na tabela users"; exit 1; }

# Gera o hash compativel (senha vai por env, nunca interpolada no codigo)
HASH=$(docker exec -e PW="$P" horus_backend python -c "import os,hashlib; p=os.environ['PW']; s=os.urandom(32); k=hashlib.pbkdf2_hmac('sha256',p.encode(),s,260000); print(s.hex()+':'+k.hex())")
[ -n "$HASH" ] || { echo "ERRO: falha ao gerar hash"; exit 1; }

# Atualiza
docker exec horus_db psql -U "$PGU" -d "$PGD" -v ON_ERROR_STOP=1 -c "UPDATE users SET password_hash='$HASH' WHERE username='$U';"
echo "OK: senha de '$U' atualizada. Faca login em http://192.168.0.10 com '$U' e a nova senha."
