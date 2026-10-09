#!/bin/sh
# Lista usuarios da tabela users do Horus. Rodar como ROOT.
set -e
PGU=$(docker exec horus_db printenv POSTGRES_USER)
PGD=$(docker exec horus_db printenv POSTGRES_DB)
docker exec horus_db psql -U "$PGU" -d "$PGD" -tAc "SELECT username FROM users ORDER BY username;"
