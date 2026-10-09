#!/bin/sh
# Lista usuarios da tabela users do NetworkAtlas. Rodar como ROOT.
set -e
PGU=$(docker exec networkatlas_db printenv POSTGRES_USER)
PGD=$(docker exec networkatlas_db printenv POSTGRES_DB)
docker exec networkatlas_db psql -U "$PGU" -d "$PGD" -tAc "SELECT username FROM users ORDER BY username;"
