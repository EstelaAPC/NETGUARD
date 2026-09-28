#!/bin/sh
set -eu

PGHOST="${PGHOST:-db}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-netguard}"
PGDATABASE="${PGDATABASE:-netguard}"
PGPASSWORD="${PGPASSWORD:-netguard}"
SQL_DIR="${SQL_DIR:-/sql}"

export PGPASSWORD

until pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" >/dev/null 2>&1; do
  sleep 2
done

psql_cmd() {
  psql \
    -v ON_ERROR_STOP=1 \
    -h "$PGHOST" \
    -p "$PGPORT" \
    -U "$PGUSER" \
    -d "$PGDATABASE" \
    "$@"
}

psql_cmd -c "
create table if not exists schema_migrations (
  version text primary key,
  description text not null,
  applied_at timestamptz not null default now()
);
"

set -- "$SQL_DIR"/*.sql

if [ ! -e "$1" ]; then
  echo "Nenhum arquivo SQL encontrado em $SQL_DIR"
  exit 0
fi

for sql_file in "$@"; do
  [ -f "$sql_file" ] || continue

  filename="$(basename "$sql_file")"
  version="${filename%.sql}"

  case "$version" in
    *[!A-Za-z0-9_.-]*)
      echo "Nome de migracao invalido: $version" >&2
      exit 1
      ;;
  esac

  if [ "$version" = "000_schema_migrations" ]; then
    echo "Garantindo controle de migracoes com $sql_file"
    psql_cmd -f "$sql_file"
    continue
  fi

  applied="$(psql_cmd -tAc "select 1 from schema_migrations where version = '$version' limit 1")"
  applied="$(printf '%s' "$applied" | tr -d '[:space:]')"

  if [ "$applied" = "1" ]; then
    echo "Ignorando $sql_file: migracao $version ja aplicada"
    continue
  fi

  echo "Aplicando $sql_file"
  psql_cmd -f "$sql_file"

  recorded="$(psql_cmd -tAc "select 1 from schema_migrations where version = '$version' limit 1")"
  recorded="$(printf '%s' "$recorded" | tr -d '[:space:]')"

  if [ "$recorded" != "1" ]; then
    echo "Registrando migracao $version em schema_migrations"
    psql_cmd \
      -c "insert into schema_migrations (version, description) values ('$version', 'Migracao aplicada por apply-loop-risk.sh') on conflict (version) do nothing"
  fi
done

echo "Migracoes concluidas com sucesso"
