#!/bin/sh
# Fresh-install hook: create the non-superuser application role.
#
# Runs inside the Postgres init sequence, after 01-schema.sql, so the grants —
# which are derived from the catalog at execution time — see the whole schema.
#
# The SQL it runs lives at /opt/orrery, NOT in /docker-entrypoint-initdb.d. The
# Postgres entrypoint executes every *.sql in that directory in filename order,
# and "0006_app_role.sql" sorts before "01-schema.sql" — so a copy placed there
# runs against an empty database, grants nothing, and is then run again by this
# hook. Keeping it outside means it executes once, after the schema.
#
# It runs the SAME file an operator applies to an existing database
# (infra/migrations/0006_app_role.sql) rather than a second copy of the SQL. Two
# copies of a grant list drift, and the one that drifts is the one nobody runs.
#
# APP_DB_PASSWORD is required. Without it the role would be created with no
# password and the application could not connect, which is a failure worth
# having at first boot rather than at first request.
set -eu

if [ -z "${APP_DB_PASSWORD:-}" ]; then
    echo "03-app-role: APP_DB_PASSWORD is not set." >&2
    echo "03-app-role: the application role would be created unable to log in." >&2
    exit 1
fi

PGOPTIONS="-c orrery.app_password=${APP_DB_PASSWORD}" \
    psql -v ON_ERROR_STOP=1 \
         --username "${POSTGRES_USER:-postgres}" \
         --dbname "${POSTGRES_DB:-orrery}" \
         -f /opt/orrery/0006_app_role.sql
