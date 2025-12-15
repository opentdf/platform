#!/bin/bash
set -e

echo "Setting up replication user..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'replicator') THEN
            CREATE ROLE replicator WITH REPLICATION PASSWORD 'replicator_password' LOGIN;
        END IF;
    END
    \$\$;
    GRANT CONNECT ON DATABASE $POSTGRES_DB TO replicator;
EOSQL

# Allow replication from same Docker network using 'samenet' keyword
# This automatically matches any address in subnets the server is connected to
echo "host replication replicator samenet md5" >> "${PGDATA}/pg_hba.conf"
echo "Replication user configured"
