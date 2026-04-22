#!/usr/bin/env bash

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	cat <<'EOF'
Populate legacy obligation triggers directly in the database so
`otdfctl migrate namespaced-policy --scope obligation-triggers` can discover them.

This script intentionally inserts triggers against a global action
(`actions.namespace_id IS NULL`). Do not use the policy API for this purpose,
because API-created triggers will resolve namespace-scoped actions and will not
be treated as legacy migration candidates.

Required:
  Either DATABASE_URL or the standard OPENTDF_DB_* connection env vars

Connection env vars:
  DATABASE_URL        PostgreSQL connection string used by psql
  OPENTDF_DB_HOST     PostgreSQL host (default: localhost)
  OPENTDF_DB_PORT     PostgreSQL port (default: 5432)
  OPENTDF_DB_USER     PostgreSQL user (default: postgres)
  OPENTDF_DB_PASSWORD PostgreSQL password (default: changeme)
  OPENTDF_DB_DATABASE PostgreSQL database (default: opentdf)
  OPENTDF_DB_SSLMODE  PostgreSQL sslmode passed via PGSSLMODE

Optional:
  ACTION_NAME    Global action name to bind to each trigger (default: read)
  CLIENT_ID      Optional client_id for scoped triggers
  NAMESPACE_ID   Restrict population to a single namespace id
  NAMESPACE_FQN  Restrict population to a single namespace fqn
  OBLIGATION_NAME  Obligation definition name to seed/reuse
                   (default: legacy-migration-obligation)
  OBLIGATION_VALUE Obligation value to seed/reuse
                   (default: legacy-migration-obligation-value)

Behavior:
  Seeds one obligation definition and one value per eligible namespace, using
  the first active attribute value found in that namespace for the trigger.
  Existing matching definitions, values, and triggers are reused/skipped.
EOF
	exit 0
fi

ACTION_NAME="${ACTION_NAME:-read}"
CLIENT_ID="${CLIENT_ID:-}"
NAMESPACE_ID="${NAMESPACE_ID:-}"
NAMESPACE_FQN="${NAMESPACE_FQN:-}"
OBLIGATION_NAME="${OBLIGATION_NAME:-legacy-migration-obligation}"
OBLIGATION_VALUE="${OBLIGATION_VALUE:-legacy-migration-obligation-value}"
DATABASE_URL="${DATABASE_URL:-}"

psql_args=()
psql_env=()

if [[ -n "${DATABASE_URL}" ]]; then
	psql_args+=("${DATABASE_URL}")
else
	psql_args+=(
		-h "${OPENTDF_DB_HOST:-localhost}"
		-p "${OPENTDF_DB_PORT:-5432}"
		-U "${OPENTDF_DB_USER:-postgres}"
		-d "${OPENTDF_DB_DATABASE:-opentdf}"
	)
	psql_env+=(
		"PGPASSWORD=${OPENTDF_DB_PASSWORD:-changeme}"
		"PGSSLMODE=${OPENTDF_DB_SSLMODE:-prefer}"
	)
fi

env "${psql_env[@]}" psql \
	"${psql_args[@]}" \
	-X \
	-v ON_ERROR_STOP=1 \
	-v action_name="${ACTION_NAME}" \
	-v client_id="${CLIENT_ID}" \
	-v namespace_id="${NAMESPACE_ID}" \
	-v namespace_fqn="${NAMESPACE_FQN}" \
	-v obligation_name="${OBLIGATION_NAME}" \
	-v obligation_value="${OBLIGATION_VALUE}" <<'SQL'
SET search_path TO "opentdf_policy", public;

SELECT CASE
	WHEN EXISTS (
		SELECT 1
		FROM actions
		WHERE namespace_id IS NULL
		  AND name = :'action_name'
	) THEN 1
	ELSE 0
END AS action_exists \gset

\if :action_exists
\else
\echo global action ":action_name" was not found; populate or choose a different ACTION_NAME
\quit 1
\endif

WITH selected_action AS (
	SELECT id, name
	FROM actions
	WHERE namespace_id IS NULL
	  AND name = :'action_name'
	ORDER BY created_at ASC, id ASC
	LIMIT 1
),
target_namespaces AS (
	SELECT
		ns.id AS namespace_id,
		av.id AS attribute_value_id
	FROM attribute_namespaces ns
	LEFT JOIN attribute_fqns ns_fqn
	  ON ns_fqn.namespace_id = ns.id
	 AND ns_fqn.attribute_id IS NULL
	 AND ns_fqn.value_id IS NULL
	JOIN attribute_definitions ad
	  ON ad.namespace_id = ns.id
	 AND ad.active = TRUE
	JOIN attribute_values av
	  ON av.attribute_definition_id = ad.id
	 AND av.active = TRUE
	WHERE (NULLIF(:'namespace_id', '') IS NULL OR ns.id = NULLIF(:'namespace_id', '')::uuid)
	  AND (NULLIF(:'namespace_fqn', '') IS NULL OR ns_fqn.fqn = NULLIF(:'namespace_fqn', ''))
),
ranked_namespaces AS (
	SELECT
		namespace_id,
		attribute_value_id,
		ROW_NUMBER() OVER (
			PARTITION BY namespace_id
			ORDER BY attribute_value_id ASC
		) AS namespace_rank
	FROM target_namespaces
),
chosen_namespaces AS (
	SELECT namespace_id, attribute_value_id
	FROM ranked_namespaces
	WHERE namespace_rank = 1
),
existing_definitions AS (
	SELECT od.id, od.namespace_id
	FROM obligation_definitions od
	JOIN chosen_namespaces cn
	  ON cn.namespace_id = od.namespace_id
	WHERE od.name = :'obligation_name'
),
inserted_definitions AS (
	INSERT INTO obligation_definitions (
		namespace_id,
		name,
		metadata
	)
	SELECT
		cn.namespace_id,
		:'obligation_name',
		jsonb_build_object(
			'labels',
			jsonb_build_object(
				'seeded_by', 'populate-legacy-obligation-triggers.sh'
			)
		)
	FROM chosen_namespaces cn
	LEFT JOIN existing_definitions ed
	  ON ed.namespace_id = cn.namespace_id
	WHERE ed.id IS NULL
	RETURNING id, namespace_id
),
all_definitions AS (
	SELECT id, namespace_id
	FROM existing_definitions
	UNION ALL
	SELECT id, namespace_id
	FROM inserted_definitions
),
existing_values AS (
	SELECT
		ov.id,
		ad.namespace_id
	FROM obligation_values_standard ov
	JOIN all_definitions ad
	  ON ad.id = ov.obligation_definition_id
	WHERE ov.value = :'obligation_value'
),
inserted_values AS (
	INSERT INTO obligation_values_standard (
		obligation_definition_id,
		value,
		metadata
	)
	SELECT
		ad.id,
		:'obligation_value',
		jsonb_build_object(
			'labels',
			jsonb_build_object(
				'seeded_by', 'populate-legacy-obligation-triggers.sh'
			)
		)
	FROM all_definitions ad
	LEFT JOIN existing_values ev
	  ON ev.namespace_id = ad.namespace_id
	WHERE ev.id IS NULL
	RETURNING id, obligation_definition_id
),
all_values AS (
	SELECT id, namespace_id
	FROM existing_values
	UNION ALL
	SELECT
		iv.id,
		ad.namespace_id
	FROM inserted_values iv
	JOIN all_definitions ad
	  ON ad.id = iv.obligation_definition_id
),
inserted AS (
	INSERT INTO obligation_triggers (
		obligation_value_id,
		action_id,
		attribute_value_id,
		metadata,
		client_id
	)
	SELECT
		av.id,
		sa.id,
		cn.attribute_value_id,
		jsonb_build_object(
			'labels',
			jsonb_build_object(
				'seeded_by', 'populate-legacy-obligation-triggers.sh'
			)
		),
		NULLIF(:'client_id', '')
	FROM all_values av
	JOIN chosen_namespaces cn
	  ON cn.namespace_id = av.namespace_id
	CROSS JOIN selected_action sa
	LEFT JOIN obligation_triggers ot
	  ON ot.obligation_value_id = av.id
	 AND ot.action_id = sa.id
	 AND ot.attribute_value_id = cn.attribute_value_id
	 AND (
		(NULLIF(:'client_id', '') IS NULL AND ot.client_id IS NULL)
		OR ot.client_id = NULLIF(:'client_id', '')
	 )
	WHERE ot.id IS NULL
	RETURNING id
)
SELECT
	(SELECT name FROM selected_action) AS action_name,
	(SELECT COUNT(*) FROM chosen_namespaces) AS namespace_count,
	(SELECT COUNT(*) FROM inserted_definitions) AS obligation_count,
	(SELECT COUNT(*) FROM inserted_values) AS obligation_value_count,
	(SELECT COUNT(*) FROM inserted) AS trigger_count;
SQL
