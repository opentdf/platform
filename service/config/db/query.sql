-- name: GetConfig :one
SELECT
  service,
  version,
  aliases,
  value
FROM config
-- todo: versioning will be added in future, and likely need an "active" or "current" indicator
WHERE service = $1;

-- name: CreateConfig :exec
INSERT INTO config (service, version, aliases, value)
VALUES ($1, $2, $3, $4);
