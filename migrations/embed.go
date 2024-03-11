package migrations

import "embed"

//go:embed *.sql
var MigrationsFS embed.FS
