package serviceregistry

import "embed"

type DBRegister struct {
	MigrationsFS *embed.FS
}
