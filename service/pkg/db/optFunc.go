package db

import (
	"embed"
	"strings"
)

type OptsFunc func(c Config) Config

func WithService(name string) OptsFunc {
	return func(c Config) Config {
		c.Schema = strings.Join([]string{c.Schema, name}, "_")
		return c
	}
}

func WithMigrations(fs *embed.FS) OptsFunc {
	return func(c Config) Config {
		c.MigrationsFS = fs
		return c
	}
}
