package db

import (
	"embed"
	"strings"
)

type optsFunc func(c Config) Config

func WithService(name string) optsFunc {
	return func(c Config) Config {
		c.Schema = strings.Join([]string{c.Schema, name}, "_")
		return c
	}
}

func WithVerifyConnection() optsFunc {
	return func(c Config) Config {
		c.VerifyConnection = true
		return c
	}
}

func WithMigrations(fs *embed.FS) optsFunc {
	return func(c Config) Config {
		c.MigrationsFS = fs
		return c
	}
}
