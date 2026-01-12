// Package db contains database migrations for the authz service.
package db

import "embed"

// Migrations contains the embedded SQL migration files for the authz service.
// These migrations create and manage the casbin_rule table for v2 authorization.
//
//go:embed migrations/*.sql
var Migrations embed.FS
