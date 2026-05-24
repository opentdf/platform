// Package filestore provides a file-backed, read-only Policy provider for use by
// the authorization endpoints. It loads attributes, namespaces, subject mappings,
// registered resources, and obligations from a YAML or JSON document at startup
// and serves them from in-memory indexes.
//
// The production runtime can therefore make entitlement and decision calls
// without contacting a Policy CRUD service or a database. Authoring of policy
// objects continues to happen on a separate server (the policy CRUD endpoints,
// driven by otdfctl) which persists to its own data store; the production
// server simply reads a snapshot of that data from the configured file.
package filestore
