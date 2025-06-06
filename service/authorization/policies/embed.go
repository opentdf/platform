package policies

import "embed"

//go:embed entitlements/*.rego
var EntitlementsRego embed.FS
