// Experimental: This package is EXPERIMENTAL and may change or be removed at any time
// Package keysplit provides key splitting functionality for TDF (Trusted Data Format) encryption.
//
// This package extracts the key splitting logic from the main SDK granter functionality,
// providing a clean API for:
//   - Analyzing policy attributes and their associated KAS (Key Access Server) grants
//   - Creating cryptographic key splits based on attribute rules (allOf, anyOf, hierarchy)
//   - Building Key Access Objects (KAOs) that can be embedded in TDF manifests
//
// The package implements XOR-based secret sharing for key splitting, where the original
// Data Encryption Key (DEK) can be reconstructed by XORing all the split keys together.
//
// # Attribute Resolution Hierarchy
//
// The package respects the attribute grant hierarchy:
//  1. Value-level grants (most specific)
//  2. Definition-level grants
//  3. Namespace-level grants (least specific)
//
// # Attribute Rules
//
// Different attribute rule types determine how splits are created:
//   - allOf: Each value gets its own split (all must be satisfied)
//   - anyOf: All values share the same split (any can satisfy)
//   - hierarchy: Ordered evaluation with precedence
//
// # Basic Usage
//
//	splitter := keysplit.NewXORSplitter(
//		keysplit.WithDefaultKAS("https://kas.example.com"),
//	)
//
//	// Generate splits from policy attributes and DEK
//	result, err := splitter.GenerateSplits(ctx, policyValues, dek)
//	if err != nil {
//		return err
//	}
//
//	// Build Key Access Objects for TDF manifest
//	kaos, err := splitter.BuildKeyAccessObjects(result, policyBytes, metadata)
//	if err != nil {
//		return err
//	}
package keysplit
