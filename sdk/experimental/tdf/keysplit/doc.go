// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

// Package keysplit is deprecated. Use [sdk.KeySplitter] instead.
//
// This package used to carry its own implementation of "ABAC attributes
// to DEK splits". That reasoning now lives in package sdk, where
// [sdk.SDK.CreateTDF] and the chunked writer share it, and what remains
// here is an adapter over [sdk.DefaultKeySplitter] kept so dependent
// code keeps compiling.
//
// The replacement:
//
//	result, err := sdk.DefaultKeySplitter().Split(ctx, sdk.SplitRequest{
//		Attributes: attributeValues,
//		DEK:        dek,
//		DefaultKAS: []*policy.SimpleKasKey{defaultKAS},
//	})
//
// [sdk.DefaultKeySplitter] is offline: every wrapping key must be
// carried by the attribute values or by the default KAS. Use
// [sdk.SDK.KeySplitter] to resolve the rest against a running platform.
//
// Most callers need neither -- [sdk.NewChunkedWriter] and
// [sdk.SDK.CreateTDF] already split keys this way, and
// [sdk.WithChunkedKeySplitter] overrides it.
//
// Splits produced through this package now follow the sdk semantics,
// which differ from what it used to decide on its own; see
// [XORSplitter.GenerateSplits] for the list.
package keysplit
