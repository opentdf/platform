package tdf

import "github.com/opentdf/platform/protocol/go/policy"

type IntegrityAlgorithm int

func (i IntegrityAlgorithm) String() string {
	switch i {
	case HS256:
		return "HS256"
	case GMAC:
		return "GMAC"
	default:
		return "unknown"
	}
}

const (
	HS256 = iota
	GMAC
)

type BaseConfig struct{}

type WriterConfig struct {
	BaseConfig
	integrityAlgorithm        IntegrityAlgorithm
	segmentIntegrityAlgorithm IntegrityAlgorithm
}

type ReaderConfig struct {
	BaseConfig
}

type Option[T any] func(T)

func WithIntegrityAlgorithm(algo IntegrityAlgorithm) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.integrityAlgorithm = algo
	}
}

func WithSegmentIntegrityAlgorithm(algo IntegrityAlgorithm) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.segmentIntegrityAlgorithm = algo
	}
}

type WriterFinalizeConfig struct {
	defaultKas                 *policy.SimpleKasKey
	attributes                 []*policy.Value
	assertions                 []AssertionConfig
	excludeVersionFromManifest bool
	encryptedMetadata          string
	payloadMimeType            string
}

func WithEncryptedMetadata(metadata string) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.encryptedMetadata = metadata
	}
}

func WithPayloadMimeType(mimeType string) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.payloadMimeType = mimeType
	}
}

func WithDefaultKAS(kas *policy.SimpleKasKey) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.defaultKas = kas
	}
}

func WithAttributeValues(values []*policy.Value) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.attributes = values
	}
}

func WithExcludeVersionFromManifest(exclude bool) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.excludeVersionFromManifest = exclude
	}
}

func WithAssertions(assertions ...AssertionConfig) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.assertions = assertions
	}
}
