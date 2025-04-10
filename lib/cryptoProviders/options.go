package cryptoProviders

import "crypto"

type baseConfig struct {
	kek []byte
}

type rsaConfig struct {
	baseConfig
	hash crypto.Hash
}

type RSAOptions func(*rsaConfig) error

func WithRSAHash(h crypto.Hash) RSAOptions {
	return func(c *rsaConfig) error {
		c.hash = h
		return nil
	}
}

func WithRSAKeK(kek []byte) RSAOptions {
	return func(c *rsaConfig) error {
		c.kek = kek
		return nil
	}
}

type ecConfig struct {
	baseConfig
}

type ECOptions func(*ecConfig) error

func WithECKeK(kek []byte) ECOptions {
	return func(c *ecConfig) error {
		c.kek = kek
		return nil
	}
}
