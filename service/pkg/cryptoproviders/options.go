package cryptoproviders

import (
	"crypto"
	"encoding/hex"
	"fmt"
)

type config struct {
	KEK          []byte
	Hash         crypto.Hash
	EphemeralKey []byte
	Salt         []byte
}

type Options func(*config) error

func WithWrappingKey(kek string, isHexEncoded bool) Options {
	return func(c *config) error {
		if len(kek) == 0 {
			return fmt.Errorf("kek must not be empty")
		}
		if isHexEncoded {
			k, err := hex.DecodeString(kek)
			if err != nil {
				return fmt.Errorf("failed to decode kek from hex: %w", err)
			}
			c.KEK = k
		} else {
			c.KEK = []byte(kek)
		}
		return nil
	}
}

func WithHash(h crypto.Hash) Options {
	return func(c *config) error {
		if !h.Available() {
			return fmt.Errorf("hash %s is not available", h.String())
		}
		c.Hash = h
		return nil
	}
}

func WithEphemeralKey(key []byte) Options {
	return func(c *config) error {
		if len(key) == 0 {
			return fmt.Errorf("ephemeral key must not be empty")
		}
		c.EphemeralKey = key
		return nil
	}
}

func WithSalt(salt []byte) Options {
	return func(c *config) error {
		c.Salt = salt
		return nil
	}
}
