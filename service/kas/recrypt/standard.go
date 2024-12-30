package recrypt

import "fmt"

// Implementation of the recrypt CryptoProvider interface using standard go crypto primitives.
type Standard struct {
	currentKIDs map[Algorithm][]KeyIdentifier
	legacyKIDs  map[Algorithm][]KeyIdentifier
}

func NewStandard() *Standard {
	return &Standard{
		currentKIDs: map[Algorithm][]KeyIdentifier{},
		legacyKIDs:  map[Algorithm][]KeyIdentifier{},
	}
}

func (s *Standard) CurrentKID(alg Algorithm) ([]KeyIdentifier, error) {
	if kid, ok := s.currentKIDs[alg]; !ok {
		return nil, fmt.Errorf("No current KIDs for algorithm %s", alg)
	} else {
		return kid, nil
	}
}

func (s *Standard) LegacyKIDs(a Algorithm) ([]KeyIdentifier, error) {
	if kid, ok := s.legacyKIDs[a]; !ok {
		return nil, fmt.Errorf("No legacy KIDs for algorithm %s", a)
	} else {
		return kid, nil
	}
}

func (s *Standard) PublicKey(a Algorithm, k KeyIdentifier, f KeyFormat) (string, error) {
	return "", fmt.Errorf("Not implemented")
}

func (s *Standard) Unwrap(k KeyIdentifier, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (s *Standard) Derive(k KeyIdentifier, ephemeralPublicKeyBytes []byte) ([]byte, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (s *Standard) Close() {
	// Nothing to do
}

func (s *Standard) GenerateKey(a Algorithm, id KeyIdentifier) (KeyIdentifier, error) {
	return "", fmt.Errorf("Not implemented")
}

func (s Standard) List() ([]KeyDetails, error) {
	return nil, fmt.Errorf("Not implemented")
}
