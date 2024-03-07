package manifest

import (
	"encoding/json"
	"errors"
	"log"
)

const (
	ErrInvalidJson = Error("manifest json invalid")
	ErrUnmarshal   = Error("manifest unmarshal")
)

// Valid validates a manifest.json
// well-formed JSON
// validate against spec version
// validate all values in manifest
// check integrity of signatures, JWT
// validate URLs can be found
func Valid(m []byte) error {
	if !json.Valid(m) {
		return ErrInvalidJson
	}
	var manifest Object
	err := json.Unmarshal(m, &manifest)
	if err != nil {
		return errors.Join(ErrUnmarshal, err)
	}
	log.Println(manifest)
	return nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
