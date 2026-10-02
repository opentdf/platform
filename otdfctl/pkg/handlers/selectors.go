package handlers

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	flat "github.com/opentdf/platform/lib/flattening"
)

func ParseSubjectString(subject string) (map[string]interface{}, error) {
	var value map[string]interface{}
	//nolint:errcheck // if fails to unmarshal, may be a JWT, so swallow the error
	json.Unmarshal([]byte(subject), &value)

	if value == nil {
		token, _, err := new(jwt.Parser).ParseUnverified(subject, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("failed to flatten subject [%v]: %w", subject, err)
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			value = claims
		} else {
			return nil, errors.New("failed to get claims from subject JWT token")
		}
	}

	if value == nil {
		return nil, errors.New("invalid subject context type. Must be of type: [json, jwt]")
	}
	return value, nil
}

func FlattenSubjectContext(subject string) ([]flat.Item, error) {
	value, err := ParseSubjectString(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject string into JSON or JWT [%s]: %w", subject, err)
	}

	flattened, err := flat.Flatten(value)
	if err != nil {
		return nil, fmt.Errorf("failed to flatten subject [%v]: %w", subject, err)
	}

	return flattened.Items, nil
}
