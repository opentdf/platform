package sdk

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AssertionType - Custom type to hold value for the assertion ranging from 0-1
type AssertionType uint

const (
	HandlingAssertion AssertionType = iota + 1
	BaseAssertion
)

var (
	assertionTypeName = map[uint8]string{
		uint8(HandlingAssertion): "handling",
		uint8(BaseAssertion):     "other",
	}
	assertionTypeValue = map[string]uint8{
		"handling": uint8(HandlingAssertion),
		"other":    uint8(BaseAssertion),
	}
)

func (a AssertionType) String() string {
	return assertionTypeName[uint8(a)]
}

func ParseAssertionType(a string) (AssertionType, error) {
	a = strings.TrimSpace(a)
	value, ok := assertionTypeValue[a]
	if !ok {
		return AssertionType(0), fmt.Errorf("%q is not a valid assertion type", a)
	}
	return AssertionType(value), nil
}

func (a AssertionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

func (a *AssertionType) UnmarshalJSON(data []byte) error {
	var assertionType string
	err := json.Unmarshal(data, &assertionType)
	if err != nil {
		return err
	}
	if *a, err = ParseAssertionType(assertionType); err != nil {
		return err
	}
	return nil
}

// Scope - Custom type to hold value for the assertion ranging from 0-1
type Scope uint

const (
	TrustedDataObj Scope = iota + 1
	Paylaod
)

var (
	scopeName = map[uint8]string{
		uint8(TrustedDataObj): "tdo",
		uint8(Paylaod):        "payload",
	}
	scopeValue = map[string]uint8{
		"tdo":     uint8(TrustedDataObj),
		"payload": uint8(Paylaod),
	}
)

func (s Scope) String() string {
	return scopeName[uint8(s)]
}

func ParseScope(s string) (Scope, error) {
	s = strings.TrimSpace(s)
	value, ok := scopeValue[s]
	if !ok {
		return Scope(0), fmt.Errorf("%q is not a valid sechma", s)
	}
	return Scope(value), nil
}

func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Scope) UnmarshalJSON(data []byte) error {
	var scope string
	err := json.Unmarshal(data, &scope)
	if err != nil {
		return err
	}
	if *s, err = ParseScope(scope); err != nil {
		return err
	}
	return nil
}

// AppliesToState - Custom type to hold value for the assertion ranging from 0-1
type AppliesToState uint

const (
	Encrypted AppliesToState = iota + 1
	Unencrypted
)

var (
	appliesToStateName = map[uint8]string{
		uint8(Encrypted):   "encrypted",
		uint8(Unencrypted): "unencrypted",
	}
	appliesToStateValue = map[string]uint8{
		"encrypted":   uint8(Encrypted),
		"unencrypted": uint8(Unencrypted),
	}
)

func (a AppliesToState) String() string {
	return appliesToStateName[uint8(a)]
}

func ParseAppliesToState(a string) (AppliesToState, error) {
	a = strings.TrimSpace(strings.ToLower(a))
	value, ok := appliesToStateValue[a]
	if !ok {
		return AppliesToState(0), fmt.Errorf("%q is not a valid applies to state", a)
	}
	return AppliesToState(value), nil
}

func (a AppliesToState) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

func (a *AppliesToState) UnmarshalJSON(data []byte) error {
	var appliesToState string
	err := json.Unmarshal(data, &appliesToState)
	if err != nil {
		return err
	}
	if *a, err = ParseAppliesToState(appliesToState); err != nil {
		return err
	}
	return nil
}

// BindingMethod -  Custom type to hold value for the binding method from 0
type BindingMethod uint

const (
	JWS BindingMethod = iota + 1
)

var (
	bindingMethodName = map[uint8]string{
		1: "jws",
	}
	bindingMethodValue = map[string]uint8{
		"jws": 1,
	}
)

func (b BindingMethod) String() string {
	return bindingMethodName[uint8(b)]
}

func ParseBindingMethod(b string) (BindingMethod, error) {
	b = strings.TrimSpace(strings.ToLower(b))
	value, ok := bindingMethodValue[b]
	if !ok {
		return BindingMethod(0), fmt.Errorf("%q is not a valid sechma", b)
	}
	return BindingMethod(value), nil
}

func (b BindingMethod) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

func (b *BindingMethod) UnmarshalJSON(data []byte) error {
	var bindingMethod string
	err := json.Unmarshal(data, &bindingMethod)
	if err != nil {
		return err
	}
	if *b, err = ParseBindingMethod(bindingMethod); err != nil {
		return err
	}
	return nil
}
