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
		1: "Handling",
		2: "Base",
	}
	assertionTypeValue = map[string]uint8{
		"Handling": 1,
		"Base":     2,
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
	Explicit
)

var (
	scopeName = map[uint8]string{
		1: "TDO",
		2: "PAYL",
		3: "EXPLICIT",
	}
	scopeValue = map[string]uint8{
		"TDO":      1,
		"PAYL":     2,
		"EXPLICIT": 3,
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
		1: "encrypted",
		2: "unencrypted",
	}
	appliesToStateValue = map[string]uint8{
		"encrypted":   1,
		"unencrypted": 2,
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

// Schema - Custom type to hold value for the assertion ranging from 0-1
type Schema uint

const (
	JSON Schema = iota + 1
	XML
	Text
)

var (
	schemaName = map[uint8]string{
		1: "urn:nato:stanag:5636:A:1:elements:json",
		2: "XML",
		3: "Text",
	}
	schemaValue = map[string]uint8{
		"urn:nato:stanag:5636:A:1:elements:json": 1,
		"XML":                                    2,
		"Text":                                   3,
	}
)

func (s Schema) String() string {
	return schemaName[uint8(s)]
}

func ParseSchema(s string) (Schema, error) {
	s = strings.TrimSpace(s)
	value, ok := schemaValue[s]
	if !ok {
		return Schema(0), fmt.Errorf("%q is not a valid sechma", s)
	}
	return Schema(value), nil
}

func (s Schema) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Schema) UnmarshalJSON(data []byte) error {
	var schema string
	err := json.Unmarshal(data, &schema)
	if err != nil {
		return err
	}
	if *s, err = ParseSchema(schema); err != nil {
		return err
	}
	return nil
}

// StatementFormat - Custom type to hold value for the assertion ranging from 0-1
type StatementFormat uint

const (
	ReferenceStatement StatementFormat = iota + 1
	StructuredStatement
	StringStatement
	Base64BinaryStatement
	XMLBase64
	HandlingStatement
	StringType
)

var (
	statementFormatName = map[uint8]string{
		1: "ReferenceStatement",
		2: "StructuredStatement",
		3: "StringStatement",
		4: "Base64BinaryStatement",
		5: "XMLBase64",
		6: "HandlingStatement",
		7: "StringType",
	}
	statementFormatValue = map[string]uint8{
		"ReferenceStatement":    1,
		"StructuredStatement":   2,
		"StringStatement":       3,
		"Base64BinaryStatement": 4,
		"XMLBase64":             5,
		"HandlingStatement":     6,
		"StringType":            7,
	}
)

func (s StatementFormat) String() string {
	return statementFormatName[uint8(s)]
}

func ParseStatementFormat(s string) (StatementFormat, error) {
	s = strings.TrimSpace(s)
	value, ok := statementFormatValue[s]
	if !ok {
		return StatementFormat(0), fmt.Errorf("%q is not a valid sechma", s)
	}
	return StatementFormat(value), nil
}

func (s StatementFormat) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *StatementFormat) UnmarshalJSON(data []byte) error {
	var statementFormat string
	err := json.Unmarshal(data, &statementFormat)
	if err != nil {
		return err
	}
	if *s, err = ParseStatementFormat(statementFormat); err != nil {
		return err
	}
	return nil
}

// BindingMethod -  Custom type to hold value for the binding method from 0
type BindingMethod uint

const (
	JWT BindingMethod = iota + 1
)

var (
	BindingMethodName = map[uint8]string{
		1: "jwt",
	}
	BindingMethodValue = map[string]uint8{
		"jwt": 1,
	}
)

func (b BindingMethod) String() string {
	return BindingMethodName[uint8(b)]
}

func ParseBindingMethod(b string) (BindingMethod, error) {
	b = strings.TrimSpace(strings.ToLower(b))
	value, ok := BindingMethodValue[b]
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
