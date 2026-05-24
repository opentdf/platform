// Package local implements the Access PDP described in the entitlement-vs-access
// taxonomy: it answers the single question "can this subject perform this
// action on this resource right now?" given a materialized grant set.
//
// The package is deliberately minimal: no policy lookup, no SDK dependency, no
// remote calls. The grant set is produced once by the Entitlement PDP (the
// authorization service's token-exchange endpoint) and embedded in the access
// token. Resource servers (KAS, and eventually language SDKs) import this
// package, parse the token, and run Decide on every access — a map lookup,
// sub-microsecond, deterministic.
//
// The Entitlement PDP lives in service/authorization/v2 and is the only
// component that needs to evaluate policy. Everything downstream is local.
package local

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// GrantType identifies the shape of a Grant. Different types carry different
// data; today only attribute grants are emitted but the registered-resource
// and obligation types are the obvious next additions.
const (
	GrantTypeAttribute = "opentdf_attribute"
)

// Grant is one entry in an access token's authorization_details claim. The
// shape is RFC 9396 compatible — actions/locations are the standard RFC field
// names — with opentdf-specific extensions for the obligation hooks the
// Obligation PDP attached at materialization time.
//
// A Grant entitles the subject to perform every Action on every Location,
// subject to fulfilling the listed Obligations. The local PDP treats actions
// and locations as a Cartesian set, so emitting one Grant covering N actions
// across M locations is equivalent to N*M single-cell grants. If obligations
// differ per (action, location), emit separate grants instead of one cross-
// product.
type Grant struct {
	Type        string   `json:"type"`
	Actions     []string `json:"actions"`
	Locations   []string `json:"locations"`
	Obligations []string `json:"obligations,omitempty"`
}

// Validate reports the structural issues that would make a Grant unsafe to
// trust. Used by both the issuer (before signing) and consumers (after
// parsing) so the wire format invariants are checked from both sides.
func (g Grant) Validate() error {
	if g.Type == "" {
		return errors.New("grant: type is required")
	}
	if len(g.Actions) == 0 {
		return errors.New("grant: at least one action is required")
	}
	if len(g.Locations) == 0 {
		return errors.New("grant: at least one location is required")
	}
	for _, a := range g.Actions {
		if a == "" {
			return errors.New("grant: action name must not be empty")
		}
	}
	for _, l := range g.Locations {
		if l == "" {
			return errors.New("grant: location must not be empty")
		}
	}
	return nil
}

// Decision is the local PDP's output: a boolean plus the obligations the PEP
// must fulfill before completing the action.
type Decision struct {
	Allow               bool
	RequiredObligations []string
}

// Decide answers the one-resource access question against the supplied grant
// set. Comparison is case-insensitive for both action name and location FQN
// (matches the rest of the platform's FQN handling).
//
// Obligations are de-duplicated across overlapping grants so a PEP that
// fulfils each fqn exactly once satisfies the policy.
func Decide(grants []Grant, action, resourceFQN string) Decision {
	if action == "" || resourceFQN == "" {
		return Decision{}
	}
	wantedAction := strings.ToLower(action)
	wantedResource := strings.ToLower(resourceFQN)
	obligations := newOrderedSet()
	allow := false
	for _, g := range grants {
		if g.Type != GrantTypeAttribute {
			continue
		}
		if !containsFold(g.Actions, wantedAction) {
			continue
		}
		if !containsFold(g.Locations, wantedResource) {
			continue
		}
		allow = true
		for _, ob := range g.Obligations {
			obligations.add(ob)
		}
	}
	return Decision{Allow: allow, RequiredObligations: obligations.values()}
}

// DecideAny is a convenience for the common KAS shape: a TDF carries multiple
// attribute value FQNs and the policy permits access only if the subject is
// entitled to every one. Returns true when each resource is independently
// permitted; obligations are the union across resources.
func DecideAny(grants []Grant, action string, resources []string) Decision {
	if len(resources) == 0 {
		return Decision{}
	}
	obligations := newOrderedSet()
	for _, r := range resources {
		d := Decide(grants, action, r)
		if !d.Allow {
			return Decision{}
		}
		for _, ob := range d.RequiredObligations {
			obligations.add(ob)
		}
	}
	return Decision{Allow: true, RequiredObligations: obligations.values()}
}

// MarshalGrants serializes grants into the JSON form expected as the
// authorization_details claim of an access token.
func MarshalGrants(grants []Grant) ([]byte, error) {
	return json.Marshal(grants)
}

// UnmarshalGrants parses the authorization_details claim. Validation is
// performed eagerly so a malformed token surfaces an error before any
// decision is rendered.
func UnmarshalGrants(raw []byte) ([]Grant, error) {
	var grants []Grant
	if err := json.Unmarshal(raw, &grants); err != nil {
		return nil, fmt.Errorf("local: unmarshal grants: %w", err)
	}
	for i, g := range grants {
		if err := g.Validate(); err != nil {
			return nil, fmt.Errorf("local: grant %d: %w", i, err)
		}
	}
	return grants, nil
}

func containsFold(haystack []string, needleLower string) bool {
	for _, v := range haystack {
		if strings.EqualFold(v, needleLower) {
			return true
		}
	}
	return false
}

// orderedSet preserves insertion order so obligations are reported in the
// order they were materialized — useful for deterministic test assertions
// and human-readable audit logs.
type orderedSet struct {
	order []string
	seen  map[string]struct{}
}

func newOrderedSet() *orderedSet {
	return &orderedSet{seen: map[string]struct{}{}}
}

func (s *orderedSet) add(v string) {
	if v == "" {
		return
	}
	if _, ok := s.seen[v]; ok {
		return
	}
	s.seen[v] = struct{}{}
	s.order = append(s.order, v)
}

func (s *orderedSet) values() []string {
	if len(s.order) == 0 {
		return nil
	}
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}
