package sdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk/sdkconnect"
)

var ErrInvalid = errors.New("invalid type")

// Attribute rule types: operators!
const (
	hierarchy   = "hierarchy"
	allOf       = "allOf"
	anyOf       = "anyOf"
	unspecified = "unspecified"
	emptyTerm   = "DEFAULT"
)

// keySplitStep represents a which KAS a split with the associated ID should be shared with.
type keySplitStep struct {
	KAS, SplitID string
}

// Template for a KAS Access Object (KAO).
// It is filled in during manifest creation by splitting the key material (DEK) across each split ID,
// then wrapping each split with the KAS public key identified by the KID at each element.
type kaoTpl struct {
	KAS, SplitID string
	kid          string
	pem          string
	algorithm    ocrypto.KeyType
}

// AttributeNameFQN represents the FQN for an attribute.
type AttributeNameFQN struct {
	url, key string
}

// Lookup Table for KAS keys, indexed by ResourceLocator.
type rlKeyCache struct {
	c map[ResourceLocator]*policy.SimpleKasKey
}

func attributeURLPartsValid(parts []string) error {
	for i, part := range parts {
		if part == "" {
			return fmt.Errorf("%w: empty url path parts are not allowed", ErrInvalid)
		} else if i > 1 && // skip first two parts as they will have protocol slashes
			strings.Contains(part, "/") {
			return fmt.Errorf("%w: slash not allowed in name or values", ErrInvalid)
		}
	}
	return nil
}

func NewAttributeNameFQN(u string) (AttributeNameFQN, error) {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/([^/\s]*)$`)
	m := re.FindStringSubmatch(u)
	if len(m) < 3 || len(m[0]) == 0 {
		return AttributeNameFQN{}, fmt.Errorf("%w: attribute regex fail", ErrInvalid)
	}

	_, err := url.PathUnescape(m[2])
	if err != nil {
		return AttributeNameFQN{}, fmt.Errorf("%w: error in attribute name [%s]", ErrInvalid, m[2])
	}

	if err := attributeURLPartsValid(m); err != nil {
		return AttributeNameFQN{}, err
	}

	return AttributeNameFQN{u, strings.ToLower(u)}, nil
}

func (a AttributeNameFQN) String() string {
	return a.url
}

func (a AttributeNameFQN) Select(v string) AttributeValueFQN {
	u := fmt.Sprintf("%s/value/%s", a.url, url.PathEscape(v))
	return AttributeValueFQN{u, strings.ToLower(u)}
}

func (a AttributeNameFQN) Prefix() string {
	return a.url
}

func (a AttributeNameFQN) Authority() string {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/[^/\s]*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic(ErrInvalid)
	}
	return m[1]
}

func (a AttributeNameFQN) Name() string {
	re := regexp.MustCompile(`^https?://[\w./-]+/attr/([^/\s]*)$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic("invalid attribute")
	}
	v, err := url.PathUnescape(m[1])
	if err != nil {
		panic(ErrInvalid)
	}
	return v
}

// AttributeValueFQN is a utility type to represent an FQN for an attribute value.
type AttributeValueFQN struct {
	url, key string
}

func NewAttributeValueFQN(u string) (AttributeValueFQN, error) {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/(\S*)/value/(\S*)$`)
	m := re.FindStringSubmatch(u)
	if len(m) < 4 || len(m[0]) == 0 {
		return AttributeValueFQN{}, fmt.Errorf("%w: attribute regex fail for [%s]", ErrInvalid, u)
	}

	_, err := url.PathUnescape(m[2])
	if err != nil {
		return AttributeValueFQN{}, fmt.Errorf("%w: error in attribute name [%s]", ErrInvalid, m[2])
	}
	_, err = url.PathUnescape(m[3])
	if err != nil {
		return AttributeValueFQN{}, fmt.Errorf("%w: error in attribute value [%s]", ErrInvalid, m[3])
	}

	if err := attributeURLPartsValid(m); err != nil {
		return AttributeValueFQN{}, err
	}

	return AttributeValueFQN{u, strings.ToLower(u)}, nil
}

func (a AttributeValueFQN) String() string {
	return a.url
}

func (a AttributeValueFQN) Authority() string {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/\S*/value/\S*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic(ErrInvalid)
	}
	return m[1]
}

func (a AttributeValueFQN) Prefix() AttributeNameFQN {
	re := regexp.MustCompile(`^(https?://[\w./-]+/attr/\S*)/value/\S*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic(ErrInvalid)
	}
	p, err := NewAttributeNameFQN(m[1])
	if err != nil {
		panic(ErrInvalid)
	}
	return p
}

func (a AttributeValueFQN) Value() string {
	re := regexp.MustCompile(`^https?://[\w./-]+/attr/\S*/value/(\S*)$`)
	m := re.FindStringSubmatch(a.String())
	if m == nil {
		panic(ErrInvalid)
	}
	v, err := url.PathUnescape(m[1])
	if err != nil {
		panic(ErrInvalid)
	}
	return v
}

func (a AttributeValueFQN) Name() string {
	re := regexp.MustCompile(`^https?://[\w./-]+/attr/(\S*)/value/\S*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic("invalid attributeInstance")
	}
	v, err := url.PathUnescape(m[1])
	if err != nil {
		panic("invalid attributeInstance")
	}
	return v
}

// Structure capable of generating a split plan from a given set of data tags.
type granter struct {
	// The data attributes (tags) that this granter is responsible for.
	tags []AttributeValueFQN

	// Older map of attribute values to associated KASes. Replaced by mapTable.
	grantTable map[string]*keyAccessGrant

	// Map from attribute values to KAS and key identifier.
	mapTable map[string][]*ResourceLocator

	// The types of grants or mapped keys found.
	typ grantType

	// The key cache to store KAS keys.
	keyCache *rlKeyCache

	// Key lookup for keys without a KID.
	keyInfoFetcher KASKeyFetcher

	// Pointer to feature client
	featureClient *openfeature.Client
}

type keyAccessGrant struct {
	attr  *policy.Attribute
	kases []string
}

func (r *granter) addGrant(fqn AttributeValueFQN, kas string, attr *policy.Attribute) {
	if _, ok := r.grantTable[fqn.key]; ok {
		r.grantTable[fqn.key].kases = append(r.grantTable[fqn.key].kases, kas)
	} else {
		r.grantTable[fqn.key] = &keyAccessGrant{attr, []string{kas}}
	}
}

func (r *granter) addMappedKey(fqn AttributeValueFQN, sk *policy.SimpleKasKey) error {
	key := sk.GetPublicKey()
	if key == nil || key.GetKid() == "" || key.GetPem() == "" {
		slog.Debug("invalid cached key in policy service",
			slog.String("kas", sk.GetKasUri()),
			slog.Any("value", fqn),
		)
		return fmt.Errorf("invalid cached key in policy service associated with [%s]", fqn)
	}
	if r.mapTable == nil {
		r.mapTable = make(map[string][]*ResourceLocator)
	}
	rls := r.mapTable[fqn.key]
	if rls == nil {
		rls = make([]*ResourceLocator, 0)
		r.mapTable[fqn.key] = rls
	}

	rl, err := NewResourceLocator(sk.GetKasUri())
	if err != nil {
		slog.Debug("invalid KAS URL in policy service",
			slog.String("kas", sk.GetKasUri()),
			slog.Any("value", fqn),
			slog.Any("error", err),
		)
		return fmt.Errorf("invalid KAS URL in policy service associated with [%s]: %w", fqn, err)
	}
	rl.identifier = key.GetKid()
	slog.Debug("added mapped key",
		slog.Any("fqn", fqn),
		slog.String("kas", sk.GetKasUri()),
		slog.String("kid", key.GetKid()),
		slog.String("alg", algProto2String(policy.KasPublicKeyAlgEnum(key.GetAlgorithm()))),
	)
	rls = append(rls, rl)
	r.mapTable[fqn.key] = rls
	r.keyCache.c[*rl] = sk
	return nil
}

func convertAlgEnum2Simple(a policy.KasPublicKeyAlgEnum) policy.Algorithm {
	switch a {
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
		return policy.Algorithm_ALGORITHM_EC_P256
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1:
		return policy.Algorithm_ALGORITHM_EC_P384
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:
		return policy.Algorithm_ALGORITHM_EC_P521
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
		return policy.Algorithm_ALGORITHM_RSA_2048
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096:
		return policy.Algorithm_ALGORITHM_RSA_4096
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	default:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

// convertStringToAlgorithm converts a string algorithm representation to policy.Algorithm
func convertStringToAlgorithm(alg string) policy.Algorithm {
	switch ocrypto.KeyType(strings.ToLower(alg)) {
	case ocrypto.EC256Key:
		return policy.Algorithm_ALGORITHM_EC_P256
	case ocrypto.EC384Key:
		return policy.Algorithm_ALGORITHM_EC_P384
	case ocrypto.EC521Key:
		return policy.Algorithm_ALGORITHM_EC_P521
	case ocrypto.RSA2048Key:
		return policy.Algorithm_ALGORITHM_RSA_2048
	case RSA4096Key:
		return policy.Algorithm_ALGORITHM_RSA_4096
	default:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

type grantType int

const (
	noKeysFound grantType = iota // No keys found
	grantsFound                  // Only grants found
	mappedFound                  // Only mapped keys found
)

type grantableObject interface {
	GetGrants() []*policy.KeyAccessServer
	GetKasKeys() []*policy.SimpleKasKey
}

// addAllGrants adds all grants from a list of KASes to the granter.
// It returns an enum value indicating what types of keys were found.
func (r *granter) addAllGrants(fqn AttributeValueFQN, ag grantableObject, attr *policy.Attribute) grantType {
	result := noKeysFound

	if r.featureClient.Boolean(context.TODO(), "key_management", false, openfeature.EvaluationContext{}) {
		// Check for mapped keys
		for _, k := range ag.GetKasKeys() {
			if k == nil || k.GetKasUri() == "" {
				slog.Debug("invalid KAS key in policy service",
					slog.Any("simple_kas_key", k),
					slog.Any("value", fqn),
				)
				continue
			}
			kasURI := k.GetKasUri()
			r.typ = mappedFound
			result = r.typ
			err := r.addMappedKey(fqn, k)
			if err != nil {
				slog.Debug("failed to add mapped key",
					slog.Any("fqn", fqn),
					slog.String("kas", kasURI),
					slog.Any("error", err),
				)
			}
			if _, present := r.grantTable[fqn.key]; !present {
				r.grantTable[fqn.key] = &keyAccessGrant{attr, []string{kasURI}}
			} else {
				r.grantTable[fqn.key].kases = append(r.grantTable[fqn.key].kases, kasURI)
			}
		}

		return result
	}

	for _, g := range ag.GetGrants() {
		if g != nil && g.GetUri() != "" { //nolint:nestif // Simplify after grant removal
			kasURI := g.GetUri()
			r.typ = grantsFound
			result = grantsFound
			r.addGrant(fqn, kasURI, attr)
			if len(g.GetKasKeys()) != 0 {
				for _, k := range g.GetKasKeys() {
					err := r.addMappedKey(fqn, k)
					if err != nil {
						slog.Warn("failed to add mapped key",
							slog.Any("fqn", fqn),
							slog.String("kas", kasURI),
							slog.Any("error", err),
						)
					}
				}
				continue
			}
			ks := g.GetPublicKey().GetCached().GetKeys()
			if len(ks) == 0 {
				slog.Debug("no cached key in policy service",
					slog.String("kas", kasURI),
					slog.Any("value", fqn),
				)
				continue
			}
			for _, k := range ks {
				if k.GetKid() == "" || k.GetPem() == "" {
					slog.Debug("invalid cached key in policy service",
						slog.String("kas", kasURI),
						slog.Any("value", fqn),
						slog.Any("key", k),
					)
					continue
				}
				sk := &policy.SimpleKasKey{
					KasUri: kasURI,
					PublicKey: &policy.SimpleKasPublicKey{
						Algorithm: convertAlgEnum2Simple(k.GetAlg()),
						Pem:       k.GetPem(),
						Kid:       k.GetKid(),
					},
					KasId: g.GetId(),
				}
				err := r.addMappedKey(fqn, sk)
				if err != nil {
					slog.Warn("failed to add mapped key",
						slog.Any("fqn", fqn),
						slog.String("kas", kasURI),
						slog.Any("error", err),
					)
				}
			}
		}
	}
	if result == noKeysFound {
		if _, present := r.grantTable[fqn.key]; !present {
			r.grantTable[fqn.key] = &keyAccessGrant{attr, []string{}}
		}
	}
	return result
}

func (r granter) byAttribute(fqn AttributeValueFQN) *keyAccessGrant {
	return r.grantTable[fqn.key]
}

// Gets a list of directory of KAS grants for a list of attribute FQNs
func newGranterFromService(ctx context.Context, keyCache *kasKeyCache, as sdkconnect.AttributesServiceClient, featureClient *openfeature.Client, fqns ...AttributeValueFQN) (granter, error) {
	fqnsStr := make([]string, len(fqns))
	for i, v := range fqns {
		fqnsStr[i] = v.String()
	}

	av, err := as.GetAttributeValuesByFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqnsStr,
		WithValue: &policy.AttributeValueSelector{
			WithKeyAccessGrants: true,
		},
	})
	if err != nil {
		return granter{}, err
	}

	grants := granter{
		tags:          fqns,
		grantTable:    make(map[string]*keyAccessGrant),
		keyCache:      &rlKeyCache{c: make(map[ResourceLocator]*policy.SimpleKasKey)},
		featureClient: featureClient,
	}
	for fqnstr, pair := range av.GetFqnAttributeValues() {
		fqn, err := NewAttributeValueFQN(fqnstr)
		if err != nil {
			return grants, err
		}
		def := pair.GetAttribute()

		if def != nil {
			storeKeysToCache(def.GetGrants(), def.GetKasKeys(), keyCache, grants.keyCache)
		}
		v := pair.GetValue()
		gType := noKeysFound
		if v != nil {
			gType = grants.addAllGrants(fqn, v, def)
			storeKeysToCache(v.GetGrants(), v.GetKasKeys(), keyCache, grants.keyCache)
		}

		// If no more specific grant was found, then add the value grants
		if gType == noKeysFound && def != nil {
			gType = grants.addAllGrants(fqn, def, def)
			storeKeysToCache(def.GetGrants(), def.GetKasKeys(), keyCache, grants.keyCache)
		}
		if gType == noKeysFound && def.GetNamespace() != nil {
			grants.addAllGrants(fqn, def.GetNamespace(), def)
			storeKeysToCache(def.GetNamespace().GetGrants(), def.GetNamespace().GetKasKeys(), keyCache, grants.keyCache)
		}
	}

	return grants, nil
}

func algProto2String(e policy.KasPublicKeyAlgEnum) string {
	switch e {
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
		return string(ocrypto.EC256Key)
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1:
		return string(ocrypto.EC384Key)
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:
		return string(ocrypto.EC521Key)
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
		return string(ocrypto.RSA2048Key)
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096:
		return string(RSA4096Key)
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED:
		return ""
	}
	return ""
}

func algProto2OcryptoKeyType(e policy.Algorithm) ocrypto.KeyType {
	switch e {
	case policy.Algorithm_ALGORITHM_EC_P256:
		return ocrypto.EC256Key
	case policy.Algorithm_ALGORITHM_EC_P384:
		return ocrypto.EC384Key
	case policy.Algorithm_ALGORITHM_EC_P521:
		return ocrypto.EC521Key
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return ocrypto.RSA2048Key
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return RSA4096Key
	case policy.Algorithm_ALGORITHM_UNSPECIFIED:
		return ocrypto.KeyType("")
	default:
		return ocrypto.KeyType("")
	}
}

func storeKeysToCache(kases []*policy.KeyAccessServer, keys []*policy.SimpleKasKey, c *kasKeyCache, kc *rlKeyCache) {
	for _, kas := range kases {
		keys := kas.GetPublicKey().GetCached().GetKeys()
		if len(keys) == 0 {
			slog.Debug("no cached key in policy service", slog.String("kas", kas.GetUri()))
			continue
		}
		for _, ki := range keys {
			c.store(KASInfo{
				URL:       kas.GetUri(),
				KID:       ki.GetKid(),
				Algorithm: algProto2String(ki.GetAlg()),
				PublicKey: ki.GetPem(),
			})

			// Store in rlKeyCache if sufficient information is available
			// (KID and PEM must not be empty)
			if kc != nil && ki.GetKid() != "" && ki.GetPem() != "" {
				rl, err := NewResourceLocator(kas.GetUri())
				if err != nil {
					slog.Debug("failed to create ResourceLocator",
						slog.String("kas", kas.GetUri()),
						slog.Any("error", err),
					)
					continue
				}
				rl.identifier = ki.GetKid()
				kc.c[*rl] = &policy.SimpleKasKey{
					KasUri: kas.GetUri(),
					PublicKey: &policy.SimpleKasPublicKey{
						Algorithm: convertAlgEnum2Simple(ki.GetAlg()),
						Pem:       ki.GetPem(),
						Kid:       ki.GetKid(),
					},
					KasId: kas.GetId(),
				}
			}
		}
	}
	for _, key := range keys {
		alg, err := formatAlg(key.GetPublicKey().GetAlgorithm())
		if err != nil {
			continue
		}
		c.store(KASInfo{
			URL:       key.GetKasUri(),
			KID:       key.GetPublicKey().GetKid(),
			Algorithm: alg,
			PublicKey: key.GetPublicKey().GetPem(),
		})

		// Store in rlKeyCache if provided
		if kc != nil && key.GetPublicKey().GetKid() != "" && key.GetPublicKey().GetPem() != "" {
			rl, err := NewResourceLocator(key.GetKasUri())
			if err != nil {
				slog.Debug("failed to create ResourceLocator",
					slog.String("kas", key.GetKasUri()),
					slog.Any("error", err),
				)
				continue
			}
			rl.identifier = key.GetPublicKey().GetKid()
			kc.c[*rl] = key
		}
	}
}

// Given a policy (list of data attributes or tags),
// get a set of grants from attribute values to KASes.
// Unlike `newGranterFromService`, this works offline.
func newGranterFromAttributes(keyCache *kasKeyCache, featureClient *openfeature.Client, attrs ...*policy.Value) (granter, error) {
	grants := granter{
		grantTable:    make(map[string]*keyAccessGrant),
		mapTable:      make(map[string][]*ResourceLocator),
		tags:          make([]AttributeValueFQN, len(attrs)),
		keyCache:      &rlKeyCache{c: make(map[ResourceLocator]*policy.SimpleKasKey)},
		featureClient: featureClient,
	}
	for i, v := range attrs {
		fqn, err := NewAttributeValueFQN(v.GetFqn())
		if err != nil {
			return grants, err
		}
		grants.tags[i] = fqn
		def := v.GetAttribute()
		if def == nil {
			return granter{}, fmt.Errorf("no associated definition with value [%s]", fqn)
		}
		namespace := def.GetNamespace()
		if namespace == nil {
			return granter{}, fmt.Errorf("no associated namespace with definition [%s] from value [%s]", def.GetFqn(), fqn)
		}

		if grants.addAllGrants(fqn, v, def) != noKeysFound {
			storeKeysToCache(v.GetGrants(), v.GetKasKeys(), keyCache, grants.keyCache)
			continue
		}
		// If no more specific grant was found, then add the attr grants
		if grants.addAllGrants(fqn, def, def) != noKeysFound {
			storeKeysToCache(def.GetGrants(), def.GetKasKeys(), keyCache, grants.keyCache)
			continue
		}
		grants.addAllGrants(fqn, namespace, def)
		storeKeysToCache(namespace.GetGrants(), namespace.GetKasKeys(), keyCache, grants.keyCache)
	}

	// Check if key_management feature is provided.
	if featureClient.Boolean(context.TODO(), "key_management", false, openfeature.EvaluationContext{}) && grants.typ == grantsFound {
		// Set to no key found, use base key
		grants.typ = noKeysFound
	}

	return grants, nil
}

type singleAttributeClause struct {
	def    *policy.Attribute
	values []AttributeValueFQN
}

type attributeBooleanExpression struct {
	must []singleAttributeClause
}

func (e attributeBooleanExpression) String() string {
	if len(e.must) == 0 {
		return "∅"
	}
	var sb strings.Builder
	for i, clause := range e.must {
		if i > 0 {
			sb.WriteString("&")
		}
		switch len(clause.values) {
		case 0:
			sb.WriteString(clause.def.GetFqn())
		case 1:
			sb.WriteString(clause.values[0].String())
		default:
			sb.WriteString(clause.def.GetFqn())
			sb.WriteString("/value/{")
			for j, v := range clause.values {
				if j > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(v.Value())
			}
			sb.WriteString("}")
		}
	}
	return sb.String()
}

func (r granter) plan(defaultKas []string, genSplitID func() string) ([]keySplitStep, error) {
	b := r.constructAttributeBoolean()
	k, err := r.insertKeysForAttribute(*b)
	if err != nil {
		return nil, err
	}

	k = k.reduce()
	l := k.Len()
	if l == 0 {
		// default behavior: split key across all default kases
		switch len(defaultKas) {
		case 0:
			return nil, errors.New("no default KAS specified; required for grantless plans")
		case 1:
			return []keySplitStep{{KAS: defaultKas[0]}}, nil
		default:
			p := make([]keySplitStep, 0, len(defaultKas))
			for _, kas := range defaultKas {
				p = append(p, keySplitStep{KAS: kas, SplitID: genSplitID()})
			}
			return p, nil
		}
	}
	p := make([]keySplitStep, 0, l)
	for _, v := range k.values {
		splitID := ""
		if l > 1 {
			splitID = genSplitID()
		}
		for _, o := range v.values {
			p = append(p, keySplitStep{KAS: o.KASURI(), SplitID: splitID})
		}
	}
	return p, nil
}

func (r granter) resolveTemplate(ctx context.Context, kaoKeyAlg string, genSplitID func() string) ([]kaoTpl, error) {
	b := r.constructAttributeBoolean()
	k, err := r.assignKeysTo(*b)
	if err != nil {
		return nil, err
	}

	k = k.reduce()
	l := k.Len()
	if l == 0 {
		return []kaoTpl{}, nil
	}
	p := make([]kaoTpl, 0, l)
	for _, v := range k.values {
		splitID := ""
		if l > 1 {
			splitID = genSplitID()
		}
		for _, o := range v.values {
			if o.ID() == "" && r.keyInfoFetcher != nil {
				// No Key ID, guess what it should be.
				kpub, err := r.keyInfoFetcher.getPublicKey(ctx, o.KASURI(), kaoKeyAlg, "")
				if err != nil {
					return nil, fmt.Errorf("failed to fetch public key for resource locator [%s]: %w", o, err)
				}
				o.identifier = kpub.KID
				// Convert the string algorithm to the appropriate enum
				algEnum := convertStringToAlgorithm(kpub.Algorithm)
				r.keyCache.c[*o] = &policy.SimpleKasKey{
					KasUri: o.KASURI(),
					PublicKey: &policy.SimpleKasPublicKey{
						Algorithm: algEnum,
						Pem:       kpub.PublicKey,
						Kid:       kpub.KID,
					},
				}
			}
			kpub, ok := r.keyCache.c[*o]
			if !ok || kpub.GetPublicKey() == nil || kpub.GetPublicKey().GetPem() == "" {
				return nil, fmt.Errorf("no key found for resource locator [%s]", o)
			}
			algorithm := algProto2OcryptoKeyType(kpub.GetPublicKey().GetAlgorithm())
			p = append(p, kaoTpl{o.KASURI(), splitID, o.ID(), kpub.GetPublicKey().GetPem(), algorithm})
		}
	}
	return p, nil
}

func (r granter) constructAttributeBoolean() *attributeBooleanExpression {
	prefixes := make(map[string]*singleAttributeClause)
	sortedPrefixes := make([]string, 0)
	for _, aP := range r.tags {
		a := aP
		p := strings.ToLower(a.Prefix().String())
		if clause, ok := prefixes[p]; ok {
			clause.values = append(clause.values, a)
		} else if kag := r.byAttribute(a); kag != nil {
			prefixes[p] = &singleAttributeClause{kag.attr, []AttributeValueFQN{a}}
			sortedPrefixes = append(sortedPrefixes, p)
		}
	}
	must := make([]singleAttributeClause, 0, len(prefixes))[0:0]
	for _, p := range sortedPrefixes {
		must = append(must, *prefixes[p])
	}
	return &attributeBooleanExpression{must}
}

type keyClause struct {
	operator string
	values   []*ResourceLocator
}

func (e keyClause) String() string {
	if len(e.values) == 1 && e.values[0].KASURI() == "" {
		return "[" + emptyTerm + "]"
	}
	if len(e.values) == 1 {
		return "(" + e.values[0].String() + ")"
	}
	var sb strings.Builder
	sb.WriteString("(")
	op := "⋀"
	if e.operator == anyOf {
		op = "⋁"
	}
	for i, v := range e.values {
		if i > 0 {
			sb.WriteString(op)
		}
		sb.WriteString(v.String())
	}
	sb.WriteString(")")
	return sb.String()
}

type booleanKeyExpression struct {
	values []keyClause
}

func (e booleanKeyExpression) String() string {
	var sb strings.Builder
	for i, v := range e.values {
		if i > 0 {
			sb.WriteString("&")
		}
		sb.WriteString(v.String())
	}
	return sb.String()
}

func ruleToOperator(e policy.AttributeRuleTypeEnum) string {
	switch e {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		return allOf
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		return anyOf
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		return hierarchy
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		return unspecified
	}
	return ""
}

// Old version of plan, without KIDs in resource locators.
func (r *granter) insertKeysForAttribute(e attributeBooleanExpression) (booleanKeyExpression, error) {
	kcs := make([]keyClause, 0, len(e.must))
	for _, clause := range e.must {
		kcv := make([]*ResourceLocator, 0, len(clause.values))
		for _, term := range clause.values {
			grant := r.byAttribute(term)
			if grant == nil {
				return booleanKeyExpression{}, fmt.Errorf("no defintion or grant found for [%s]", term)
			}
			kases := grant.kases
			if len(kases) == 0 {
				kases = []string{emptyTerm}
			}
			for _, kas := range kases {
				var rl *ResourceLocator
				if kas == emptyTerm {
					// Default term, no KAS associated
					rl = &ResourceLocator{}
				} else {
					var err error
					rl, err = NewResourceLocator(kas)
					if err != nil {
						slog.Warn("invalid KAS URL in policy service",
							slog.String("kas", kas),
							slog.Any("value", term),
							slog.Any("error", err),
						)
						return booleanKeyExpression{}, fmt.Errorf("invalid KAS URL in policy service associated with [%s]: %w", term, err)
					}
				}
				kcv = append(kcv, rl)
			}
		}
		op := ruleToOperator(clause.def.GetRule())
		if op == unspecified {
			slog.Warn("unknown attribute rule type", slog.Any("rule", clause))
		}
		kc := keyClause{
			operator: op,
			values:   kcv,
		}
		kcs = append(kcs, kc)
	}
	return booleanKeyExpression{
		values: kcs,
	}, nil
}

func (r *granter) assignKeysTo(e attributeBooleanExpression) (booleanKeyExpression, error) {
	anyAssignmentsFound := false
	kcs := make([]keyClause, 0, len(e.must))
	for _, clause := range e.must {
		kcv := make([]*ResourceLocator, 0, len(clause.values))
		for _, term := range clause.values {
			mv, ok := r.mapTable[term.key]
			if ok {
				for _, rl := range mv {
					kcv = append(kcv, rl)
					anyAssignmentsFound = true
				}
			}
		}
		op := ruleToOperator(clause.def.GetRule())
		if op == unspecified {
			slog.Warn("unknown attribute rule type", slog.Any("rule", clause))
		}
		kc := keyClause{
			operator: op,
			values:   kcv,
		}
		kcs = append(kcs, kc)
	}
	if !anyAssignmentsFound {
		// No assignments found, fall back to grants
		return r.insertKeysForAttribute(e)
	}

	return booleanKeyExpression{
		values: kcs,
	}, nil
}

// remove duplicates, sort a set of strings
func sortedNoDupes(l []*ResourceLocator) disjunction {
	set := map[string]bool{}
	list := make([]*ResourceLocator, 0)
	for _, e := range l {
		kas := e.String()
		if kas != "" && !set[kas] {
			set[kas] = true
			list = append(list, e)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Less(list[j])
	})
	return list
}

type disjunction []*ResourceLocator

func (l disjunction) Less(r disjunction) bool {
	m := min(len(l), len(r))
	for i := 1; i <= m; i++ {
		if l[i].Less(r[i]) {
			return true
		}
		if r[i].Less(l[i]) {
			return false
		}
	}
	return len(l) < len(r)
}

func (l disjunction) Equal(r disjunction) bool {
	if len(l) != len(r) {
		return false
	}
	for i, v := range l {
		if !v.Equals(*r[i]) {
			return false
		}
	}
	return true
}

func within(l []disjunction, e disjunction) bool {
	for _, v := range l {
		if e.Equal(v) {
			return true
		}
	}
	return false
}

func (e booleanKeyExpression) Len() int {
	c := 0
	for _, v := range e.values {
		c += len(v.values)
	}
	return c
}

func (e booleanKeyExpression) reduce() booleanKeyExpression {
	var conjunction []disjunction
	for _, v := range e.values {
		switch v.operator {
		case anyOf:
			terms := sortedNoDupes(v.values)
			if len(terms) > 0 && !within(conjunction, terms) {
				conjunction = append(conjunction, terms)
			}
		default:
			for _, k := range v.values {
				if k.KASURI() == "" {
					continue
				}
				terms := []*ResourceLocator{k}
				if !within(conjunction, terms) {
					conjunction = append(conjunction, terms)
				}
			}
		}
	}
	if len(conjunction) == 0 {
		return booleanKeyExpression{}
	}
	values := make([]keyClause, len(conjunction))
	for i, d := range conjunction {
		pki := make([]*ResourceLocator, len(d))
		copy(pki, d)
		values[i] = keyClause{
			operator: anyOf,
			values:   pki,
		}
	}
	return booleanKeyExpression{values}
}
