package sdk

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

// baseKeyProvider supplies the platform's base key, the wrapping target
// of last resort for a payload whose attributes name no KAS at all.
// SDK satisfies it; an offline splitter has none and errors instead.
type baseKeyProvider interface {
	GetBaseKey(ctx context.Context) (*policy.SimpleKasKey, error)
}

// attributeSplitter is the canonical [KeySplitter]: the same attribute
// reasoning SDK.CreateTDF performs, behind the seam the chunked Writer
// injects. It delegates to [granter], so mapped-keys-over-grants
// precedence, hierarchy-as-AND, and KID-qualified deduplication are
// decided in exactly one place.
type attributeSplitter struct {
	// fetcher resolves a public key from a KAS that policy named
	// without naming a key. Nil means offline: unresolvable keys are
	// an error rather than a network call.
	fetcher KASKeyFetcher

	// base supplies the platform base key when nothing else names a
	// KAS. Nil disables the base-key fallback.
	base baseKeyProvider

	// keyCache holds keys carried inline by policy, so the common case
	// resolves without touching the network.
	keyCache *kasKeyCache

	// logger records why a fallback was taken.
	logger *slog.Logger

	// rand is the entropy source for the XOR shares.
	rand io.Reader
}

// KeySplitterOption configures a splitter built by
// [NewAttributeKeySplitter].
type KeySplitterOption func(*attributeSplitter)

// WithSplitterLogger sets the logger the splitter reports fallback
// decisions to.
func WithSplitterLogger(logger *slog.Logger) KeySplitterOption {
	return func(x *attributeSplitter) {
		if logger != nil {
			x.logger = logger
		}
	}
}

// WithSplitterRand overrides the entropy source used for the XOR
// shares. Tests inject a deterministic reader to get reproducible
// manifests.
func WithSplitterRand(r io.Reader) KeySplitterOption {
	return func(x *attributeSplitter) {
		if r != nil {
			x.rand = r
		}
	}
}

// NewAttributeKeySplitter returns the canonical attribute splitter,
// working entirely offline: every wrapping key must be carried by the
// attribute values themselves or supplied as a default KAS. A policy
// that names a KAS without a usable key is an error rather than a
// network fetch.
//
// Use [SDK.KeySplitter] instead to resolve missing keys against a
// running platform and to pick up the base key.
func NewAttributeKeySplitter(opts ...KeySplitterOption) KeySplitter {
	x := &attributeSplitter{
		keyCache: newKasKeyCache(),
		logger:   slog.Default(),
		rand:     defaultRand,
	}
	for _, opt := range opts {
		opt(x)
	}
	return x
}

// KeySplitter returns the canonical attribute splitter bound to this
// SDK, so it resolves keys the policy did not carry against the
// platform and falls back to the platform base key.
//
// This is what SDK.CreateTDF uses. Pass it to
// [WithChunkedKeySplitter] to give a chunked Writer identical key
// access behavior.
func (s SDK) KeySplitter(opts ...KeySplitterOption) KeySplitter {
	x := &attributeSplitter{
		fetcher:  s,
		base:     s,
		keyCache: s.kasKeyCache,
		logger:   s.logger,
		rand:     defaultRand,
	}
	if x.logger == nil {
		x.logger = slog.Default()
	}
	if x.keyCache == nil {
		x.keyCache = newKasKeyCache()
	}
	for _, opt := range opts {
		opt(x)
	}
	return x
}

func (x *attributeSplitter) Split(ctx context.Context, req SplitRequest) (*SplitResult, error) {
	g := req.granter
	if g == nil {
		// CreateTDF resolves attribute FQNs over the network before it
		// gets here and passes the result along; anyone else hands us
		// fully-populated values, which resolve offline.
		resolved, err := newGranterFromAttributes(x.logger, x.keyCache, req.Attributes...)
		if err != nil {
			return nil, err
		}
		resolved.keyInfoFetcher = x.fetcher
		g = &resolved
	}

	tpl, err := planKAOTemplate(ctx, *g, req, x.fetcher, x.base, x.logger)
	if err != nil {
		return nil, err
	}
	return splitResultFromTemplate(tpl, req.DEK, x.rand)
}

// planKAOTemplate is the canonical "resolved attributes -> KAO
// template" step. Both SDK.CreateTDF and the chunked Writer reach it,
// so both derive the same splits from the same policy.
func planKAOTemplate(ctx context.Context, g granter, req SplitRequest, fetcher KASKeyFetcher, base baseKeyProvider, logger *slog.Logger) ([]kaoTpl, error) {
	genSplitID := req.GenerateSplitID
	if genSplitID == nil {
		genSplitID = uuidSplitIDGenerator
	}

	var tpl []kaoTpl
	var err error
	switch g.typ {
	case mappedFound:
		// Mapped keys are KID-qualified, so the template can name a
		// specific key at each KAS.
		tpl, err = g.resolveTemplate(ctx, string(req.PreferredWrappingAlgorithm), genSplitID)
	case grantsFound, noKeysFound:
		// Legacy grants name a KAS but not a key, so plan on URLs and
		// resolve each URL to a key afterwards. Routing grantsFound
		// through resolveTemplate instead would silently change split
		// counts, because grants that embed several keys at one KAS
		// deduplicate per (URL, key ID) rather than per URL.
		var steps []keySplitStep
		steps, err = g.planSteps(genSplitID)
		if err == nil {
			tpl, err = g.fillTemplateFromPlan(ctx, steps, req.PreferredWrappingAlgorithm, fetcher)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(tpl) > 0 {
		return tpl, nil
	}
	return fallbackTemplate(ctx, req, genSplitID, fetcher, base, logger)
}

// fallbackTemplate binds the DEK when policy yielded no key
// assignments at all -- no attributes, no mapped keys, no grants, or
// only the DEFAULT placeholder that reduce() drops.
//
// The wrapping targets are, in order: the caller's default KAS, then
// the platform base key. Explicit configuration wins so that a caller
// who named a KAS gets that KAS. With neither, there is nothing to
// wrap to and the split fails.
//
// Given one target the DEK is unsplit and the single key access object
// carries no split ID; given several the DEK is split across all of
// them, so every one is required to reassemble it.
func fallbackTemplate(ctx context.Context, req SplitRequest, genSplitID func() string, fetcher KASKeyFetcher, base baseKeyProvider, logger *slog.Logger) ([]kaoTpl, error) {
	kases := req.DefaultKAS
	if len(kases) == 0 && base != nil {
		baseKey, err := base.GetBaseKey(ctx)
		switch {
		case err != nil:
			logger.Debug("no base key available for grantless policy", slog.Any("error", err))
		case baseKey == nil:
			logger.Debug("policy service returned no base key for grantless policy")
		default:
			kases = []*policy.SimpleKasKey{baseKey}
		}
	}
	if len(kases) == 0 {
		return nil, ErrSplitterRequiresDefaultKAS
	}

	tpl := make([]kaoTpl, 0, len(kases))
	for _, kas := range kases {
		splitID := ""
		if len(kases) > 1 {
			splitID = genSplitID()
		}
		entry, err := defaultKASTemplate(ctx, kas, splitID, req.PreferredWrappingAlgorithm, fetcher)
		if err != nil {
			return nil, err
		}
		tpl = append(tpl, entry)
	}
	return tpl, nil
}

// defaultKASTemplate turns one default-KAS entry into a KAO template
// entry, fetching the public key if the entry did not carry one.
func defaultKASTemplate(ctx context.Context, kas *policy.SimpleKasKey, splitID string, preferred ocrypto.KeyType, fetcher KASKeyFetcher) (kaoTpl, error) {
	url := kas.GetKasUri()
	if url == "" {
		return kaoTpl{}, fmt.Errorf("default KAS with no URL: %w", errKasPubKeyMissing)
	}

	if pub := kas.GetPublicKey(); pub.GetPem() != "" {
		// An algorithm the SDK cannot map is a misconfiguration worth
		// failing on: the empty string reaches createKeyAccess, which reads
		// it as RSA, and ocrypto.FromPublicPEM then sniffs the PEM instead
		// of honoring that choice. An EC or ML-KEM key wraps successfully
		// but leaves the KAO claiming keyType "wrapped" with no ephemeral
		// public key, producing a TDF nothing can decrypt.
		//
		// ALGORITHM_UNSPECIFIED is exempt because it is not a claim about
		// the key: KASInfo.Algorithm is optional, and createKaoTemplateFromKasInfo
		// has always read a bare URL and PEM as RSA. Keys that came from
		// policy rather than the caller are checked strictly in
		// fillTemplateFromPlan.
		alg := algorithmPolicyToString(pub.GetAlgorithm())
		if alg == "" && pub.GetAlgorithm() != policy.Algorithm_ALGORITHM_UNSPECIFIED {
			return kaoTpl{}, fmt.Errorf("%w: kas %s advertises algorithm %v",
				ErrSplitterUnsupportedAlgorithm, url, pub.GetAlgorithm())
		}
		return kaoTpl{url, splitID, pub.GetKid(), pub.GetPem(), ocrypto.KeyType(alg)}, nil
	}

	if fetcher == nil {
		return kaoTpl{}, fmt.Errorf("default KAS [%s] carries no public key and this splitter is offline: %w", url, errKasPubKeyMissing)
	}
	info, err := fetcher.getPublicKey(ctx, url, string(preferred), kas.GetPublicKey().GetKid())
	if err != nil {
		return kaoTpl{}, fmt.Errorf("unable to retrieve public key from KAS at [%s]: %w", url, err)
	}
	if info.PublicKey == "" {
		return kaoTpl{}, fmt.Errorf("kas:[%s]: %w", url, errKasPubKeyMissing)
	}
	return kaoTpl{url, splitID, info.KID, info.PublicKey, ocrypto.KeyType(info.Algorithm)}, nil
}

// planSteps reduces the attribute boolean expression to the KAS URLs
// each DEK share must be wrapped to.
//
// Unlike [granter.plan] it has no default-KAS fallback: an expression
// that reduces to nothing returns no steps, and the caller decides
// what to bind the DEK to. That keeps the fallback rule in one place
// for both the grants path and the mapped-keys path.
func (r granter) planSteps(genSplitID func() string) ([]keySplitStep, error) {
	b := r.constructAttributeBoolean()
	k, err := r.insertKeysForAttribute(*b)
	if err != nil {
		return nil, err
	}

	k = k.reduce()
	l := k.Len()
	if l == 0 {
		return nil, nil
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

// fillTemplateFromPlan resolves each planned KAS URL to a concrete
// wrapping key. Grants name a KAS but not a key, so the key comes from
// whatever policy carried inline, and only failing that from the KAS
// itself.
func (r granter) fillTemplateFromPlan(ctx context.Context, steps []keySplitStep, preferred ocrypto.KeyType, fetcher KASKeyFetcher) ([]kaoTpl, error) {
	tpl := make([]kaoTpl, 0, len(steps))
	for _, step := range steps {
		if key := r.keyForURL(step.KAS, preferred); key != nil {
			algorithm, err := PolicyAlgorithmToKeyType(key.GetPublicKey().GetAlgorithm())
			if err != nil {
				return nil, fmt.Errorf("invalid algorithm [%v] for kas [%s]: %w", key.GetPublicKey().GetAlgorithm(), step.KAS, err)
			}
			tpl = append(tpl, kaoTpl{step.KAS, step.SplitID, key.GetPublicKey().GetKid(), key.GetPublicKey().GetPem(), algorithm})
			continue
		}
		if fetcher == nil {
			return nil, fmt.Errorf("splitID:[%s], kas:[%s] has no key in policy and this splitter is offline: %w", step.SplitID, step.KAS, errKasPubKeyMissing)
		}
		info, err := fetcher.getPublicKey(ctx, step.KAS, string(preferred), "")
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve public key from KAS at [%s]: %w", step.KAS, err)
		}
		if info.PublicKey == "" {
			return nil, fmt.Errorf("splitID:[%s], kas:[%s]: %w", step.SplitID, step.KAS, errKasPubKeyMissing)
		}
		tpl = append(tpl, kaoTpl{step.KAS, step.SplitID, info.KID, info.PublicKey, ocrypto.KeyType(info.Algorithm)})
	}
	return tpl, nil
}

// keyForURL returns a usable cached key for the given KAS URL,
// whatever its key ID. A grant names a KAS without naming a key, so
// the KID-qualified cache cannot be probed directly.
//
// A KAS may hold several keys. Prefer one matching the requested
// algorithm, and break any remaining tie on the resource locator so
// the choice does not vary between runs -- Go randomizes map order,
// and the choice ends up in the manifest.
func (r granter) keyForURL(url string, preferred ocrypto.KeyType) *policy.SimpleKasKey {
	if r.keyCache == nil {
		return nil
	}
	var candidates []ResourceLocator
	for locator, key := range r.keyCache.c {
		if locator.KASURI() != url || key.GetPublicKey().GetPem() == "" {
			continue
		}
		candidates = append(candidates, locator)
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if preferred != "" {
			iMatch := keyMatchesAlgorithm(r.keyCache.c[candidates[i]], preferred)
			jMatch := keyMatchesAlgorithm(r.keyCache.c[candidates[j]], preferred)
			if iMatch != jMatch {
				return iMatch
			}
		}
		return candidates[i].String() < candidates[j].String()
	})
	return r.keyCache.c[candidates[0]]
}

// keyMatchesAlgorithm reports whether key wraps with the given key
// type. An unmappable algorithm never matches.
func keyMatchesAlgorithm(key *policy.SimpleKasKey, preferred ocrypto.KeyType) bool {
	alg, err := PolicyAlgorithmToKeyType(key.GetPublicKey().GetAlgorithm())
	return err == nil && alg == preferred
}

// splitResultFromTemplate groups a KAO template by split ID and splits
// the DEK across the resulting groups, one XOR share each. Groups
// appear in first-seen order, so the manifest's key access objects
// follow the order the attribute reasoning emitted them in.
func splitResultFromTemplate(tpl []kaoTpl, dek []byte, rand io.Reader) (*SplitResult, error) {
	if len(tpl) == 0 {
		return nil, fmt.Errorf("no key access template specified or inferred: %w", errInvalidKasInfo)
	}

	var splitIDs []string
	conjunction := make(map[string][]KASPublicKey)
	for _, entry := range tpl {
		if _, ok := conjunction[entry.SplitID]; !ok {
			splitIDs = append(splitIDs, entry.SplitID)
		}
		conjunction[entry.SplitID] = append(conjunction[entry.SplitID], KASPublicKey{
			Algorithm: string(entry.algorithm),
			KID:       entry.kid,
			PEM:       entry.pem,
			URL:       entry.KAS,
		})
	}

	shares, err := splitDEK(dek, len(splitIDs), rand)
	if err != nil {
		return nil, err
	}

	result := &SplitResult{Splits: make([]Split, len(splitIDs))}
	for i, splitID := range splitIDs {
		result.Splits[i] = Split{
			Data: shares[i],
			ID:   splitID,
			Keys: conjunction[splitID],
		}
	}
	return result, nil
}
