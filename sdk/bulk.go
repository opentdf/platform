package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/kas"
)

// BulkTDF: Reader is TDF Content. Writer writes encrypted data. Error is the error that occurs if decrypting fails.
type BulkTDF struct {
	Reader               io.ReadSeeker
	Writer               io.Writer
	Error                error
	TriggeredObligations RequiredObligations
}

type BulkDecryptRequest struct {
	TDFs               []*BulkTDF
	TDF3DecryptOptions []TDFReaderOption // Options for TDF3 Decryptor
	TDFType            TdfType
	kasAllowlist       AllowList
	ignoreAllowList    bool
}

// BulkDecryptPrepared holds the prepared state for bulk decryption
// The PolicyTDF is a map of created policy IDs to their corresponding BulkTDF
// The policy IDs are generated during the prepareDecryptors function
type BulkDecryptPrepared struct {
	PolicyTDF     map[string]*BulkTDF
	tdfDecryptors map[string]decryptor
	allRewrapResp map[string][]kaoResult
}

// BulkErrors List of Errors that Failed during Bulk Decryption
type BulkErrors []error

func (b BulkErrors) Unwrap() []error {
	return b
}

func (b BulkErrors) Error() string {
	return "Some TDFs could not be Decrypted: " + errors.Join(b...).Error()
}

// FromBulkErrors Returns List of Decrypt Failures and true if is decryption failures
func FromBulkErrors(err error) ([]error, bool) {
	var list BulkErrors
	ok := errors.As(err, &list)
	return list, ok
}

type BulkDecryptOption func(request *BulkDecryptRequest) error

// WithTDFs Adds Lists of TDFs to be decrypted
func WithTDFs(tdfs ...*BulkTDF) BulkDecryptOption {
	return func(request *BulkDecryptRequest) error {
		request.appendTDFs(tdfs...)
		return nil
	}
}

// WithTDFType Type of TDFs to be decrypted
func WithTDFType(tdfType TdfType) BulkDecryptOption {
	return func(request *BulkDecryptRequest) error {
		request.TDFType = tdfType
		return nil
	}
}

func WithBulkKasAllowlist(kasList []string) BulkDecryptOption {
	return func(request *BulkDecryptRequest) error {
		allowlist, err := newAllowList(kasList)
		if err != nil {
			return fmt.Errorf("failed to create kas allowlist: %w", err)
		}
		request.kasAllowlist = allowlist
		return nil
	}
}

func WithBulkIgnoreAllowlist(ignore bool) BulkDecryptOption {
	return func(request *BulkDecryptRequest) error {
		request.ignoreAllowList = ignore
		return nil
	}
}

func WithTDF3DecryptOptions(options ...TDFReaderOption) BulkDecryptOption {
	return func(request *BulkDecryptRequest) error {
		request.TDF3DecryptOptions = append(request.TDF3DecryptOptions, options...)
		return nil
	}
}

func createBulkRewrapRequest(options ...BulkDecryptOption) (*BulkDecryptRequest, error) {
	req := &BulkDecryptRequest{}
	for _, opt := range options {
		err := opt(req)
		if err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (s SDK) createDecryptor(tdf *BulkTDF, req *BulkDecryptRequest) (decryptor, error) {
	switch req.TDFType {
	case Standard:
		return s.createTDF3DecryptHandler(tdf.Writer, tdf.Reader, req.TDF3DecryptOptions...)
	case Invalid:
	}
	return nil, fmt.Errorf("unknown tdf type: %s", req.TDFType)
}

// setupKasAllowlist configures the KAS allowlist for the bulk request
func (s SDK) setupKasAllowlist(ctx context.Context, bulkReq *BulkDecryptRequest) error {
	if !bulkReq.ignoreAllowList && len(bulkReq.kasAllowlist) == 0 { //nolint:nestif // not complex
		if s.KeyAccessServerRegistry != nil {
			platformEndpoint, err := s.PlatformConfiguration.platformEndpoint()
			if err != nil {
				return fmt.Errorf("retrieving platformEndpoint failed: %w", err)
			}
			// if no kasAllowlist is set, we get the allowlist from the registry
			allowlist, err := allowListFromKASRegistry(ctx, s.logger, s.KeyAccessServerRegistry, platformEndpoint)
			if err != nil {
				return fmt.Errorf("failed to get allowlist from registry: %w", err)
			}
			bulkReq.kasAllowlist = allowlist
			bulkReq.TDF3DecryptOptions = append(bulkReq.TDF3DecryptOptions, withKasAllowlist(bulkReq.kasAllowlist))
		} else {
			s.Logger().Error("no KAS allowlist provided and no KeyAccessServerRegistry available")
			return errors.New("no KAS allowlist provided and no KeyAccessServerRegistry available")
		}
	}
	return nil
}

// prepareDecryptors creates decryptors and rewrap requests for all TDFs
func (s SDK) prepareDecryptors(ctx context.Context, bulkReq *BulkDecryptRequest) (map[string][]*kas.UnsignedRewrapRequest_WithPolicyRequest, map[string]decryptor, map[string]*BulkTDF) {
	kasRewrapRequests := make(map[string][]*kas.UnsignedRewrapRequest_WithPolicyRequest)
	tdfDecryptors := make(map[string]decryptor)
	policyTDF := make(map[string]*BulkTDF)

	for i, tdf := range bulkReq.TDFs {
		policyID := fmt.Sprintf("policy-%d", i)
		decryptor, err := s.createDecryptor(tdf, bulkReq) //nolint:contextcheck // context is not used in createDecryptor
		if err != nil {
			tdf.Error = err
			continue
		}

		req, err := decryptor.CreateRewrapRequest(ctx)
		if err != nil {
			tdf.Error = err
			continue
		}
		tdfDecryptors[policyID] = decryptor
		policyTDF[policyID] = tdf
		for kasURL, r := range req {
			r.Policy.Id = policyID
			kasRewrapRequests[kasURL] = append(kasRewrapRequests[kasURL], r)
		}
	}

	return kasRewrapRequests, tdfDecryptors, policyTDF
}

// performRewraps executes all rewrap requests with KAS servers
func (s SDK) performRewraps(ctx context.Context, bulkReq *BulkDecryptRequest, kasRewrapRequests map[string][]*kas.UnsignedRewrapRequest_WithPolicyRequest, fulfillableObligations []string) (map[string][]kaoResult, error) {
	kasClient := newKASClient(s.conn.Client, s.conn.Options, s.tokenSource, s.kasSessionKey, fulfillableObligations)
	allRewrapResp := make(map[string][]kaoResult)
	var err error

	for kasurl, rewrapRequests := range kasRewrapRequests {
		if bulkReq.ignoreAllowList {
			s.Logger().Warn("kasAllowlist is ignored, kas url is allowed", slog.String("kas_url", kasurl))
		} else if !bulkReq.kasAllowlist.IsAllowed(kasurl) {
			// if kas url is not allowed, the result for each kao in each rewrap request is set to error
			for _, req := range rewrapRequests {
				id := req.GetPolicy().GetId()
				for _, kao := range req.GetKeyAccessObjects() {
					allRewrapResp[id] = append(allRewrapResp[id], kaoResult{
						Error:             fmt.Errorf("KasAllowlist: kas url %s is not allowed", kasurl),
						KeyAccessObjectID: kao.GetKeyAccessObjectId(),
					})
				}
			}
			continue
		}

		var rewrapResp map[string][]kaoResult
		rewrapResp, err = kasClient.unwrap(ctx, rewrapRequests...)

		for id, res := range rewrapResp {
			allRewrapResp[id] = append(allRewrapResp[id], res...)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("bulk rewrap failed: %w", err)
	}

	return allRewrapResp, nil
}

// PrepareBulkDecrypt does everything except decrypt from the Bulk Decrypt
// ! Currently you cannot specify fulfillable obligations on an individual TDF basis
func (s SDK) PrepareBulkDecrypt(ctx context.Context, opts ...BulkDecryptOption) (*BulkDecryptPrepared, error) {
	bulkReq, createError := createBulkRewrapRequest(opts...)
	if createError != nil {
		return nil, fmt.Errorf("failed to create bulk rewrap request: %w", createError)
	}

	// Setup KAS allowlist
	if err := s.setupKasAllowlist(ctx, bulkReq); err != nil {
		return nil, err
	}

	// Prepare decryptors and rewrap requests
	kasRewrapRequests, tdfDecryptors, policyTDF := s.prepareDecryptors(ctx, bulkReq)

	// Use the default fulfillable obligations unless a decryptor is available to provide its own
	fulfillableObligations := s.fulfillableObligationFQNs
	if len(tdfDecryptors) > 0 {
		for _, d := range tdfDecryptors {
			fulfillableObligations = getFulfillableObligations(d, s.logger)
			break
		}
	}

	// Perform rewraps
	allRewrapResp, err := s.performRewraps(ctx, bulkReq, kasRewrapRequests, fulfillableObligations)
	if err != nil {
		return nil, err
	}

	for id, tdf := range policyTDF {
		policyRes, ok := allRewrapResp[id]
		if !ok {
			tdf.Error = errors.New("rewrap did not create a response for this TDF")
			continue
		}
		tdf.TriggeredObligations = RequiredObligations{FQNs: dedupRequiredObligations(policyRes)}
	}

	return &BulkDecryptPrepared{
		PolicyTDF:     policyTDF,
		tdfDecryptors: tdfDecryptors,
		allRewrapResp: allRewrapResp,
	}, nil
}

// Allow the bulk decryption to occur
func (bp *BulkDecryptPrepared) BulkDecrypt(ctx context.Context) error {
	var errList []error
	var err error
	for id, tdf := range bp.PolicyTDF {
		kaoRes, ok := bp.allRewrapResp[id]
		if !ok {
			tdf.Error = errors.New("rewrap did not create a response for this TDF")
			errList = append(errList, tdf.Error)
			continue
		}
		decryptor := bp.tdfDecryptors[id]
		if _, err = decryptor.Decrypt(ctx, kaoRes); err != nil {
			tdf.Error = err
			errList = append(errList, tdf.Error)
			continue
		}
	}

	if len(errList) != 0 {
		return BulkErrors(errList)
	}

	return nil
}

// BulkDecrypt Decrypts a list of BulkTDF and if a partial failure of TDFs unable to be decrypted, BulkErrors would be returned.
func (s SDK) BulkDecrypt(ctx context.Context, opts ...BulkDecryptOption) error {
	prepared, err := s.PrepareBulkDecrypt(ctx, opts...)
	if err != nil {
		return err
	}

	return prepared.BulkDecrypt(ctx)
}

func (b *BulkDecryptRequest) appendTDFs(tdfs ...*BulkTDF) {
	b.TDFs = append(
		b.TDFs,
		tdfs...,
	)
}

func getFulfillableObligations(decryptor decryptor, logger *slog.Logger) []string {
	if decryptor == nil {
		logger.Warn("decryptor is nil, cannot populate obligations")
		return make([]string, 0)
	}

	switch d := decryptor.(type) {
	case *tdf3DecryptHandler:
		return d.reader.config.fulfillableObligationFQNs
	default:
		logger.Warn("unknown decryptor type, cannot populate obligations", slog.String("type", fmt.Sprintf("%T", d)))
		return make([]string, 0)
	}
}
