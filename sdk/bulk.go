package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/platform/protocol/go/kas"
)

// BulkTDF: Reader is TDF Content. Writer writes encrypted data. Error is the error that occurs if decrypting fails.
type BulkTDF struct {
	Reader io.ReadSeeker
	Writer io.Writer
	Error  error
}

type BulkDecryptRequest struct {
	TDFs    []*BulkTDF
	TDFType TdfType
}

// BulkErrors List of Errors that Failed during Bulk Decryption
type BulkErrors []error

func (b BulkErrors) Unwrap() []error {
	return b
}

func (b BulkErrors) Error() string {
	return fmt.Sprintf("Some TDFs could not be Decrypted: %s", errors.Join(b...).Error())
}

// FromBulkErrors Returns List of Decrypt Failures and true if is decryption failures
func FromBulkErrors(err error) ([]error, bool) {
	var list BulkErrors
	ok := errors.As(err, &list)
	return list, ok
}

type BulkDecryptOption func(request *BulkDecryptRequest)

// WithTDFs Adds Lists of TDFs to be decrypted
func WithTDFs(tdfs ...*BulkTDF) BulkDecryptOption {
	return func(request *BulkDecryptRequest) {
		request.appendTDFs(tdfs...)
	}
}

// WithTDFType Type of TDFs to be decrypted
func WithTDFType(tdfType TdfType) BulkDecryptOption {
	return func(request *BulkDecryptRequest) {
		request.TDFType = tdfType
	}
}

func createBulkRewrapRequest(options ...BulkDecryptOption) *BulkDecryptRequest {
	req := &BulkDecryptRequest{}
	for _, opt := range options {
		opt(req)
	}
	return req
}

func (s SDK) createDecryptor(tdf *BulkTDF, tdfType TdfType) (decryptor, error) {
	switch tdfType {
	case Nano:
		decryptor := createNanoTDFDecryptHandler(tdf.Reader, tdf.Writer)
		return decryptor, nil
	case Standard:
		return s.createTDF3DecryptHandler(tdf.Writer, tdf.Reader)
	case Invalid:
	}
	return nil, fmt.Errorf("unknown tdf type: %s", tdfType)
}

// BulkDecrypt Decrypts a list of BulkTDF and if a partial failure of TDFs unable to be decrypted, BulkErrors would be returned.
func (s SDK) BulkDecrypt(ctx context.Context, opts ...BulkDecryptOption) error {
	bulkReq := createBulkRewrapRequest(opts...)
	kasRewrapRequests := make(map[string][]*kas.UnsignedRewrapRequest_WithPolicyRequest)
	tdfDecryptors := make(map[string]decryptor)
	policyTDF := make(map[string]*BulkTDF)

	for i, tdf := range bulkReq.TDFs {
		policyID := fmt.Sprintf("policy-%d", i)
		decryptor, err := s.createDecryptor(tdf, bulkReq.TDFType)
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

	kasClient := newKASClient(s.dialOptions, s.tokenSource, s.kasSessionKey)
	allRewrapResp := make(map[string][]kaoResult)
	var err error
	for _, rewrapRequests := range kasRewrapRequests {
		var rewrapResp map[string][]kaoResult
		switch bulkReq.TDFType {
		case Nano:
			rewrapResp, err = kasClient.nanoUnwrap(ctx, rewrapRequests...)
		case Standard, Invalid:
			rewrapResp, err = kasClient.unwrap(ctx, rewrapRequests...)
		}

		for id, res := range rewrapResp {
			allRewrapResp[id] = append(allRewrapResp[id], res...)
		}
	}
	if err != nil {
		return fmt.Errorf("bulk rewrap failed: %w", err)
	}

	var errList []error
	for id, tdf := range policyTDF {
		kaoRes, ok := allRewrapResp[id]
		if !ok {
			tdf.Error = fmt.Errorf("rewrap did not create a response for this TDF")
			errList = append(errList, tdf.Error)
			continue
		}
		decryptor := tdfDecryptors[id]
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

func (b *BulkDecryptRequest) appendTDFs(tdfs ...*BulkTDF) {
	b.TDFs = append(
		b.TDFs,
		tdfs...,
	)
}
