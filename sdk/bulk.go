package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/platform/service/kas/request"
)

type BulkTDF struct {
	Reader io.ReadSeeker
	Writer io.Writer
	Error  error
}

type BulkDecryptRequest struct {
	TDFs    []*BulkTDF
	TDFType TdfType
}

type BulkDecryptionErrors []error

func (b BulkDecryptionErrors) Error() string {
	return fmt.Sprintf("Some TDFs could not be Decrypted: %s", errors.Join(b...).Error())
}

// IsPartialFailure Returns List of Decrypt Failures and true if is decryption failures
func IsPartialFailure(err error) ([]error, bool) {
	var list BulkDecryptionErrors
	ok := errors.As(err, &list)
	return list, ok
}

type BulkDecryptOption func(request *BulkDecryptRequest)

func WithTDFs(tdfs ...*BulkTDF) BulkDecryptOption {
	return func(request *BulkDecryptRequest) {
		request.AppendTDFs(tdfs...)
	}
}

func (s SDK) CreateBulkRewrapRequest(options ...BulkDecryptOption) *BulkDecryptRequest {
	req := &BulkDecryptRequest{}
	for _, opt := range options {
		opt(req)
	}
	return req
}

func (s SDK) createDecryptor(tdf *BulkTDF, tdfType TdfType) (Decryptor, error) {
	switch tdfType {
	case Nano:
		decryptor := CreateNanoTDFDecryptHandler(tdf.Reader, tdf.Writer)
		return decryptor, nil
	case Standard:
		return s.createTDF3DecryptHandler(tdf.Writer, tdf.Reader)
	case Invalid:
	}
	return nil, fmt.Errorf("unknown tdf type: %s", tdfType)
}

func (s SDK) BulkDecrypt(ctx context.Context, bulkReq *BulkDecryptRequest) error {
	kasRewrapRequests := make(map[string][]*request.RewrapRequests)
	tdfDecryptors := make(map[string]Decryptor)
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
			r.Policy.ID = policyID
			kasRewrapRequests[kasURL] = append(kasRewrapRequests[kasURL], r)
		}
	}

	kasClient := newKASClient(s.dialOptions, s.tokenSource, s.kasSessionKey)
	allRewrapResp := make(map[string][]KAOResult)
	var err error
	for _, rewrapRequests := range kasRewrapRequests {
		var rewrapResp map[string][]KAOResult
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
		return BulkDecryptionErrors(errList)
	}

	return nil
}

func (b *BulkDecryptRequest) AppendTDFs(tdfs ...*BulkTDF) {
	b.TDFs = append(
		b.TDFs,
		tdfs...,
	)
}
