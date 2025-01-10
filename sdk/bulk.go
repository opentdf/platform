package sdk

import (
	"context"
	"errors"
	"fmt"
	"github.com/opentdf/platform/service/kas/request"
	"io"
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
	default:
		return s.createTDF3DecryptHandler(tdf.Writer, tdf.Reader)
	}
}

func (s SDK) BulkDecrypt(ctx context.Context, bulkReq *BulkDecryptRequest) error {
	var rewrapRequests []*request.RewrapRequests
	tdfDecryptors := make(map[string]Decryptor)
	policyTDF := make(map[string]*BulkTDF)

	for i, tdf := range bulkReq.TDFs {
		policyId := fmt.Sprintf("policy-%d", i)
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
		tdfDecryptors[policyId] = decryptor
		policyTDF[policyId] = tdf

		req.Policy.ID = policyId
		rewrapRequests = append(rewrapRequests, req)
	}

	kasClient := newKASClient(s.dialOptions, s.tokenSource, s.kasSessionKey)
	var rewrapResp map[string][]KAOResult
	var err error
	switch bulkReq.TDFType {
	case Nano:
		rewrapResp, err = kasClient.nanoUnwrap(ctx, rewrapRequests)
	default:
		rewrapResp, err = kasClient.unwrap(ctx, rewrapRequests)
	}
	if err != nil {
		return fmt.Errorf("bulk rewrap failed: %w", err)
	}

	var errList []error
	for id, tdf := range policyTDF {
		kaoRes, ok := rewrapResp[id]
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
