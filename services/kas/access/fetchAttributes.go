package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/virtru/access-pdp/attributes"
)

const (
	ErrAttributeDefinitionsUnmarshal   = Error("attribute definitions unmarshal")
	ErrAttributeDefinitionsServiceCall = Error("attribute definitions service call unexpected")
)

func ResolveAttributeAuthority(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		slog.Error("invalid attribute authority", "err", err)
		return nil, errors.Join(ErrConfig, err)
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		slog.Error("invalid attribute authority", "url", u)
		return nil, ErrConfig
	}
	r, err := u.Parse("v1/attrName")
	if err != nil {
		panic(err)
	}
	return r, nil
}

func (p *Provider) fetchAttributes(ctx context.Context, namespaces []string) ([]attributes.AttributeDefinition, error) {
	var definitions []attributes.AttributeDefinition
	for _, ns := range namespaces {
		attrDefs, err := p.fetchAttributesForNamespace(ctx, ns)
		if err != nil {
			slog.ErrorContext(ctx, "unable to fetch attributes for namespace", "err", err, "namespace", ns)
			return nil, err
		}
		definitions = append(definitions, attrDefs...)
	}
	return definitions, nil
}

func (p *Provider) fetchAttributesForNamespace(ctx context.Context, namespace string) ([]attributes.AttributeDefinition, error) {
	slog.DebugContext(ctx, "Fetching", "namespace", namespace)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.AttributeSvc.String(), nil)
	if err != nil {
		slog.ErrorContext(ctx, "unable to create http request to attributes service", "namespace", namespace, "attributeHost", p.AttributeSvc)
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}

	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("authority", namespace)
	req.URL.RawQuery = q.Encode()
	var httpClient http.Client
	resp, err := httpClient.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "failed http request to attributes service", "err", err, "namespace", namespace, "req.URL", req.URL)
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.ErrorContext(ctx, "failed to close http request to attributes service", "err", err, "namespace", namespace, "req.URL", req.URL)
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("status code %v %v", resp.StatusCode, http.StatusText(resp.StatusCode))
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}

	var definitions []attributes.AttributeDefinition
	err = json.NewDecoder(resp.Body).Decode(&definitions)
	if err != nil {
		slog.ErrorContext(ctx, "failed to parse response from attributes service", "err", err, "namespace", namespace, "req.URL", req.URL)
		return nil, errors.Join(ErrAttributeDefinitionsUnmarshal, err)
	}

	return definitions, nil
}
