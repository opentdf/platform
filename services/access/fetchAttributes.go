package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	ErrAttributeDefinitionsUnmarshal   = Error("attribute definitions unmarshal")
	ErrAttributeDefinitionsServiceCall = Error("attribute definitions service call unexpected")
)

func (p *Provider) fetchAttributes(ctx context.Context, namespaces []string) ([]attributes.Attribute, error) {
	conn, err := grpc.Dial(p.AttributeSvc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.ErrorContext(ctx, "unable to connect to attribute service", "err", err)
		return nil, fmt.Errorf("attribute service connection failed: %w", err)
	}
	defer conn.Close()
	a := attributes.NewAttributesServiceClient(conn)
	response, err := a.ListAttributes(ctx, &attributes.ListAttributesRequest{})

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
