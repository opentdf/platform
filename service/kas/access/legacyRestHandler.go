package access

import (
	"encoding/json"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	kaspb "github.com/opentdf/platform/protocol/go/kas" // Ensure this path is correct and matches the actual package location
)

type LegacyMuxEndpoint struct {
	Method string
	Path   string
}

var (
	LegacyPublicKey = LegacyMuxEndpoint{
		Method: "GET",
		Path:   "/kas/kas_public_key",
	}
	LegacyPublicKeyV2 = LegacyMuxEndpoint{
		Method: "GET",
		Path:   "/kas/v2/kas_public_key",
	}
	LegacyRewrap = LegacyMuxEndpoint{
		Method: "POST",
		Path:   "/kas/v2/rewrap",
	}
)

func (p *Provider) LegacyMuxHandlerPublicKey(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	// Example handler for PublicKey RPC
	req := &kaspb.PublicKeyRequest{}
	req.Reset()
	connectReq := connect.NewRequest(req)
	response, err := p.PublicKey(r.Context(), connectReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get public key: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	responseBytes, err := json.Marshal(struct {
		PublicKey string `json:"publicKey"`
		Kid       string `json:"kid"`
	}{
		PublicKey: response.Msg.GetPublicKey(),
		Kid:       response.Msg.GetKid(),
	})
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(responseBytes)
}

func (p *Provider) LegacyMuxHandlerRewrap(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	// Example handler for Rewrap RPC
	req := &kaspb.RewrapRequest{}
	req.Reset()
	connectReq := connect.NewRequest(req)
	response, err := p.Rewrap(r.Context(), connectReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get public key: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	responseBytes, err := json.Marshal(struct {
		SessionPublicKey string `json:"sessionPublicKey"`
	}{
		SessionPublicKey: response.Msg.GetSessionPublicKey(),
	})
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(responseBytes)
}
