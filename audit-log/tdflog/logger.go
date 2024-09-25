package tdflog

import (
	"log/slog"
	"os"

	"github.com/opentdf/platform/sdk"
)

type Option func(*config) 

var DefaultTDFClient *sdk.SDK

func SetDefaultTDFClient(client *sdk.SDK) {
	DefaultTDFClient = client
}

type config struct {
	Attributes []string
	AttributeMap map[string][]string
	Delegate slog.Handler
	Level slog.Level
	SDK *sdk.SDK
}
func newDefaultConfig() *config {
	return &config{Attributes: []string{}, AttributeMap: map[string][]string{}, Delegate: slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}), Level: slog.LevelDebug}
}

func NewTDFLogger(platformEndpoint string, opts ...Option) *slog.Logger {
	cfg := newDefaultConfig()
	for _, o := range opts {
		o(cfg)
	}

	handler := NewTDFHandler(platformEndpoint, cfg)
	return slog.New(handler)
}

func WithAttributes(attr ...string) Option {
	return func(c *config) {
		c.Attributes = append(c.Attributes, attr...)
	}
}

func WithAttributeMap(m map[string][]string) Option {
	return func(c *config) {
		c.AttributeMap = m
	}
}

func WithDelegateHandler(del slog.Handler) Option {
	return func(c *config) {
		c.Delegate = del
	}
}

func WithSDK(client *sdk.SDK) Option {
	return func(c *config) {
		c.SDK = client 
	}
}
