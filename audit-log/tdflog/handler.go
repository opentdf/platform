package tdflog 

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/sdk"
)

type tdfHandler struct {
	level slog.Level 
	policy []string
	sdk *sdk.SDK
	kasUrl string
	attributeMap map[string][]string
	
	delegate slog.Handler
}

func NewTDFHandler(sdk *sdk.SDK, platformEndpoint string, cfg *config) *tdfHandler {
	policy := []string{}
	for _, a := range cfg.Attributes {
		policy = append(policy, cfg.AttributeMap[a]...)
	}

	return &tdfHandler{level: cfg.Level, policy: policy, sdk: sdk, kasUrl: platformEndpoint, attributeMap: cfg.AttributeMap, delegate: cfg.Delegate}
}

func (t *tdfHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return t.level <= level
}

func (t *tdfHandler) Handle(ctx context.Context, record slog.Record) error {
	return t.delegate.Handle(ctx, t.cleanRecord(&record))
}

func (t *tdfHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	t2 := *t
	attrs = t2.cleanAttrs(attrs)
	t2.delegate = t.delegate.WithAttrs(attrs)
	return &t2
}

func (t *tdfHandler) WithGroup(name string) slog.Handler {
	t2 := *t
	t2.delegate = t.delegate.WithGroup(name)
	return &t2
}


func (t *tdfHandler) cleanRecord(record *slog.Record) slog.Record {
	cleanRecord := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)	
	cleanRecord.AddAttrs(t.getAttrs(record)...)
	return cleanRecord
}

func (t *tdfHandler) getAttrs(record *slog.Record) []slog.Attr {
	attrs := []slog.Attr{}
	record.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	return t.cleanAttrs(attrs)
}


func (t *tdfHandler) cleanAttrs(attrs []slog.Attr) []slog.Attr {
	var err error
	ret := []slog.Attr{}
	for i := range attrs {
		a := &attrs[i] 
		switch {
		case isEncryptAttr(*a): 
			err = t.encryptAttributes(a)
			ret = append(ret, *a)
		case isAddAttr(*a):
			attributes := getAttributes(a)
			t.policy = append(t.policy, t.buildPolicy(attributes)...)
		}
	}
	if err != nil {
		// TODO: handle this 
		panic(err)
	}
	return ret
}
func (t *tdfHandler) encryptAttributes(attr *slog.Attr) error {
	stringVal := fmt.Sprintf("%v", attr.Value.Any())
	var encryptBuf bytes.Buffer
	cfg, err := t.sdk.NewNanoTDFConfig()
	if err != nil {
		return fmt.Errorf("could not encrypt log attribute! error creating nano tdf config: %w", err)
	}
	attrs := t.buildPolicy(cleanEncryptAttr(attr))
	attrs = append(attrs, t.policy...)
	if err := cfg.SetAttributes(attrs); err != nil {
		return fmt.Errorf("could not encrypt log attribute! error setting attribute: %w", err)
	}
	if err := cfg.SetKasURL(t.kasUrl); err != nil {
		return fmt.Errorf("could not encrypt log attribute! error setting kas url: %w", err)
	}

	_, err = t.sdk.CreateNanoTDF(&encryptBuf, strings.NewReader(stringVal), *cfg)
	if err != nil {
		return fmt.Errorf("could not encrypt log attribute! error creating tdf: %w", err)
	}

	encryptedData := encryptBuf.Bytes()
	attr.Value = slog.AnyValue(encryptedData)
	return nil
}


func (t *tdfHandler) buildPolicy(attributes []string) []string {
	policy := []string{}
	for _, a := range attributes {
		policy = append(policy, t.attributeMap[a]...)
	}
	return policy
}
