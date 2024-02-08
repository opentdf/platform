package opa

import (
	"context"
	"fmt"
	opalog "github.com/open-policy-agent/opa/logging"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// compile fail if opa Logger changes interface
var _ opalog.Logger = &AdapterSlogger{}

var tl = TestLogHandler{}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(&tl))
	code := m.Run()
	os.Exit(code)
}

func TestNewEngine(t *testing.T) {
	type args struct {
		config Config
	}
	tests := []struct {
		name    string
		args    args
		want    *Engine
		wantLog string
		wantErr bool
	}{
		{
			name: "simple",
			args: args{
				config: Config{
					Path:     "",
					Embedded: true,
				},
			},
			want:    &Engine{},
			wantLog: "Download starting.",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewEngine(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("NewEngine() got = %v, want %v", got, tt.want)
			}
			if tt.wantLog != "" {
				found := false
				for _, log := range tl.Logs {
					//t.Log(log)
					found = strings.Contains(log, tt.wantLog)
					if found {
						break
					}
				}
				if !found {
					t.Errorf("NewEngine() wantLog %v not found", tt.wantLog)
				}
			}
		})
	}
}

type TestLogHandler struct {
	mu    sync.Mutex
	Logs  []string
	attrs []slog.Attr
}

func (h *TestLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *TestLogHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Logs = append(h.Logs, record.Level.String()+": "+record.Message+" -- "+fmt.Sprint(h.attrs))
	h.attrs = nil
	return nil
}

func (h *TestLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.attrs = attrs
	return h
}

func (h *TestLogHandler) WithGroup(string) slog.Handler {
	// add if needed
	return h
}
