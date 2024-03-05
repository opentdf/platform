package opa

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"

	opalog "github.com/open-policy-agent/opa/logging"
)

// compile fail if opa Logger changes interface
var _ opalog.Logger = &AdapterSlogger{}

func TestNewEngine(t *testing.T) {
	var tl = TestLogHandler{}
	type args struct {
		config Config
	}
	tests := []struct {
		name       string
		args       args
		want       *Engine
		wantLog    string
		logHandler *TestLogHandler
		wantErr    bool
	}{
		{
			name: "simple",
			args: args{
				config: Config{
					Path:     "",
					Embedded: true,
					Logger:   slog.New(&tl),
				},
			},
			want:       &Engine{},
			wantLog:    "Download starting.",
			logHandler: &tl,
			wantErr:    false,
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
				for _, log := range tl.Logs() {
					// t.Log(log)
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
	logs  []string
	attrs []slog.Attr
}

func (h *TestLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *TestLogHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logs = append(h.logs, record.Level.String()+": "+record.Message+" -- "+fmt.Sprint(h.attrs))
	h.attrs = nil
	return nil
}

func (h *TestLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.attrs = attrs
	return h
}

func (h *TestLogHandler) WithGroup(string) slog.Handler {
	// add if needed
	return h
}

func (h *TestLogHandler) Logs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.logs
}
