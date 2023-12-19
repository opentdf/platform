package opa

import (
	"bytes"
	"context"
	"os"

	"github.com/open-policy-agent/opa/hooks"
	opalog "github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/sdk"
)

type Engine struct {
	*sdk.OPA
}

type Config struct {
	Path     string        `yaml:"path" default:"./opentdf-opa.yaml"`
	Embedded bool          `yaml:"embedded" default:"false"`
	Logging  LoggingConfig `yaml:"logging"`
}

type LoggingConfig struct {
	Level  string `yaml:"level" default:"info"`
	Output string `yaml:"output" default:"stdout"`
}

func NewEngine(config Config) (*Engine, error) {
	var (
		err     error
		bConfig []byte
		mock    *mockBundleServer
	)

	if config.Embedded {
		mock, err = createMockServer()
		if err != nil {
			return nil, err
		}
	}

	if config.Embedded {
		bConfig = mock.config
	} else {
		bConfig, err = os.ReadFile(config.Path)
		if err != nil {
			return nil, err
		}
	}

	logger := newStandardLogger(config.Logging)

	opa, err := sdk.New(context.Background(), sdk.Options{
		Config:        bytes.NewReader(bConfig),
		Logger:        logger,
		ConsoleLogger: logger,
		ID:            "opentdf",
		Ready:         nil,
		Store:         nil,
		Hooks:         hooks.Hooks{},
	})
	if err != nil {
		return nil, err
	}

	return &Engine{
		OPA: opa,
	}, nil
}

func newStandardLogger(c LoggingConfig) *opalog.StandardLogger {
	opalogger := opalog.New()

	switch c.Level {
	case "debug":
		opalogger.SetLevel(opalog.Debug)
	case "info":
		opalogger.SetLevel(opalog.Info)
	case "error":
		opalogger.SetLevel(opalog.Error)
	default:
		opalogger.SetLevel(opalog.Info)
	}

	switch c.Output {
	case "stdout":
		opalogger.SetOutput(os.Stdout)
	default:
		opalogger.SetOutput(os.Stdout)
	}
	return opalogger
}
