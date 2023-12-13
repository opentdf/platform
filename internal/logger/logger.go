package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

type Logger struct {
	*slog.Logger
	config Config
}

type Config struct {
	Level  string `yaml:"level" default:"info"`
	Output string `yaml:"output" default:"stdout"`
	Type   string `yaml:"type" default:"json"`
}

func NewLogger(config Config) (*Logger, error) {
	var logger *slog.Logger

	w, err := getWriter(config)
	if err != nil {
		return nil, err
	}

	level, err := getLevel(config)
	if err != nil {
		return nil, err
	}

	switch config.Type {
	case "json":
		j := slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level: level,
		})
		logger = slog.New(j)
	case "text":
		t := slog.NewTextHandler(w, &slog.HandlerOptions{
			Level: level,
		})
		logger = slog.New(t)
	default:
		return nil, fmt.Errorf("invalid logger type: %s", config.Type)
	}
	return &Logger{
		Logger: logger,
	}, nil
}

// Was trying to pass in the logger to the opa engine but it isn't that simple.

// func (l Logger) GetLevel() opalog.Level {
// 	switch l.config.Level {
// 	case "debug":
// 		return opalog.Debug
// 	case "info":
// 		return opalog.Info
// 	case "error":
// 		return opalog.Error
// 	default:
// 		return opalog.Info
// 	}
// }

// func (l Logger) SetLevel(opalog.Level) {
// 	// Don't let opa override our log level
// }

// func (l *Logger) WithFields(fields map[string]interface{}) opalog.Logger {
// 	newLogger := *l
// 	for k, v := range fields {
// 		newLogger.With(slog.Any(k, v))
// 	}
// 	return &newLogger
// }

func getWriter(config Config) (io.Writer, error) {
	switch config.Output {
	case "stdout":
		return os.Stdout, nil
	default:
		return nil, fmt.Errorf("invalid logger output: %s", config.Output)
	}
}

func getLevel(config Config) (slog.Leveler, error) {
	switch config.Level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "error":
		return slog.LevelError, nil
	default:
		return nil, fmt.Errorf("invalid logger level: %s", config.Level)
	}
}
