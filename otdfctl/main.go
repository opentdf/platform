package main

import (
	"log/slog"
	"os"
	"strings"

	"github.com/opentdf/platform/otdfctl/cmd"
)

func main() {
	// f, err := os.Create("cpu.pprof")
	// if err != nil {
	// 	panic(err)
	// }
	// pprof.StartCPUProfile(f)
	// defer pprof.StopCPUProfile()

	l := new(slog.LevelVar)
	l.Set(slog.LevelInfo)
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		l.Set(slog.LevelDebug)
	case "info":
		l.Set(slog.LevelInfo)
	case "warn":
		l.Set(slog.LevelWarn)
	case "error":
		l.Set(slog.LevelError)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: l,
	}))

	slog.SetDefault(logger)

	cmd.Execute()
}
