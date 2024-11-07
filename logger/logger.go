package logger

import (
	"log/slog"
	"os"
)

type Logger struct{}

func New(lvl slog.Level) *slog.Logger {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug, // Set log level to DEBUG
	})

	return slog.New(handler)
}
