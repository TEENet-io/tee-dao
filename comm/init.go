package comm

import (
	"errors"
	"log/slog"
)

var logLvl = slog.LevelInfo

func SetLogLevel(lvl string) error {
	switch lvl {
	case "debug":
		logLvl = slog.LevelDebug
	case "info":
		logLvl = slog.LevelInfo
	case "warn":
		logLvl = slog.LevelWarn
	case "error":
		logLvl = slog.LevelError
	default:
		return errors.New("invalid log level")
	}

	return nil
}
