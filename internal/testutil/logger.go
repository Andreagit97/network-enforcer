package testutil

import (
	"log/slog"
	"testing"
)

// NewTestLogger returns an [slog.Logger] that writes to t.Logf.
func NewTestLogger(t testing.TB) *slog.Logger {
	return slog.New(slog.NewJSONHandler(t.Output(), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("component", t.Name())
}
