package flowdumper

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/ringbuf"
)

type Dumper struct {
	Buffer *ringbuf.Buffer[json.RawMessage]
	Logger *slog.Logger
	server *http.Server
}

func New(
	buffer *ringbuf.Buffer[json.RawMessage],
	logger *slog.Logger,
	port int,
) *Dumper {
	mux := http.NewServeMux()
	mux.HandleFunc("/flow", func(w http.ResponseWriter, r *http.Request) {
		records := buffer.Drain()
		w.Header().Set("Content-Type", "application/jsonl")
		for _, rec := range records {
			if _, err := w.Write(rec); err != nil {
				logger.ErrorContext(r.Context(), "failed to write flow debug record", "error", err)
				return
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				logger.ErrorContext(r.Context(), "failed to write newline", "error", err)
				return
			}
		}
	})
	const readHeaderTimeout = 5 * time.Second
	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", port),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	return &Dumper{Buffer: buffer, Logger: logger, server: server}
}

func (d *Dumper) Start(ctx context.Context) error {
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- d.server.ListenAndServe()
	}()

	select {
	case err := <-serveErrCh:
		if err != nil {
			return fmt.Errorf("flow dumper server error: %w", err)
		}
		return nil
	case <-ctx.Done():
		err := d.server.Close()
		if err != nil {
			return fmt.Errorf("failed to close flow dumper server: %w", err)
		}
		return nil
	}
}
