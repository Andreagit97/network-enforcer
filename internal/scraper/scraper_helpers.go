package scraper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	retry "github.com/avast/retry-go/v4"
)

func isContextCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func runStreamWithReconnect(
	ctx context.Context,
	logger *slog.Logger,
	name string,
	stream func(context.Context, *bool) error,
) error {
	const (
		reconnectMinBackoff         = 1 * time.Second
		reconnectMaxBackoff         = 30 * time.Second
		maxConsecutiveFailures uint = 5
	)
	for {
		successfulConnection := false
		err := retry.Do(
			func() error {
				return stream(ctx, &successfulConnection)
			},
			retry.Context(ctx),
			retry.Attempts(maxConsecutiveFailures),
			retry.Delay(reconnectMinBackoff),
			retry.DelayType(retry.BackOffDelay),
			retry.MaxDelay(reconnectMaxBackoff),
			retry.RetryIf(func(err error) bool {
				if isContextCancellation(err) ||
					successfulConnection {
					// every time we stop a successful stream, we will do a fresh retry
					return false
				}
				return true
			}),
			retry.OnRetry(func(n uint, retryErr error) {
				logger.WarnContext(ctx, name+" scraper stream failed before processing flows, retrying",
					"attempt", n+1,
					"maxAttempts", maxConsecutiveFailures,
					"error", retryErr,
				)
			}),
		)
		if isContextCancellation(err) || ctx.Err() != nil {
			break
		}
		if !successfulConnection {
			return fmt.Errorf("%s scraper stopped after %d consecutive failures: %w",
				strings.ToLower(name), maxConsecutiveFailures, err)
		}
		// The stream was interrupted after a successful connection: back off
		logger.WarnContext(ctx, name+" scraper stream connection was interrupted, retrying",
			"error", err,
		)
		select {
		case <-ctx.Done():
			logger.InfoContext(ctx, name+" scraper shutting down due to context cancel")
			return nil
		case <-time.After(reconnectMinBackoff):
			continue
		}
	}
	logger.InfoContext(ctx, name+" scraper shutting down due to context cancel")
	//nolint:nilerr // ignore context cancellation errors
	return nil
}
