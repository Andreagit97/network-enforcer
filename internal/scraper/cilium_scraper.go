package scraper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	retry "github.com/avast/retry-go/v4"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CiliumScraperConfig struct {
	client.Client

	Logger               *slog.Logger
	Endpoint             string
	EnqueueLearningEvent LearningEnqueueFunc
}

type CiliumScraper struct {
	CiliumScraperConfig
}

// NewCiliumScraper creates a Cilium learning scraper.
func NewCiliumScraper(conf CiliumScraperConfig) *CiliumScraper {
	return &CiliumScraper{CiliumScraperConfig: conf}
}

func (s *CiliumScraper) newHubbleClient() (hubbleObserver.ObserverClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		s.Endpoint,
		// todo!: support TLS with hubble-relay
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Hubble: %w", err)
	}

	client := hubbleObserver.NewObserverClient(conn)
	return client, conn, nil
}

func (s *CiliumScraper) Start(ctx context.Context) error {
	s.Logger.InfoContext(ctx, "Starting Cilium scraper")

	const (
		ciliumReconnectMinBackoff         = 1 * time.Second
		ciliumReconnectMaxBackoff         = 30 * time.Second
		ciliumMaxConsecutiveFailures uint = 5
	)

	isContextCancellation := func(err error) bool {
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}

	for {
		successfulConnection := false
		err := retry.Do(
			func() error {
				return s.stream(ctx, &successfulConnection)
			},
			retry.Context(ctx),
			retry.Attempts(ciliumMaxConsecutiveFailures),
			retry.Delay(ciliumReconnectMinBackoff),
			retry.DelayType(retry.BackOffDelay),
			retry.MaxDelay(ciliumReconnectMaxBackoff),
			retry.RetryIf(func(err error) bool {
				if isContextCancellation(err) ||
					successfulConnection {
					// every time we stop a successful stream, we will do a fresh retry.
					return false
				}
				return true
			}),
			retry.OnRetry(func(n uint, retryErr error) {
				s.Logger.WarnContext(ctx, "Cilium scraper stream failed before processing flows, retrying",
					"attempt", n+1,
					"maxAttempts", ciliumMaxConsecutiveFailures,
					"error", retryErr,
				)
			}),
		)

		if isContextCancellation(err) || ctx.Err() != nil {
			s.Logger.InfoContext(ctx, "Cilium scraper shutting down due to context cancel")
			//nolint:nilerr // ignore context cancellation errors
			return nil
		}

		if !successfulConnection {
			return fmt.Errorf("cilium scraper stopped after %d consecutive failures: %w",
				ciliumMaxConsecutiveFailures, err)
		}
		// if we have a failure after a success we just retry again waiting a min backoff
		s.Logger.WarnContext(ctx, "Cilium scraper stream connection was interrupted, retrying",
			"error", err,
		)
		time.Sleep(ciliumReconnectMinBackoff)
	}
}

func (s *CiliumScraper) stream(ctx context.Context, successfulConnection *bool) error {
	*successfulConnection = false
	client, conn, err := s.newHubbleClient()
	if err != nil {
		return fmt.Errorf("failed to create Hubble client: %w", err)
	}
	defer conn.Close()

	req := &hubbleObserver.GetFlowsRequest{
		Number:    0,
		Follow:    true,
		Whitelist: []*flowpb.FlowFilter{},
	}
	innerClient, err := client.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get flows from Hubble: %w", err)
	}

	for {
		flow, recvErr := innerClient.Recv()
		if recvErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("error receiving flow from Hubble: %w", recvErr)
		}
		*successfulConnection = true

		result := s.processFlow(ctx, flow)
		switch result.outcome {
		case processFlowOutcomeSkip:
			// nothing; continue
		case processFlowOutcomeError:
			s.Logger.ErrorContext(ctx, "Failed to process flow",
				"flow", flow,
				"error", result.err,
			)
		case processFlowOutcomeEnqueue:
			if !s.EnqueueLearningEvent(result.event) {
				// todo!: we can consider some rate limiting here
				s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
			}
		default:
			s.Logger.ErrorContext(ctx, "Failed to process flow",
				"flow", flow,
				"error", "unknown flow outcome",
			)
		}
	}
}
