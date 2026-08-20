package scraper

import (
	"context"
	"fmt"
	"log/slog"

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

func (s *CiliumScraper) newHubbleClient() (hubbleObserver.ObserverClient, error) {
	conn, err := grpc.NewClient(
		s.Endpoint,
		// todo!: support TLS with hubble-relay
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to connect to Hubble: %w", err)
	}

	client := hubbleObserver.NewObserverClient(conn)
	return client, nil
}

func (s *CiliumScraper) Start(ctx context.Context) error {
	s.Logger.InfoContext(ctx, "Starting Cilium scraper")

	client, err := s.newHubbleClient()
	if err != nil {
		return fmt.Errorf("failed to create Hubble client: %w", err)
	}

	req := &hubbleObserver.GetFlowsRequest{
		Number:    0,
		Follow:    true,
		Whitelist: []*flowpb.FlowFilter{},
	}
	// todo!: handle multiple retries.
	innerClient, err := client.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get flows from Hubble: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			s.Logger.InfoContext(ctx, "Cilium scraper shutting down due to context cancel")
			return nil
		default:
			flow, recvErr := innerClient.Recv()
			if recvErr != nil {
				if recvErr.Error() == "EOF" {
					return nil
				}
				return fmt.Errorf("error receiving flow from Hubble: %w", recvErr)
			}
			result := s.processFlow(ctx, flow)
			switch result.outcome {
			case processFlowOutcomeSkip:
				continue
			case processFlowOutcomeError:
				s.Logger.ErrorContext(ctx, "failed to process flow",
					"flow", flow,
					"error", result.err)
				continue
			case processFlowOutcomeEnqueue:
				if !s.EnqueueLearningEvent(result.event) {
					// todo!: we can consider some rate limiting here
					s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
				}
			default:
				s.Logger.ErrorContext(ctx, "failed to process flow", "flow", flow, "error", "unknown flow outcome")
			}
		}
	}
}
