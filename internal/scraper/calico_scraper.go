package scraper

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	pb "github.com/rancher-sandbox/network-enforcer/internal/scraper/goldmane"
	"github.com/rancher-sandbox/network-enforcer/internal/tlsutil"
	"google.golang.org/grpc"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	calicoAggregationInterval = 15
	goldmaneCertDir           = "/etc/goldmane/certs"
)

type CalicoScraperConfig struct {
	client.Client

	Endpoint             string
	EnqueueLearningEvent LearningEnqueueFunc
	Logger               *slog.Logger
}

type CalicoScraper struct {
	CalicoScraperConfig
}

func NewCalicoScraper(conf CalicoScraperConfig) *CalicoScraper {
	return &CalicoScraper{CalicoScraperConfig: conf}
}

func (s *CalicoScraper) Start(ctx context.Context) error {
	defer s.Logger.InfoContext(ctx, "calico scraper has stopped")
	s.Logger.InfoContext(ctx, "Starting Calico scraper")
	return runStreamWithReconnect(ctx, s.Logger, "Calico", s.stream)
}

func (s *CalicoScraper) newGoldmaneClient(ctx context.Context) (*grpc.ClientConn, error) {
	serverName, _, err := net.SplitHostPort(s.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid Goldmane endpoint %q: %w", s.Endpoint, err)
	}
	creds, err := tlsutil.ClientCredentials(goldmaneCertDir, serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS credentials for Goldmane: %w", err)
	}
	s.Logger.InfoContext(ctx, "Using TLS credentials for Goldmane connection")

	conn, connErr := grpc.NewClient(s.Endpoint, grpc.WithTransportCredentials(creds))
	if connErr != nil {
		return nil, fmt.Errorf("failed to connect to Goldmane: %w", connErr)
	}
	return conn, nil
}

func (s *CalicoScraper) stream(ctx context.Context, successfulConnection *bool) error {
	*successfulConnection = false
	conn, err := s.newGoldmaneClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Goldmane client: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			s.Logger.WarnContext(ctx, "Failed to close Goldmane connection", "error", closeErr)
		}
	}()

	req := &pb.FlowStreamRequest{
		StartTimeGte: 0,
		Filter: &pb.Filter{
			Actions: []pb.Action{pb.Action_Allow},
		},
		AggregationInterval: calicoAggregationInterval,
	}

	s.Logger.InfoContext(ctx, "Starting to watch Calico allowed flows from Goldmane")
	innerClient, err := pb.NewFlowsClient(conn).Stream(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to stream flows from Goldmane: %w", err)
	}

	for {
		flowResult, recvErr := innerClient.Recv()
		if recvErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("error receiving flow from Goldmane: %w", recvErr)
		}
		*successfulConnection = true

		result := resolveParsedFlow(ctx, s.resolve, nil, parseCalicoFlow(flowResult))
		//nolint:exhaustive // implement `processFlowOutcomeViolation`
		switch result.outcome {
		case processFlowOutcomeSkip:
			// nothing; continue
		case processFlowOutcomeError:
			s.Logger.ErrorContext(ctx, "Failed to process flow",
				"flow", flowResult,
				"error", result.err,
			)
		case processFlowOutcomeEnqueue:
			if !s.EnqueueLearningEvent(result.event) {
				s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
			}
		default:
			s.Logger.ErrorContext(ctx, "Failed to process flow",
				"flow", flowResult,
				"error", "unknown flow outcome",
			)
		}
	}
}
