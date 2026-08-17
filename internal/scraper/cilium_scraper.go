package scraper

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// CiliumScraperConfig configures CiliumScraper.
type CiliumScraperConfig struct {
	Logger               *slog.Logger
	Endpoint             string
	EnqueueLearningEvent LearningEnqueueFunc
}

// CiliumScraper is the controller-side learning scraper for Cilium.
//
// Stub implementation: it only wires lifecycle management and logging,
// without connecting to Hubble yet.
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
			if flowErr := s.processFlow(ctx, innerClient); flowErr != nil {
				return flowErr
			}
		}
	}
}

func (s *CiliumScraper) processFlow(
	ctx context.Context,
	client hubbleObserver.Observer_GetFlowsClient,
) error {
	flow, recvErr := client.Recv()
	if recvErr != nil {
		if recvErr.Error() == "EOF" {
			return nil
		}
		return fmt.Errorf("error receiving flow from Hubble: %w", recvErr)
	}

	flowInfo := flow.GetFlow()
	if flowInfo == nil {
		s.Logger.WarnContext(ctx, "found empty flow")
		return nil
	}

	isReply := flowInfo.GetIsReply()
	if isReply == nil ||
		isReply.GetValue() ||
		flowInfo.GetVerdict() == hubbleObserver.Verdict_DROPPED {
		// For now we ignore reply flows, as they are not relevant for learning traffic for k8s network policies.
		// We ignore as well dropped flows, since we will use them for violations.
		return nil
	}

	// this means that we will see the same flow multiple times with different TCP flags.
	// example:
	//	1. SYN
	//	2. ACK, ACK/PSH
	//	3. FIN
	//  4. ACK
	// this is probably not ideal but acceptable for now.

	var srcIdentity string
	if src := flowInfo.GetSource(); src != nil {
		srcIdentity = strconv.FormatUint(uint64(src.GetIdentity()), 10)
	}

	var dstNamespace, dstName string
	if dst := flowInfo.GetDestination(); dst != nil {
		dstNamespace = dst.GetNamespace()
		dstName = dst.GetPodName()
	}

	var dstPort string
	if l4 := flowInfo.GetL4(); l4 != nil {
		switch {
		case l4.GetTCP() != nil:
			dstPort = strconv.FormatUint(uint64(l4.GetTCP().GetDestinationPort()), 10)
		case l4.GetUDP() != nil:
			dstPort = strconv.FormatUint(uint64(l4.GetUDP().GetDestinationPort()), 10)
		case l4.GetSCTP() != nil:
			dstPort = strconv.FormatUint(uint64(l4.GetSCTP().GetDestinationPort()), 10)
		}
	}

	if dstName == "" || dstNamespace == "" || dstPort == "" || srcIdentity == "" {
		return nil
	}

	// We send the learning event to the controller. The controller will deduplicate the events.
	if !s.EnqueueLearningEvent(types.LearningEvent{
		Source: &securityv1alpha1.WorkloadRef{Identity: srcIdentity},
		Dest: &securityv1alpha1.WorkloadRef{
			Namespace: dstNamespace,
			OwnerName: dstName,
		},
		DstPort: dstPort,
	}) {
		// todo!: we can consider some rate limiting here
		s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
	}

	// flow.GetFlow().Source.

	s.Logger.InfoContext(ctx, "Received flow from Hubble", "flow", flow)
	return nil
}
