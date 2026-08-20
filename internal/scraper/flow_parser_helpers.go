package scraper

import (
	"context"
	"errors"
	"fmt"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	errUnsupportedProtocol   = errors.New("unsupported protocol")
	errEndpointHasNoWorkload = errors.New("endpoint has no associated workload")
	errSkipWorkload          = errors.New("endpoint has no supported workload")
)

type processFlowOutcome int

const (
	processFlowOutcomeSkip processFlowOutcome = iota
	processFlowOutcomeEnqueue
	processFlowOutcomeError
)

type processFlowResult struct {
	outcome processFlowOutcome
	event   types.LearningEvent
	err     error
}

func processFlowSkip() processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeSkip}
}

func processFlowEnqueue(event types.LearningEvent) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeEnqueue, event: event}
}

func processFlowError(err error) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeError, err: err}
}

func resolveOutcome(role string, err error) processFlowResult {
	if errors.Is(err, errSkipWorkload) {
		return processFlowSkip()
	}
	return processFlowError(fmt.Errorf("cannot resolve %s workload: %w", role, err))
}

func resolveParsedFlow(
	ctx context.Context,
	resolve func(context.Context, *securityv1alpha1.WorkloadRef) error,
	parsed processFlowResult,
) processFlowResult {
	if parsed.outcome != processFlowOutcomeEnqueue {
		return parsed
	}
	if err := resolve(ctx, parsed.event.Source); err != nil {
		return resolveOutcome("source", err)
	}
	if err := resolve(ctx, parsed.event.Dest); err != nil {
		return resolveOutcome("destination", err)
	}
	return parsed
}

func completeSelector(ctx context.Context, c client.Client, ref *securityv1alpha1.WorkloadRef) error {
	if err := workload.LookupPodSelectorForWorkload(ctx, c, ref); err != nil {
		return fmt.Errorf("failed to lookup pod selector for workload %q: %w", ref.OwnerName, err)
	}
	return nil
}
