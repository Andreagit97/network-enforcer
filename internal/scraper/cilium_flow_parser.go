package scraper

import (
	"context"
	"errors"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
	corev1 "k8s.io/api/core/v1"
)

var errEndpointHasNoWorkload = errors.New("endpoint has no associated workload")
var errUnsupportedProtocol = errors.New("unsupported protocol")

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

func convertCiliumKindToSecurityWorkloadKind(kind string) securityv1alpha1.WorkloadKind {
	// Today Cilium is following the same naming we use ("Deployment", "StatefulSet", "DaemonSet")
	// so no need of extra conversion for types.
	return securityv1alpha1.WorkloadKind(kind)
}

func fromEndpointToWorkloadRef(endpoint *hubbleObserver.Endpoint) (*securityv1alpha1.WorkloadRef, error) {
	if endpoint == nil {
		return nil, errors.New("endpoint is nil")
	}

	if len(endpoint.GetWorkloads()) == 0 {
		// in case of host connections or connections to the api server we usually don't have a workload associated.
		// For now we will skip those cases.
		// Examples:
		// "source":{"identity":1,"labels":["reserved:host"]}
		// "source":{"identity":1,"labels":["reserved:host","reserved:kube-apiserver"]}
		return nil, errEndpointHasNoWorkload
	}

	if len(endpoint.GetWorkloads()) > 1 {
		return nil, fmt.Errorf("endpoint should have only one workload, got %d. workloads: %v",
			len(endpoint.GetWorkloads()), endpoint.GetWorkloads())
	}

	parsedWorkload := endpoint.GetWorkloads()[0]

	return &securityv1alpha1.WorkloadRef{
		Namespace: endpoint.GetNamespace(),
		OwnerName: parsedWorkload.GetName(),
		OwnerKind: convertCiliumKindToSecurityWorkloadKind(parsedWorkload.GetKind()),
		Identity:  "", // we don't need it for Cilium
		// we will compute the selector only if the workload is supported.
	}, nil
}

func discardFlow(flowInfo *flowpb.Flow) bool {
	isReply := flowInfo.GetIsReply()
	// For now we ignore reply flows, as they are not relevant for learning traffic for k8s network policies.
	// We ignore as well dropped flows, since we will use them for violations.
	// this means that we will see the same flow multiple times with different TCP flags.
	// example:
	//	1. SYN
	//	2. ACK, ACK/PSH
	//	3. FIN
	//  4. ACK
	// this is probably not ideal but acceptable for now.
	return isReply == nil || isReply.GetValue() || flowInfo.GetVerdict() == hubbleObserver.Verdict_DROPPED
}

func extractPortAndProtocol(flowInfo *flowpb.Flow) (uint32, corev1.Protocol, error) {
	layer4 := flowInfo.GetL4()
	if layer4 == nil {
		return 0, "", errors.New("found flow with nil layer4")
	}
	var dstPort uint32
	var proto corev1.Protocol
	switch layer4.GetProtocol().(type) {
	case *flowpb.Layer4_TCP:
		proto = corev1.ProtocolTCP
		dstPort = layer4.GetTCP().GetDestinationPort()
	case *flowpb.Layer4_UDP:
		proto = corev1.ProtocolUDP
		dstPort = layer4.GetUDP().GetDestinationPort()
	default:
		return 0, "", fmt.Errorf("%w: %T", errUnsupportedProtocol, layer4.GetProtocol())
	}
	return dstPort, proto, nil
}

func parseCiliumFlowResponse(flow *flowpb.Flow) processFlowResult {
	if discardFlow(flow) {
		return processFlowSkip()
	}

	dstPort, proto, err := extractPortAndProtocol(flow)
	if err != nil {
		if errors.Is(err, errUnsupportedProtocol) {
			return processFlowSkip()
		}
		return processFlowError(err)
	}

	sourceWorkload, err := fromEndpointToWorkloadRef(flow.GetSource())
	if err != nil {
		if errors.Is(err, errEndpointHasNoWorkload) {
			return processFlowSkip()
		}
		return processFlowError(fmt.Errorf("cannot get source workload: %w", err))
	}
	if !sourceWorkload.IsSupported() {
		return processFlowSkip()
	}

	destWorkload, err := fromEndpointToWorkloadRef(flow.GetDestination())
	if err != nil {
		if errors.Is(err, errEndpointHasNoWorkload) {
			return processFlowSkip()
		}
		return processFlowError(fmt.Errorf("cannot get destination workload: %w", err))
	}
	if !destWorkload.IsSupported() {
		return processFlowSkip()
	}

	return processFlowEnqueue(types.LearningEvent{
		Source:   sourceWorkload,
		Dest:     destWorkload,
		DstPort:  int(dstPort),
		Protocol: proto,
		Backend:  securityv1alpha1.PolicyBackendKubernetes,
	})
}

func (s *CiliumScraper) processFlowResponse(
	ctx context.Context,
	flow *flowpb.Flow,
) processFlowResult {
	parsed := parseCiliumFlowResponse(flow)
	if parsed.outcome != processFlowOutcomeEnqueue {
		return parsed
	}

	if err := workload.LookupPodSelectorForWorkload(ctx, s.Client, parsed.event.Source); err != nil {
		return processFlowError(fmt.Errorf("failed to lookup pod selector for source workload: %w", err))
	}

	if err := workload.LookupPodSelectorForWorkload(ctx, s.Client, parsed.event.Dest); err != nil {
		return processFlowError(fmt.Errorf("failed to lookup pod selector for destination workload: %w", err))
	}

	return parsed
}

func (s *CiliumScraper) processFlow(
	ctx context.Context,
	flow *hubbleObserver.GetFlowsResponse,
) processFlowResult {
	if flow == nil {
		return processFlowError(errors.New("found nil flow"))
	}

	switch flow.GetResponseTypes().(type) {
	case *hubbleObserver.GetFlowsResponse_Flow:
		flowResponse := flow.GetFlow()
		if flowResponse == nil {
			return processFlowError(errors.New("found nil response flow"))
		}
		return s.processFlowResponse(ctx, flowResponse)
	case *hubbleObserver.GetFlowsResponse_LostEvents:
		flowLost := flow.GetLostEvents()
		if flowLost == nil {
			return processFlowError(errors.New("found nil flow lost event"))
		}
		s.Logger.WarnContext(ctx, "Hubble lost events",
			"count", flowLost.GetNumEventsLost(),
			"source", flowLost.GetSource(),
		)
		return processFlowSkip()
	case *hubbleObserver.GetFlowsResponse_NodeStatus:
		return processFlowSkip()
	default:
		return processFlowSkip()
	}
}
