package scraper

import (
	"context"
	"errors"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

func convertCiliumKindToSecurityWorkloadKind(kind string) securityv1alpha1.WorkloadKind {
	// Today Cilium is following the same naming we use ("Deployment", "StatefulSet", "DaemonSet")
	// so no need of extra conversion for types.
	return securityv1alpha1.WorkloadKind(kind)
}

func handleNoWorkload(endpoint *hubbleObserver.Endpoint) (*securityv1alpha1.WorkloadRef, error) {
	// Here we have 2 possible cases
	// 1. the endpoint is a pod but hubble is not able to resolve the workload.
	// 2. the endpoint is not a pod but the local node.
	if endpoint.GetPodName() != "" {
		// This is an example where the pod is part of a deployment
		// but hubble is not able to resolve it. We return the pod here as
		// workload and we will try the resolution later.
		//
		// "destination": {
		// 	"identity": 24995,
		// 	"cluster_name": "default",
		// 	"namespace": "kube-system",
		// 	"labels": [
		// 		"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
		// 		"k8s:io.cilium.k8s.policy.cluster=default",
		// 		"k8s:io.cilium.k8s.policy.serviceaccount=coredns",
		// 		"k8s:io.kubernetes.pod.namespace=kube-system",
		// 		"k8s:k8s-app=kube-dns"
		// 	],
		// 	"pod_name": "coredns-7d764666f9-hjbxq"
		// },
		return &securityv1alpha1.WorkloadRef{
			Namespace: endpoint.GetNamespace(),
			OwnerName: endpoint.GetPodName(),
			OwnerKind: securityv1alpha1.WorkloadKindPod,
		}, nil
	}

	// in case of host connections or connections to the api server we usually don't have a workload associated.
	// For now we will skip those cases.
	// Examples:
	// "source":{"identity":1,"labels":["reserved:host"]}
	// "source":{"identity":1,"labels":["reserved:host","reserved:kube-apiserver"]}
	return nil, errEndpointHasNoWorkload
}

func fromEndpointToWorkloadRef(endpoint *hubbleObserver.Endpoint) (*securityv1alpha1.WorkloadRef, error) {
	if endpoint == nil {
		return nil, errors.New("endpoint is nil")
	}

	if len(endpoint.GetWorkloads()) == 0 {
		return handleNoWorkload(endpoint)
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
	// this means that we will see the same flow multiple times with different TCP flags.
	// example:
	//	1. SYN
	//	2. ACK, ACK/PSH
	//	3. FIN
	//  4. ACK
	// this is probably not ideal but acceptable for now.
	return isReply == nil || isReply.GetValue()
}

func violationTimestamp(flow *flowpb.Flow) metav1.Time {
	if ts := flow.GetTime(); ts != nil {
		return metav1.NewTime(ts.AsTime())
	}
	return metav1.Now()
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

func shouldSkipWorkload(workload *securityv1alpha1.WorkloadRef) bool {
	// we keep also pods here because we will handle them later
	return !workload.IsSupported() && workload.OwnerKind != securityv1alpha1.WorkloadKindPod
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
	if shouldSkipWorkload(sourceWorkload) {
		return processFlowSkip()
	}

	destWorkload, err := fromEndpointToWorkloadRef(flow.GetDestination())
	if err != nil {
		if errors.Is(err, errEndpointHasNoWorkload) {
			return processFlowSkip()
		}
		return processFlowError(fmt.Errorf("cannot get destination workload: %w", err))
	}
	if shouldSkipWorkload(destWorkload) {
		return processFlowSkip()
	}

	if flow.GetVerdict() == hubbleObserver.Verdict_DROPPED {
		// we need the direction to determine if the violation happens at the source or destination
		var direction networkingv1.PolicyType
		switch flow.GetTrafficDirection() {
		case hubbleObserver.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN:
			return processFlowError(errors.New("found violation flow with unknown traffic direction"))
		case hubbleObserver.TrafficDirection_INGRESS:
			direction = networkingv1.PolicyTypeIngress
		case hubbleObserver.TrafficDirection_EGRESS:
			direction = networkingv1.PolicyTypeEgress
		}

		observation := violation.Observation{
			Provider:  securityv1alpha1.PolicyBackendKubernetes,
			Direction: direction,
			ViolationInfo: securityv1alpha1.ViolationInfo{
				Timestamp: violationTimestamp(flow),
				Source:    *sourceWorkload,
				Dest:      *destWorkload,
				Protocol:  proto,
				DstPort:   int32(dstPort), //nolint:gosec // dstPort is always in the range 0 - 65536
				Action:    securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				// for now our policy are of ALLOW type so we never have a
				// correlation cilium-side. We will try to resolve the denying
				// policy later on in the flow
				DenyingPolicyNamespace: "",
				DenyingPolicyName:      "",
			},
		}
		return processFlowRecordViolation(observation)
	}

	return processFlowEnqueue(types.LearningEvent{
		Source:   sourceWorkload,
		Dest:     destWorkload,
		DstPort:  int(dstPort),
		Protocol: proto,
		Backend:  securityv1alpha1.PolicyBackendKubernetes,
	})
}

func (s *CiliumScraper) resolve(ctx context.Context, ref *securityv1alpha1.WorkloadRef) error {
	if ref.OwnerKind == securityv1alpha1.WorkloadKindPod {
		return s.resolvePod(ctx, ref)
	}
	return completeSelector(ctx, s.Client, ref)
}

func (s *CiliumScraper) resolveDenyingPolicy(
	ctx context.Context,
	ref *securityv1alpha1.WorkloadRef,
) (k8stypes.NamespacedName, error) {
	return workload.ResolveDenyingPolicy(ctx, s.Client, ref)
}

func (s *CiliumScraper) resolvePod(ctx context.Context, ref *securityv1alpha1.WorkloadRef) error {
	resolved, err := workload.Get(ctx, s.Client, k8stypes.NamespacedName{
		Namespace: ref.Namespace,
		Name:      ref.OwnerName,
	})
	if err != nil {
		return fmt.Errorf("failed to resolve pod %q to workload: %w", ref.OwnerName, err)
	}
	// it is possible that here we have still a pod as kind if the pod was a standalone pod
	// in this case we skip.
	if !resolved.IsSupported() {
		return errSkipWorkload
	}
	*ref = resolved
	return nil
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
		return resolveParsedFlow(ctx, s.resolve, s.resolveDenyingPolicy, parseCiliumFlowResponse(flowResponse))
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
