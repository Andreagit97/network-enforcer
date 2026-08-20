package scraper

import (
	"context"
	"errors"
	"fmt"
	"strings"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	pb "github.com/rancher-sandbox/network-enforcer/internal/scraper/goldmane"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
	corev1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	minValidPort = 1
	maxValidPort = 65535
)

func parseCalicoFlow(flowResult *pb.FlowResult) processFlowResult {
	if flowResult == nil {
		return processFlowError(errors.New("found nil flow result"))
	}
	flow := flowResult.GetFlow()
	if flow == nil {
		return processFlowError(errors.New("found empty flow"))
	}
	key := flow.GetKey()
	if discardCalicoFlow(key) {
		return processFlowSkip()
	}

	dstPort, proto, err := extractCalicoPortAndProtocol(key)
	if err != nil {
		if errors.Is(err, errUnsupportedProtocol) {
			return processFlowSkip()
		}
		return processFlowError(err)
	}

	return processFlowEnqueue(types.LearningEvent{
		Source: &securityv1alpha1.WorkloadRef{
			Namespace: key.GetSourceNamespace(),
			OwnerName: key.GetSourceName(),
		},
		Dest: &securityv1alpha1.WorkloadRef{
			Namespace: key.GetDestNamespace(),
			OwnerName: key.GetDestName(),
		},
		DstPort:  int(dstPort),
		Protocol: proto,
		Backend:  securityv1alpha1.PolicyBackendKubernetes,
	})
}

func discardCalicoFlow(key *pb.FlowKey) bool {
	if key == nil {
		return true
	}
	if key.GetAction() != pb.Action_Allow {
		return true
	}
	if key.GetReporter() != pb.Reporter_Dst {
		return true
	}
	if key.GetSourceType() != pb.EndpointType_WorkloadEndpoint {
		return true
	}
	if key.GetDestType() != pb.EndpointType_WorkloadEndpoint {
		return true
	}
	if key.GetSourceName() == "" || key.GetSourceNamespace() == "" {
		return true
	}
	if key.GetDestName() == "" || key.GetDestNamespace() == "" {
		return true
	}
	port := key.GetDestPort()
	return port < minValidPort || port > maxValidPort
}

func extractCalicoPortAndProtocol(key *pb.FlowKey) (int64, corev1.Protocol, error) {
	switch strings.ToUpper(key.GetProto()) {
	case string(corev1.ProtocolTCP):
		return key.GetDestPort(), corev1.ProtocolTCP, nil
	case string(corev1.ProtocolUDP):
		return key.GetDestPort(), corev1.ProtocolUDP, nil
	default:
		return 0, "", fmt.Errorf("%w: %s", errUnsupportedProtocol, key.GetProto())
	}
}

// resolve maps a Goldmane aggregated name on ref into a supported WorkloadRef.
// OwnerName is GenerateName+"*" (for example "http-client-abc123-*"). A name
// without that suffix is a standalone pod, which we skip.
func (s *CalicoScraper) resolve(ctx context.Context, ref *securityv1alpha1.WorkloadRef) error {
	ownerName, ok := strings.CutSuffix(ref.OwnerName, "-*")
	if !ok || ownerName == "" {
		return errSkipWorkload
	}
	resolved, err := s.resolvePod(ctx, ref.Namespace, ownerName)
	if err != nil {
		return err
	}
	if !resolved.IsSupported() {
		return errSkipWorkload
	}
	*ref = resolved
	return nil
}

func (s *CalicoScraper) resolvePod(
	ctx context.Context,
	namespace, ownerName string,
) (securityv1alpha1.WorkloadRef, error) {
	generateName := ownerName + "-"
	var pods corev1.PodList
	if err := s.Client.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return securityv1alpha1.WorkloadRef{}, err
	}
	for idx := range pods.Items {
		pod := &pods.Items[idx]
		if pod.GenerateName != generateName && !strings.HasPrefix(pod.Name, generateName) {
			continue
		}
		return workload.Get(ctx, s.Client, k8stypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name})
	}
	return securityv1alpha1.WorkloadRef{}, nil
}
