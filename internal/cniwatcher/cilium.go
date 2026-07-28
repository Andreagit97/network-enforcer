package cniwatcher

import (
	"errors"
	"fmt"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	monitorApi "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CiliumWatcher struct {
	Watcher

	ConnEndpoint string
	Client       hubbleObserver.ObserverClient
	conn         *grpc.ClientConn
}

func NewCiliumWatcher(watcher Watcher, connEndpoint string) (*CiliumWatcher, error) {
	return &CiliumWatcher{Watcher: watcher, ConnEndpoint: connEndpoint}, nil
}

func (w *CiliumWatcher) Start() error {
	w.Log.Info("Starting Cilium cniWatcher")

	return w.RetryConnectAndWatchFlows(
		w.ConnectToHubble,
		func() error {
			if w.conn != nil && w.Client != nil {
				return w.WatchFlows()
			}
			return errors.New("not connected to Hubble")
		},
		"Cilium cniWatcher",
	)
}

func (w *CiliumWatcher) ConnectToHubble() error {
	conn, err := grpc.NewClient(
		w.ConnEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		return fmt.Errorf("failed to connect to Hubble: %w", err)
	}

	w.conn = conn
	w.Client = hubbleObserver.NewObserverClient(conn)
	w.Log.Info("Successfully connected to Hubble", "endpoint", w.ConnEndpoint)

	return nil
}

func (w *CiliumWatcher) WatchFlows() error {
	req := &hubbleObserver.GetFlowsRequest{
		Number: 0,
		Follow: true,
		Whitelist: []*flowpb.FlowFilter{
			{
				EventType: []*flowpb.EventTypeFilter{
					{Type: monitorApi.MessageTypePolicyVerdict},
				},
				DropReasonDesc: []flowpb.DropReason{
					flowpb.DropReason_POLICY_DENIED,
					flowpb.DropReason_POLICY_DENY,
				},
			},
		},
	}

	w.Log.Info("Starting to watch Cilium policy deny events from Hubble")
	client, err := w.Client.GetFlows(w.Ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get flows from Hubble: %w", err)
	}

	for {
		select {
		case <-w.Ctx.Done():
			w.Log.Info("Cilium cniWatcher shutting down due to context cancel")
			return nil
		default:
			if flowErr := w.processFlow(client); flowErr != nil {
				return flowErr
			}
		}
	}
}

func (w *CiliumWatcher) processFlow(client hubbleObserver.Observer_GetFlowsClient) error {
	flow, recvErr := client.Recv()
	if recvErr != nil {
		if recvErr.Error() == "EOF" {
			return nil
		}
		return fmt.Errorf("error receiving flow from Hubble: %w", recvErr)
	}

	event, parseErr := w.parsePolicyDenyEvent(flow)
	if parseErr != nil {
		w.Log.Error("failed to parse policy deny event", "flow", flow, "err", parseErr)
		return nil
	}
	if processErr := w.ProcessPolicyDenyEvent(event); processErr != nil {
		w.Log.Error("failed to process policy deny event", "event", event, "err", processErr)
	}
	return nil
}

// parsePolicyDenyEvent parses Cilium Hubble flow and extracts policy deny events.
// It processes flow response and filters for flows with "POLICY_DENIED" or "POLICY_DENY" drop reasons.
//
// The function may return (nil, nil) when the drop reason is not "POLICY_DENIED" or "POLICY_DENY".
// This is not an error condition but indicates the flow should be skipped.
//
// Returns:
//   - (*types.PolicyDenyEvent, nil): Successfully parsed policy deny event
//   - (nil, error): Failed to parse the flow (nil flowsResponse, nil flowResponse, etc.)
//   - (nil, nil): Not a policy deny event (should be skipped)
func (w *CiliumWatcher) parsePolicyDenyEvent(
	flowsResponse *hubbleObserver.GetFlowsResponse,
) (*types.PolicyDenyEvent, error) {
	if flowsResponse == nil {
		return nil, errors.New("flowsResponse is empty")
	}

	flowResponse, ok := flowsResponse.GetResponseTypes().(*hubbleObserver.GetFlowsResponse_Flow)
	if !ok || flowResponse == nil || flowResponse.Flow == nil {
		return nil, errors.New("flowResponse is empty")
	}

	flow := flowResponse.Flow

	if flow.GetEventType() == nil ||
		(flow.GetDropReasonDesc() != flowpb.DropReason_POLICY_DENIED &&
			flow.GetDropReasonDesc() != flowpb.DropReason_POLICY_DENY) {
		return nil, nil //nolint:nilnil // This is not a policy deny event, just skip it
	}

	var proto string
	var dstPort int32
	var srcNamespace, srcName, dstNamespace, dstName string
	var srcLabels, dstLabels []string
	var srcWorkloads, dstWorkloads []string

	source := flow.GetSource()
	if source != nil {
		srcNamespace, srcName, srcLabels, srcWorkloads = w.extractEndpointInfo(source)
	}

	destination := flow.GetDestination()
	if destination != nil {
		dstNamespace, dstName, dstLabels, dstWorkloads = w.extractEndpointInfo(destination)
	}

	if l4 := flow.GetL4(); l4 != nil {
		switch l4.GetProtocol().(type) {
		case *flowpb.Layer4_TCP:
			proto = string(types.ProtocolTCP)
			dstPort = int32(l4.GetTCP().GetDestinationPort()) //nolint:gosec // port 0-65535 fits int32
		case *flowpb.Layer4_UDP:
			proto = string(types.ProtocolUDP)
			dstPort = int32(l4.GetUDP().GetDestinationPort()) //nolint:gosec // port 0-65535 fits int32
		default:
			proto = string(types.ProtocolUnknown)
		}
	}

	egressPolicies := w.extractPolicies(flow.GetEgressDeniedBy())
	ingressPolicies := w.extractPolicies(flow.GetIngressDeniedBy())

	var timestamp int64
	if flowsResponse.GetTime() != nil {
		timestamp = flowsResponse.GetTime().AsTime().Unix()
	} else {
		timestamp = time.Now().Unix()
	}

	event := &types.PolicyDenyEvent{
		Timestamp:         timestamp,
		CNIType:           string(types.CNITypeCilium),
		Protocol:          corev1.Protocol(proto),
		SrcNamespace:      srcNamespace,
		SrcName:           srcName,
		SrcLabels:         srcLabels,
		DstNamespace:      dstNamespace,
		DstName:           dstName,
		DstLabels:         dstLabels,
		SrcWorkloads:      srcWorkloads,
		DstWorkloads:      dstWorkloads,
		DstPort:           dstPort,
		EgressEnforcedBy:  egressPolicies,
		IngressEnforcedBy: ingressPolicies,
	}

	return event, nil
}

func (w *CiliumWatcher) extractEndpointInfo(
	endpoint *flowpb.Endpoint,
) (string, string, []string, []string) {
	namespace := endpoint.GetNamespace()
	name := endpoint.GetPodName()
	labels := endpoint.GetLabels()

	var workloads []string
	for _, wl := range endpoint.GetWorkloads() {
		if wl.GetKind() != "" && wl.GetName() != "" {
			workloads = append(workloads, fmt.Sprintf("%s/%s", wl.GetKind(), wl.GetName()))
		}
	}

	return namespace, name, labels, workloads
}

func (w *CiliumWatcher) extractPolicies(policies []*flowpb.Policy) []types.Policy {
	var result []types.Policy
	for _, policy := range policies {
		policyKind := policy.GetKind()
		policyName := policy.GetName()
		policyNamespace := policy.GetNamespace()

		apiVersion, err := w.GetNetworkPolicyAPIVersion(policyKind)
		if err != nil {
			w.Log.Error("Failed to get API version for policy",
				"policyKind", policyKind,
				"policyName", policyName,
				"policyNamespace", policyNamespace,
				"err", err)
			continue
		}
		result = append(result, types.Policy{
			TypeMeta:  metav1.TypeMeta{APIVersion: apiVersion, Kind: policyKind},
			Name:      policyName,
			Namespace: policyNamespace,
		})
	}
	return result
}

func (w *CiliumWatcher) Shutdown() error {
	if w.conn != nil {
		return w.conn.Close()
	}

	return nil
}
