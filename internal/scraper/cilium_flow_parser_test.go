package scraper

import (
	"errors"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/api/v1/relay"
	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/testutil"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const defaultCiliumTestNamespace = "default"

func flowResponse(flow *flowpb.Flow) *hubbleObserver.GetFlowsResponse {
	return &hubbleObserver.GetFlowsResponse{
		ResponseTypes: &hubbleObserver.GetFlowsResponse_Flow{Flow: flow},
	}
}

func testProcessFlowOutcomeError() processFlowResult {
	return processFlowResult{
		outcome: processFlowOutcomeError,
		err:     errors.New("example error, not relevant"),
	}
}

func TestParseCiliumFlow(t *testing.T) {
	t.Parallel()

	endpoint := func(name, kind string) *hubbleObserver.Endpoint {
		return &hubbleObserver.Endpoint{
			Namespace: defaultCiliumTestNamespace,
			Workloads: []*flowpb.Workload{{
				Name: name,
				Kind: kind,
			}},
		}
	}

	tests := []struct {
		name              string
		flow              *flowpb.Flow
		processFlowResult processFlowResult
	}{
		{
			name: "reply_flow_is_skipped",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(true),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "dropped_flow_is_skipped",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				Verdict: flowpb.Verdict_DROPPED,
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "unsupported_protocol",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{}}},
				Source:      endpoint("source-deploy", "Deployment"),
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "unsupported_source_workload_kind",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:      endpoint("source-pod", "Pod"),
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "endpoint_without_workload_is_skipped",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					// No workload associated will cause a skip.
				},
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "endpoint_with_multiple_workloads",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{
						{Name: "source-1", Kind: "Deployment"},
						{Name: "source-2", Kind: "Deployment"},
					},
				},
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name: "valid_tcp_flow",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:      endpoint("source-deploy", "Deployment"),
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowEnqueue(
				types.LearningEvent{
					Source: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "source-deploy",
						OwnerKind: securityv1alpha1.WorkloadKindDeployment,
						Identity:  "",
					},
					Dest: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "dest-deploy",
						OwnerKind: securityv1alpha1.WorkloadKindDeployment,
						Identity:  "",
					},
					DstPort:  8080,
					Protocol: corev1.ProtocolTCP,
					Backend:  securityv1alpha1.PolicyBackendKubernetes,
				},
			),
		},
		{
			name: "valid_udp_flow",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 5353}}},
				Source:      endpoint("source-sts", "StatefulSet"),
				Destination: endpoint("dest-ds", "DaemonSet"),
			},
			processFlowResult: processFlowEnqueue(
				types.LearningEvent{
					Source: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "source-sts",
						OwnerKind: securityv1alpha1.WorkloadKindStatefulSet,
					},
					Dest: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "dest-ds",
						OwnerKind: securityv1alpha1.WorkloadKindDaemonSet,
					},
					DstPort:  5353,
					Protocol: corev1.ProtocolUDP,
					Backend:  securityv1alpha1.PolicyBackendKubernetes,
				},
			),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := parseCiliumFlowResponse(tc.flow)
			require.Equal(t, tc.processFlowResult.outcome, result.outcome)
			// we assert the learning event if we have it
			if tc.processFlowResult.outcome == processFlowOutcomeEnqueue {
				require.Equal(t, tc.processFlowResult.event, result.event)
			}
		})
	}
}

func TestProcessFlowResolvesSelectorsWithFakeClient(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "source-deploy", Namespace: defaultCiliumTestNamespace},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "source"}},
				},
			},
			&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "dest-deploy", Namespace: defaultCiliumTestNamespace},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "dest"}},
				},
			},
		).Build()

	s := NewCiliumScraper(CiliumScraperConfig{
		Client: cl,
		Logger: testutil.NewTestLogger(t),
	})

	tests := []struct {
		name              string
		flow              *hubbleObserver.GetFlowsResponse
		processFlowResult processFlowResult
		assert            func(t *testing.T, result processFlowResult)
	}{
		{
			name: "both_workloads_present",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "dest-deploy", Kind: "Deployment"}},
				},
			}),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "source-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "source"}},
				},
				Dest: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "dest-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "dest"}},
				},
				DstPort:  8080,
				Protocol: corev1.ProtocolTCP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "missing_dst",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "dest-deploy-not-present", Kind: "Deployment"}},
				},
			}),
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name:              "nil_flow_response",
			flow:              nil,
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name:              "nil_payload_flow_response",
			flow:              flowResponse(nil),
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name: "lost_events_is_skipped",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_LostEvents{
					LostEvents: &flowpb.LostEvent{NumEventsLost: 5},
				},
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "node_status_is_skipped",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_NodeStatus{
					NodeStatus: &relay.NodeStatusEvent{},
				},
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name:              "empty_response_type_is_skipped",
			flow:              &hubbleObserver.GetFlowsResponse{},
			processFlowResult: processFlowSkip(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := s.processFlow(t.Context(), tc.flow)
			require.Equal(t, tc.processFlowResult.outcome, result.outcome)
			if tc.assert != nil {
				tc.assert(t, result)
			}
		})
	}
}
