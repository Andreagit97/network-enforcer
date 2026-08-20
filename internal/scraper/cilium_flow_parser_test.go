package scraper

import (
	"errors"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
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

func TestParseCiliumFlow(t *testing.T) {
	t.Parallel()

	// if the outcome is error we don't check the error msg.
	testProcessFlowOutcomeError := processFlowError(errors.New("example error, not relevant"))

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
		flow              *hubbleObserver.GetFlowsResponse
		processFlowResult processFlowResult
	}{
		{
			name:              "nil_flow",
			flow:              nil,
			processFlowResult: testProcessFlowOutcomeError,
		},
		{
			name:              "empty_flow",
			flow:              flowResponse(nil),
			processFlowResult: testProcessFlowOutcomeError,
		},
		{
			name: "reply_flow_is_skipped",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(true),
			}),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "dropped_flow_is_skipped",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				Verdict: flowpb.Verdict_DROPPED,
			}),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "unsupported_protocol",
			flow: flowResponse(&flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{}}},
				Source:      endpoint("source-deploy", "Deployment"),
				Destination: endpoint("dest-deploy", "Deployment"),
			}),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "unsupported_source_workload_kind",
			flow: flowResponse(&flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:      endpoint("source-pod", "Pod"),
				Destination: endpoint("dest-deploy", "Deployment"),
			}),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "endpoint_without_workload_is_skipped",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					// No workload associated will cause a skip.
				},
				Destination: endpoint("dest-deploy", "Deployment"),
			}),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "endpoint_with_multiple_workloads",
			flow: flowResponse(&flowpb.Flow{
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
			}),
			processFlowResult: testProcessFlowOutcomeError,
		},
		{
			name: "valid_tcp_flow",
			flow: flowResponse(&flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:      endpoint("source-deploy", "Deployment"),
				Destination: endpoint("dest-deploy", "Deployment"),
			}),
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
			flow: flowResponse(&flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 5353}}},
				Source:      endpoint("source-sts", "StatefulSet"),
				Destination: endpoint("dest-ds", "DaemonSet"),
			}),
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
			result := parseCiliumFlow(tc.flow)
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

	t.Run("both_workloads_present", func(t *testing.T) {
		t.Parallel()

		// Both source and dst workloads are in the cache.
		result := s.processFlow(t.Context(), flowResponse(&flowpb.Flow{
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
		}))
		require.Equal(t, processFlowOutcomeEnqueue, result.outcome)
		require.Equal(t, map[string]string{"app": "source"}, result.event.Source.Selector.MatchLabels)
		require.Equal(t, map[string]string{"app": "dest"}, result.event.Dest.Selector.MatchLabels)
	})

	t.Run("missing_dst", func(t *testing.T) {
		t.Parallel()

		// Both source and dst workloads are in the cache.
		result := s.processFlow(t.Context(), flowResponse(&flowpb.Flow{
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
		}))
		require.Equal(t, processFlowOutcomeError, result.outcome)
	})
}
