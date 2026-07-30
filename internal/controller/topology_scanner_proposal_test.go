package controller

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/ownerkind"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
)

func newDeployment(namespace, name string, selector map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: selector}},
	}
}

func newTestTopologyScanner(t *testing.T, objs ...client.Object) *TopologyScanner {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &TopologyScanner{
		client:                 cl,
		log:                    slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug})),
		monitorViolationBuffer: violationbuf.NewBuffer(),
	}
}

func TestTopologyScannerReconcileConnection(t *testing.T) {
	t.Parallel()

	const (
		defaultNamespace = "default"
		workloadName     = "frontend"
		peerName         = "backend"
	)
	workloadLabels := map[string]string{"app": workloadName}
	peerLabels := map[string]string{"app": peerName}

	workload := topology.WorkloadKey{
		Namespace: defaultNamespace,
		OwnerKind: ownerkind.KindDeployment,
		OwnerName: workloadName,
	}
	peer := topology.Peer{
		WorkloadKey: topology.WorkloadKey{
			Namespace: defaultNamespace,
			OwnerKind: ownerkind.KindDeployment,
			OwnerName: peerName,
		},
		DstPort:  443,
		Protocol: corev1.ProtocolTCP,
	}
	expectedEgressProposal := &securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getProposalName(workload, networkingv1.PolicyTypeEgress),
			Namespace: workload.Namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: workloadLabels,
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{corev1.LabelMetadataName: defaultNamespace},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: peerLabels,
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protocolPtr(peer.Protocol),
							Port:     portPtr(peer.DstPort),
						},
					},
				},
			},
		},
	}
	expectedIngressProposal := &securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getProposalName(workload, networkingv1.PolicyTypeIngress),
			Namespace: workload.Namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: workloadLabels},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{corev1.LabelMetadataName: defaultNamespace},
					},
					PodSelector: &metav1.LabelSelector{MatchLabels: peerLabels},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: protocolPtr(peer.Protocol),
					Port:     portPtr(peer.DstPort),
				}},
			}},
		},
	}

	newPromotedPolicy := func(
		t *testing.T,
		proposalName string,
		mode securityv1alpha1.WorkloadNetworkPolicyMode,
		template networkingv1.NetworkPolicySpec,
	) *securityv1alpha1.WorkloadNetworkPolicy {
		t.Helper()

		policy := &securityv1alpha1.WorkloadNetworkPolicy{
			// policy has the same name of the proposal
			ObjectMeta: metav1.ObjectMeta{Name: proposalName, Namespace: workload.Namespace},
			Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
				Mode:           mode,
				PolicyTemplate: template,
			},
		}
		require.NoError(t, policy.SetPromotedLabel(proposalName))
		return policy
	}

	newMissingRuleTemplate := func() networkingv1.NetworkPolicySpec {
		template := expectedEgressProposal.Spec
		template.Egress = []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{corev1.LabelMetadataName: defaultNamespace},
				},
				PodSelector: &metav1.LabelSelector{MatchLabels: peerLabels},
			}},
			Ports: []networkingv1.NetworkPolicyPort{{
				Protocol: protocolPtr(corev1.ProtocolTCP),
				Port:     portPtr(8443),
			}},
		}}
		return template
	}

	tests := []struct {
		name             string
		direction        networkingv1.PolicyType
		initialObjects   func(t *testing.T) []client.Object
		wantErrContains  string
		wantProposal     *securityv1alpha1.WorkloadNetworkPolicyProposal
		assertViolations func(*testing.T, []violationbuf.ViolationRecord)
	}{
		{
			name:      "proposal_is_created_egress",
			direction: networkingv1.PolicyTypeEgress,
			initialObjects: func(_ *testing.T) []client.Object {
				return []client.Object{
					newDeployment(workload.Namespace, workload.OwnerName, workloadLabels),
					newDeployment(peer.Namespace, peer.OwnerName, peerLabels),
				}
			},
			wantProposal: expectedEgressProposal,
		},
		{
			name:      "proposal_is_created_ingress",
			direction: networkingv1.PolicyTypeIngress,
			initialObjects: func(_ *testing.T) []client.Object {
				return []client.Object{
					newDeployment(workload.Namespace, workload.OwnerName, workloadLabels),
					newDeployment(peer.Namespace, peer.OwnerName, peerLabels),
				}
			},
			wantProposal: expectedIngressProposal,
		},
		{
			name:      "policy_already_exists_protect_mode",
			direction: networkingv1.PolicyTypeEgress,
			initialObjects: func(t *testing.T) []client.Object {
				return []client.Object{newPromotedPolicy(
					t,
					expectedEgressProposal.Name,
					securityv1alpha1.WorkloadNetworkPolicyModeProtect,
					expectedEgressProposal.Spec,
				)}
			},
		},
		{
			name:      "policy_already_exists_monitor_mode_no_violations",
			direction: networkingv1.PolicyTypeEgress,
			initialObjects: func(t *testing.T) []client.Object {
				return []client.Object{
					newDeployment(peer.Namespace, peer.OwnerName, peerLabels),
					newPromotedPolicy(
						t,
						expectedEgressProposal.Name,
						securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
						expectedEgressProposal.Spec,
					),
				}
			},
		},
		{
			name:      "policy_already_exists_monitor_mode_records_violation",
			direction: networkingv1.PolicyTypeEgress,
			initialObjects: func(t *testing.T) []client.Object {
				return []client.Object{
					newDeployment(peer.Namespace, peer.OwnerName, peerLabels),
					newPromotedPolicy(
						t,
						expectedEgressProposal.Name,
						securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
						newMissingRuleTemplate(),
					),
				}
			},
			assertViolations: func(t *testing.T, records []violationbuf.ViolationRecord) {
				t.Helper()
				require.Len(t, records, 1)
				require.Equal(t, workload.OwnerName, records[0].SrcName)
				require.Equal(t, peer.OwnerName, records[0].DstName)
				require.Equal(t, networkingv1.PolicyTypeEgress, records[0].Direction)
				require.Equal(t, expectedEgressProposal.Name, records[0].DenyingPolicyName)
			},
		},
		{
			name:      "returns_error_when_multiple_policies_match",
			direction: networkingv1.PolicyTypeEgress,
			initialObjects: func(t *testing.T) []client.Object {
				first := newPromotedPolicy(
					t,
					expectedEgressProposal.Name,
					securityv1alpha1.WorkloadNetworkPolicyModeProtect,
					expectedEgressProposal.Spec,
				)
				first.Name += "-first"
				second := newPromotedPolicy(
					t,
					expectedEgressProposal.Name,
					securityv1alpha1.WorkloadNetworkPolicyModeProtect,
					expectedEgressProposal.Spec,
				)
				second.Name += "-second"
				return []client.Object{first, second}
			},
			wantErrContains: "multiple policies associated with the same proposal",
		},
		{
			name:      "returns_error_when_workload_selector_cannot_be_resolved",
			direction: networkingv1.PolicyTypeEgress,
			initialObjects: func(_ *testing.T) []client.Object {
				return []client.Object{
					// we miss the workload deployment here
					newDeployment(peer.Namespace, peer.OwnerName, peerLabels),
				}
			},
			wantErrContains: "resolving workload selector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := newTestTopologyScanner(t, tt.initialObjects(t)...)
			err := scanner.reconcileConnection(t.Context(), workload, tt.direction, sets.New(peer))

			if tt.wantErrContains != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrContains)
				return
			}
			require.NoError(t, err)

			var proposal securityv1alpha1.WorkloadNetworkPolicyProposal
			if tt.wantProposal != nil {
				require.NoError(t, scanner.client.Get(t.Context(), tt.wantProposal.NamespacedName(), &proposal))
				require.Equal(t, tt.wantProposal.Spec, proposal.Spec)
			} else {
				err = scanner.client.Get(t.Context(), client.ObjectKey{
					Namespace: workload.Namespace,
					Name:      getProposalName(workload, tt.direction),
				}, &proposal)
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))
			}

			records := scanner.monitorViolationBuffer.Drain()
			if tt.assertViolations != nil {
				tt.assertViolations(t, records)
			} else {
				require.Empty(t, records)
			}
		})
	}
}
