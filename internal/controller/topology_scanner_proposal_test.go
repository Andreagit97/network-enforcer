package controller

import (
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

	return &TopologyScanner{client: cl}
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
	expectedProposal := &securityv1alpha1.WorkloadNetworkPolicyProposal{
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
	promotedPolicy := &securityv1alpha1.WorkloadNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      expectedProposal.Name,
			Namespace: expectedProposal.Namespace,
		},
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			Mode:           securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			PolicyTemplate: expectedProposal.Spec,
		},
	}
	require.NoError(t, promotedPolicy.SetPromotedLabel(expectedProposal.Name))

	tests := []struct {
		name   string
		setup  func() []client.Object
		assert func(*testing.T, *TopologyScanner)
	}{
		{
			// No policy in the cluster so we expect the creation of a new proposal
			name: "proposal_is_created",
			setup: func() []client.Object {
				return []client.Object{
					// We need the deployment to get the label selectors
					newDeployment(workload.Namespace, workload.OwnerName, workloadLabels),
					newDeployment(peer.Namespace, peer.OwnerName, peerLabels),
				}
			},
			assert: func(t *testing.T, scanner *TopologyScanner) {
				var proposal securityv1alpha1.WorkloadNetworkPolicyProposal
				require.NoError(t, scanner.client.Get(t.Context(), expectedProposal.NamespacedName(), &proposal))
				require.Equal(t, expectedProposal.Spec, proposal.Spec)
			},
		},
		{
			name: "policy_already_exists_protect_mode",
			setup: func() []client.Object {
				return []client.Object{promotedPolicy}
			},
			assert: func(t *testing.T, scanner *TopologyScanner) {
				var proposal securityv1alpha1.WorkloadNetworkPolicyProposal
				err := scanner.client.Get(t.Context(), expectedProposal.NamespacedName(), &proposal)
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := newTestTopologyScanner(t, tt.setup()...)
			require.NoError(t, scanner.reconcileConnection(
				t.Context(),
				workload,
				networkingv1.PolicyTypeEgress,
				sets.New(peer),
			))
			tt.assert(t, scanner)
		})
	}
}
