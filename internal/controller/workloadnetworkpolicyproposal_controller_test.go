package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

func newTestProposalReconciler(t *testing.T, objs ...client.Object) *WorkloadNetworkPolicyProposalReconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &WorkloadNetworkPolicyProposalReconciler{
		Client: cl,
		Scheme: scheme,
	}
}

func newBaseProposal() *securityv1alpha1.WorkloadNetworkPolicyProposal {
	protocolUDP := corev1.ProtocolUDP
	portDNS := intstr.FromInt32(53)
	return &securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "example",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},

			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "10.0.0.10/32",
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &protocolUDP,
							Port:     &portDNS,
						},
					},
				},
			},
		},
	}
}

func TestWorkloadNetworkPolicyProposalReconciler(t *testing.T) {
	t.Parallel()

	baseProposal := newBaseProposal()
	basePolicy := securityv1alpha1.WorkloadNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseProposal.Name,
			Namespace: baseProposal.Namespace,
		},
	}
	require.NoError(t, basePolicy.SetPromotedLabel(baseProposal.Name))

	tests := []struct {
		name   string
		setup  func() []client.Object
		assert func(*testing.T, *WorkloadNetworkPolicyProposalReconciler)
	}{
		{
			name: "ProposalDeleted",
			setup: func() []client.Object {
				proposal := baseProposal.DeepCopy()
				proposal.DeletionTimestamp = &metav1.Time{Time: time.Now()}
				// if there is the deletion timestamp, we need to set the finalizer
				proposal.Finalizers = []string{"test.finalizer"}
				return []client.Object{proposal}
			},
			assert: func(t *testing.T, reconciler *WorkloadNetworkPolicyProposalReconciler) {
				var p securityv1alpha1.WorkloadNetworkPolicy
				err := reconciler.Get(t.Context(), baseProposal.NamespacedName(), &p)
				// No policy is created
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))
			},
		},
		{
			name: "AlreadyPromotedPolicy",
			setup: func() []client.Object {
				return []client.Object{baseProposal.DeepCopy(), basePolicy.DeepCopy()}
			},
			assert: func(t *testing.T, reconciler *WorkloadNetworkPolicyProposalReconciler) {
				var p securityv1alpha1.WorkloadNetworkPolicyProposal
				err := reconciler.Get(t.Context(), baseProposal.NamespacedName(), &p)
				// The proposal is deleted because the policy already exists
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))
			},
		},
		{
			name: "NoPromotionLabel",
			setup: func() []client.Object {
				return []client.Object{baseProposal.DeepCopy()}
			},
			assert: func(t *testing.T, reconciler *WorkloadNetworkPolicyProposalReconciler) {
				var p securityv1alpha1.WorkloadNetworkPolicy
				err := reconciler.Get(t.Context(), baseProposal.NamespacedName(), &p)
				// No policy should be created
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))
			},
		},
		{
			name: "PromotionLabelMonitor",
			setup: func() []client.Object {
				proposal := baseProposal.DeepCopy()
				proposal.SetPromotionLabel(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)
				return []client.Object{proposal}
			},
			assert: func(t *testing.T, reconciler *WorkloadNetworkPolicyProposalReconciler) {
				var p securityv1alpha1.WorkloadNetworkPolicy
				err := reconciler.Get(t.Context(), baseProposal.NamespacedName(), &p)
				require.NoError(t, err)
				require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, p.Spec.Mode)
				require.True(t, p.HasPromotedLabel(baseProposal.Name))
				require.Equal(t, baseProposal.Spec, p.Spec.PolicyTemplate)
			},
		},
		{
			name: "PromotionLabelProtect",
			setup: func() []client.Object {
				proposal := baseProposal.DeepCopy()
				proposal.SetPromotionLabel(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				return []client.Object{proposal}
			},
			assert: func(t *testing.T, reconciler *WorkloadNetworkPolicyProposalReconciler) {
				var p securityv1alpha1.WorkloadNetworkPolicy
				err := reconciler.Get(t.Context(), baseProposal.NamespacedName(), &p)
				require.NoError(t, err)
				require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, p.Spec.Mode)
				require.True(t, p.HasPromotedLabel(baseProposal.Name))
				require.Equal(t, baseProposal.Spec, p.Spec.PolicyTemplate)
			},
		},
		{
			name: "InvalidPromotionLabel",
			setup: func() []client.Object {
				proposal := baseProposal.DeepCopy()
				proposal.Labels = map[string]string{
					securityv1alpha1.ProposalPromoteLabelKey: "invalid",
				}
				return []client.Object{proposal}
			},
			assert: func(t *testing.T, reconciler *WorkloadNetworkPolicyProposalReconciler) {
				var p securityv1alpha1.WorkloadNetworkPolicy
				err := reconciler.Get(t.Context(), baseProposal.NamespacedName(), &p)
				// Invalid promotion label values are ignored
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reconciler := newTestProposalReconciler(t, tt.setup()...)
			_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: baseProposal.NamespacedName()})
			require.NoError(t, err)
			tt.assert(t, reconciler)
		})
	}
}
