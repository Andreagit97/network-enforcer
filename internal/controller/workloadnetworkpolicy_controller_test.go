package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

func newTestWNPreconciler(t *testing.T, objs ...client.Object) *WorkloadNetworkPolicyReconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))
	require.NoError(t, networkingv1.AddToScheme(scheme))
	require.NoError(t, istiosecurityv1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &WorkloadNetworkPolicyReconciler{
		Client: cl,
		Scheme: scheme,
	}
}

func createWorkloadNetworkPolicy(
	mode securityv1alpha1.WorkloadNetworkPolicyMode,
) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := newTestWNP("test-policy", "default")
	wnp.UID = types.UID("test-uid")
	wnp.Spec.Mode = mode
	wnp.Spec.Kubernetes.PodSelector.MatchLabels = map[string]string{"app": "web"}
	wnp.Spec.Kubernetes.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	wnp.Spec.Kubernetes.Ingress = []networkingv1.NetworkPolicyIngressRule{
		{
			From: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"role": "frontend"},
					},
				},
			},
		},
	}
	return wnp
}

func createAssociatedNetworkPolicy() *networkingv1.NetworkPolicy {
	return newOwnedNetworkPolicy(
		createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect),
	)
}

func TestWorkloadNetworkPolicyReconcilerProtect(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		setup   func() []client.Object
		wantErr bool
	}{
		{
			name: "CreateProtectMode",
			setup: func() []client.Object {
				return []client.Object{createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)}
			},
		},
		{
			name: "UpdatePolicyTemplate",
			setup: func() []client.Object {
				wnp := createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				// Also seed an existing NetworkPolicy with old spec
				np := createAssociatedNetworkPolicy()
				np.Spec.PodSelector.MatchLabels["app"] = "old"
				return []client.Object{wnp, np}
			},
		},
		{
			name: "UnexpectedNetworkPolicy",
			setup: func() []client.Object {
				wnp := createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				// Seed an existing NetworkPolicy without owner references
				np := createAssociatedNetworkPolicy()
				np.OwnerReferences = []metav1.OwnerReference{}
				return []client.Object{wnp, np}
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := types.NamespacedName{Name: "test-policy", Namespace: "default"}
			r := newTestWNPreconciler(t, tc.setup()...)
			_, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: key,
			})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			var np networkingv1.NetworkPolicy
			err = r.Get(t.Context(), key, &np)
			require.NoError(t, err)
			require.Equal(t, "test-policy", np.Name)
			require.Equal(t, "default", np.Namespace)
			require.Equal(t, "web", np.Spec.PodSelector.MatchLabels["app"])
			require.Contains(t, np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
			require.Len(t, np.Spec.Ingress, 1)
			require.Len(t, np.Spec.Ingress[0].From, 1)
			require.NotNil(t, np.Spec.Ingress[0].From[0].PodSelector)
			require.Equal(t, "frontend", np.Spec.Ingress[0].From[0].PodSelector.MatchLabels["role"])

			// Verify owner reference is set as controller
			require.Len(t, np.OwnerReferences, 1)
			ref := np.OwnerReferences[0]
			require.True(t, ref.Controller != nil && *ref.Controller)
			require.Equal(t, "test-policy", ref.Name)
			require.Equal(t, string(types.UID("test-uid")), string(ref.UID))
		})
	}
}

func TestWorkloadNetworkPolicyReconcilerMonitor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		setup func() []client.Object
	}{
		{
			name: "SwitchProtectToMonitor",
			setup: func() []client.Object {
				wnp := createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)
				// Seed a NetworkPolicy that exists from a previous protect mode
				np := createAssociatedNetworkPolicy()
				return []client.Object{wnp, np}
			},
		},
		{
			name: "MonitorModeNoop",
			setup: func() []client.Object {
				return []client.Object{createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)}
			},
		},
		{
			name: "DeleteWorkloadNetworkPolicy",
			setup: func() []client.Object {
				// No WorkloadNetworkPolicy in the client — simulates deletion.
				return nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newTestWNPreconciler(t, tc.setup()...)
			_, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "test-policy", Namespace: "default"},
			})
			require.NoError(t, err)

			key := types.NamespacedName{Name: "test-policy", Namespace: "default"}
			var np networkingv1.NetworkPolicy
			err = r.Get(t.Context(), key, &np)
			require.True(t, apierrors.IsNotFound(err), "NetworkPolicy should not exist")
		})
	}
}
