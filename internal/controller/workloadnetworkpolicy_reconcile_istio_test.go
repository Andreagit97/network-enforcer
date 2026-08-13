package controller

import (
	"testing"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	istiosecurityv1beta1 "istio.io/api/security/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func createIstioWorkloadNetworkPolicy(
	mode securityv1alpha1.WorkloadNetworkPolicyMode,
) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := newTestWNP("test-policy", "default")
	wnp.UID = types.UID("test-uid")
	wnp.Spec.Mode = mode
	wnp.Spec.PolicyBackendSpec = securityv1alpha1.PolicyBackendSpec{
		Backend: securityv1alpha1.PolicyBackendIstio,
		Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			Rules: []securityv1alpha1.IstioAuthorizationPolicyRule{
				{
					From: []securityv1alpha1.IstioFrom{
						{
							Source: securityv1alpha1.IstioSource{
								Principals: []string{"cluster.local/ns/default/sa/frontend"},
							},
						},
					},
					To: []securityv1alpha1.IstioTo{
						{
							Operation: securityv1alpha1.IstioOperation{
								Ports: []string{"8080"},
							},
						},
					},
				},
			},
		},
	}
	return wnp
}

func createAssociatedAuthorizationPolicy() *istiosecurityv1.AuthorizationPolicy {
	wnp := createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
	ap := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wnp.Name,
			Namespace: wnp.Namespace,
		},
	}
	populateIstioAuthorizationPolicySpec(&ap.Spec, wnp.Spec.Istio)
	controller := true
	blockOwnerDeletion := true
	ap.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         securityv1alpha1.GroupVersion.String(),
			Kind:               securityv1alpha1.WorkloadNetworkPolicyKind,
			Name:               wnp.Name,
			UID:                wnp.UID,
			Controller:         &controller,
			BlockOwnerDeletion: &blockOwnerDeletion,
		},
	}
	return ap
}

func TestWorkloadNetworkPolicyReconcilerIstioProtect(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		setup   func() []client.Object
		wantErr bool
	}{
		{
			name: "CreateProtectMode",
			setup: func() []client.Object {
				return []client.Object{createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)}
			},
		},
		{
			name: "UpdatePolicyTemplate",
			setup: func() []client.Object {
				wnp := createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				ap := createAssociatedAuthorizationPolicy()
				ap.Spec.Selector = nil
				ap.Annotations = map[string]string{istioDryRunAnnotationKey: "true"}
				return []client.Object{wnp, ap}
			},
		},
		{
			name: "UnexpectedAuthorizationPolicy",
			setup: func() []client.Object {
				wnp := createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				ap := createAssociatedAuthorizationPolicy()
				ap.OwnerReferences = []metav1.OwnerReference{}
				return []client.Object{wnp, ap}
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := types.NamespacedName{Name: "test-policy", Namespace: "default"}
			r := newTestWNPreconciler(t, tc.setup()...)
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			var ap istiosecurityv1.AuthorizationPolicy
			err = r.Get(t.Context(), key, &ap)
			require.NoError(t, err)
			require.Equal(t, istiosecurityv1beta1.AuthorizationPolicy_ALLOW, ap.Spec.GetAction())
			require.Equal(t, map[string]string{"app": "web"}, ap.Spec.GetSelector().GetMatchLabels())
			require.Len(t, ap.Spec.GetRules(), 1)
			require.Len(t, ap.Spec.GetRules()[0].GetFrom(), 1)
			require.Equal(
				t,
				[]string{"cluster.local/ns/default/sa/frontend"},
				ap.Spec.GetRules()[0].GetFrom()[0].GetSource().GetPrincipals(),
			)
			require.Len(t, ap.Spec.GetRules()[0].GetTo(), 1)
			require.Equal(t, []string{"8080"}, ap.Spec.GetRules()[0].GetTo()[0].GetOperation().GetPorts())
			require.NotContains(t, ap.Annotations, istioDryRunAnnotationKey)

			require.Len(t, ap.OwnerReferences, 1)
			ref := ap.OwnerReferences[0]
			require.True(t, ref.Controller != nil && *ref.Controller)
			require.Equal(t, "test-policy", ref.Name)
			require.Equal(t, string(types.UID("test-uid")), string(ref.UID))
		})
	}
}

func TestWorkloadNetworkPolicyReconcilerIstioMonitor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		setup func() []client.Object
	}{
		{
			name: "CreateMonitorMode",
			setup: func() []client.Object {
				return []client.Object{createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)}
			},
		},
		{
			name: "SwitchProtectToMonitor",
			setup: func() []client.Object {
				wnp := createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)
				ap := createAssociatedAuthorizationPolicy()
				return []client.Object{wnp, ap}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := types.NamespacedName{Name: "test-policy", Namespace: "default"}
			r := newTestWNPreconciler(t, tc.setup()...)
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
			require.NoError(t, err)

			var ap istiosecurityv1.AuthorizationPolicy
			err = r.Get(t.Context(), key, &ap)
			require.NoError(t, err)
			require.Equal(t, "true", ap.Annotations[istioDryRunAnnotationKey])
		})
	}
}

func TestPopulateIstioAuthorizationPolicySpec(t *testing.T) {
	t.Parallel()

	backendSpec := &securityv1alpha1.IstioAuthorizationPolicySpec{
		Selector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app":  "web",
				"tier": "frontend",
			},
		},
		Rules: []securityv1alpha1.IstioAuthorizationPolicyRule{
			{
				From: []securityv1alpha1.IstioFrom{
					{
						Source: securityv1alpha1.IstioSource{
							Principals: []string{
								"cluster.local/ns/default/sa/frontend",
								"cluster.local/ns/default/sa/gateway",
							},
						},
					},
				},
				To: []securityv1alpha1.IstioTo{
					{
						Operation: securityv1alpha1.IstioOperation{
							Ports: []string{"8080", "8443"},
						},
					},
				},
			},
		},
	}

	spec := &istiosecurityv1beta1.AuthorizationPolicy{}
	populateIstioAuthorizationPolicySpec(spec, backendSpec)

	require.Equal(t, istiosecurityv1beta1.AuthorizationPolicy_ALLOW, spec.GetAction())
	require.Equal(t, backendSpec.Selector.MatchLabels, spec.GetSelector().GetMatchLabels())
	require.Len(t, spec.GetRules(), 1)
	require.Len(t, spec.GetRules()[0].GetFrom(), 1)
	require.Equal(
		t,
		[]string{"cluster.local/ns/default/sa/frontend", "cluster.local/ns/default/sa/gateway"},
		spec.GetRules()[0].GetFrom()[0].GetSource().GetPrincipals(),
	)
	require.Len(t, spec.GetRules()[0].GetTo(), 1)
	require.Equal(t, []string{"8080", "8443"}, spec.GetRules()[0].GetTo()[0].GetOperation().GetPorts())

	backendSpec.Selector.MatchLabels["app"] = "api"
	backendSpec.Rules[0].From[0].Source.Principals[0] = "cluster.local/ns/default/sa/changed"
	backendSpec.Rules[0].To[0].Operation.Ports[0] = "9090"

	require.Equal(t, "web", spec.GetSelector().GetMatchLabels()["app"])
	require.Equal(
		t,
		[]string{"cluster.local/ns/default/sa/frontend", "cluster.local/ns/default/sa/gateway"},
		spec.GetRules()[0].GetFrom()[0].GetSource().GetPrincipals(),
	)
	require.Equal(t, []string{"8080", "8443"}, spec.GetRules()[0].GetTo()[0].GetOperation().GetPorts())
}
