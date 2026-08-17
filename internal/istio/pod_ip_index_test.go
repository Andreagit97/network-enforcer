package istio

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/ownerkind"
)

// newTestLogger returns a [slog.Logger] that discards output, for enrichment
// tests that only care about the returned observation, not the logs.
func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// errFake is returned by the erroring fake clients below to exercise the
// unexpected-error branch of resolveSourceWorkload and the destination fetch.
var errFake = errors.New("boom")

// newEnricherScheme builds a scheme with the core, apps, networking and
// security types used by the enrichment tests.
func newEnricherScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = scheme.AddToScheme(s) // core/v1
	return s
}

// newEnricherWithObjects builds an Enricher backed by a fake client seeded with
// the given objects. The status.podIP field index is registered so source
// resolution behaves as it does in production.
func newEnricherWithObjects(objs ...client.Object) *Enricher {
	return NewEnricher(fake.NewClientBuilder().
		WithScheme(newEnricherScheme()).
		WithIndex(&corev1.Pod{}, PodIPIndexField, IndexPodByIP).
		WithObjects(objs...).
		Build())
}

// newEnricherWithListError builds an Enricher whose pod List always fails, to
// exercise the unexpected-error path of resolveSourceWorkload.
func newEnricherWithListError() *Enricher {
	return NewEnricher(fake.NewClientBuilder().
		WithScheme(newEnricherScheme()).
		WithIndex(&corev1.Pod{}, PodIPIndexField, IndexPodByIP).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return errFake
			},
		}).
		Build())
}

// newEnricherWithGetError builds an Enricher whose Get always fails with a
// non-NotFound error, to exercise the unexpected-error path of the destination
// pod fetch.
func newEnricherWithGetError() *Enricher {
	return NewEnricher(fake.NewClientBuilder().
		WithScheme(newEnricherScheme()).
		WithIndex(&corev1.Pod{}, PodIPIndexField, IndexPodByIP).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return errFake
			},
		}).
		Build())
}

// controllerRef builds a controller owner reference for the given workload.
func controllerRef(apiVersion, kind, name string) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        types.UID(name + "-uid"),
		Controller: new(true),
	}
}

// sourcePod builds a client pod for resolution tests: an assigned pod IP,
// a service account, and an optional controller owner reference.
func sourcePod(name, namespace, ip, serviceAccount string, owner *metav1.OwnerReference) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(name + "-uid"),
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: serviceAccount,
		},
		Status: corev1.PodStatus{
			PodIP: ip,
		},
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return pod
}

// deploymentPod builds a pod owned by a ReplicaSet with a pod-template-hash so
// ExtractWorkloadKey resolves it to the owning Deployment.
func deploymentPod(deployName, namespace, ip, serviceAccount string) *corev1.Pod {
	const hash = "abc123"
	rsName := deployName + "-" + hash
	pod := sourcePod(rsName+"-pod", namespace, ip, serviceAccount,
		controllerRef(appsv1.SchemeGroupVersion.String(), string(ownerkind.KindReplicaSet), rsName))
	pod.Labels = map[string]string{appsv1.DefaultDeploymentUniqueLabelKey: hash}
	return pod
}

// destPod builds a Deployment-owned pod carrying the given selector labels, for
// ALLOW-miss correlation tests that match a destination pod against WNP
// selectors. It has no pod IP because destination resolution fetches it by name.
func destPod(deployName, namespace, serviceAccount string, matchLabels map[string]string) *corev1.Pod {
	pod := deploymentPod(deployName, namespace, "", serviceAccount)
	maps.Copy(pod.Labels, matchLabels)
	return pod
}

// istioWNP builds an Istio-backend WorkloadNetworkPolicy whose selector matches
// the given labels, for ALLOW-miss owning-policy resolution tests.
func istioWNP(namespace, name string, matchLabels map[string]string) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendIstio,
				Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{MatchLabels: matchLabels},
				},
			},
		},
	}
}

// kubernetesWNP builds a Kubernetes-backend WorkloadNetworkPolicy whose pod
// selector matches the given labels, for ALLOW-miss owning-policy resolution
// tests of the kubernetes backend.
func kubernetesWNP(namespace, name string, matchLabels map[string]string) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: matchLabels},
				},
			},
		},
	}
}

func TestIndexPodByIP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "pod with IP",
			obj:  sourcePod("p", "ns", "10.244.0.2", "sa", nil),
			want: []string{"10.244.0.2"},
		},
		{
			name: "pod without IP",
			obj:  sourcePod("p", "ns", "", "sa", nil),
			want: nil,
		},
		{
			name: "non-pod object",
			obj:  &corev1.Service{},
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, IndexPodByIP(c.obj))
		})
	}
}
