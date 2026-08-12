package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/ownerkind"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
)

const testNamespace = "default"

func newWorkloadTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))
	return scheme
}

func ownedPod(name string, owner *metav1.OwnerReference, labels map[string]string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    labels,
			UID:       types.UID(name + "-uid"),
		},
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return pod
}

func controllerRef(apiVersion, kind, name string) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        types.UID(name + "-uid"),
		Controller: new(true),
	}
}

// Cases adapted from runtime-enforcer getPodInfo tests:
// https://github.com/rancher-sandbox/runtime-enforcer/pull/219/changes#diff-43908338b58fbcda0d302e74469efb9886c7f6846076de871715ef480b0b76efL13
func TestExtractWorkloadKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pod  *corev1.Pod
		want topology.WorkloadKey
	}{
		{
			name: "standalone pod without controller",
			pod:  ownedPod("mypod", nil, nil),
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindPod,
				OwnerName: "mypod",
			},
		},
		{
			name: "replicaset without pod-template-hash stays replicaset",
			pod: ownedPod(
				"runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				controllerRef(
					"apps/v1",
					string(ownerkind.KindReplicaSet),
					"runtime-enforcer-controller-manager-6f4b9855c6",
				),
				map[string]string{},
			),
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindReplicaSet,
				OwnerName: "runtime-enforcer-controller-manager-6f4b9855c6",
			},
		},
		{
			name: "replicaset with pod-template-hash becomes deployment",
			pod: ownedPod(
				"runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				controllerRef(
					"apps/v1",
					string(ownerkind.KindReplicaSet),
					"runtime-enforcer-controller-manager-6f4b9855c6",
				),
				map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "6f4b9855c6",
				},
			),
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindDeployment,
				OwnerName: "runtime-enforcer-controller-manager",
			},
		},
		{
			name: "statefulset",
			pod: ownedPod(
				"db-0",
				controllerRef("apps/v1", string(ownerkind.KindStatefulSet), "db"),
				nil,
			),
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindStatefulSet,
				OwnerName: "db",
			},
		},
		{
			name: "daemonset",
			pod: ownedPod(
				"agent-node1",
				controllerRef("apps/v1", string(ownerkind.KindDaemonSet), "agent"),
				nil,
			),
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindDaemonSet,
				OwnerName: "agent",
			},
		},
		{
			name: "job controller remains job",
			pod: ownedPod(
				"ubuntu-job-pq2qc",
				controllerRef("batch/v1", "Job", "ubuntu-job"),
				nil,
			),
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.Kind("Job"),
				OwnerName: "ubuntu-job",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, extractWorkloadKey(tt.pod))
		})
	}
}

func TestWorkloadKeyFromPod(t *testing.T) {
	t.Parallel()

	pod := ownedPod(
		"frontend-abc123-xyz",
		controllerRef("apps/v1", string(ownerkind.KindReplicaSet), "frontend-abc123"),
		map[string]string{appsv1.DefaultDeploymentUniqueLabelKey: "abc123"},
	)

	cl := fake.NewClientBuilder().
		WithScheme(newWorkloadTestScheme(t)).
		WithObjects(pod).
		Build()

	got, err := workloadKeyFromPod(context.Background(), cl, testNamespace, pod.Name)
	require.NoError(t, err)
	require.Equal(t, topology.WorkloadKey{
		Namespace: testNamespace,
		OwnerKind: ownerkind.KindDeployment,
		OwnerName: "frontend",
	}, got)

	_, err = workloadKeyFromPod(context.Background(), cl, testNamespace, "missing")
	require.True(t, apierrors.IsNotFound(err))
}
