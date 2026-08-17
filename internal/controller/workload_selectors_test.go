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
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
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
func TestExtractWorkloadRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pod  *corev1.Pod
		want securityv1alpha1.WorkloadRef
	}{
		{
			name: "standalone pod without controller",
			pod:  ownedPod("mypod", nil, nil),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: workload.KindPod,
				OwnerName: "mypod",
			},
		},
		{
			name: "replicaset without pod-template-hash stays replicaset",
			pod: ownedPod(
				"runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				controllerRef(
					"apps/v1",
					string(workload.KindReplicaSet),
					"runtime-enforcer-controller-manager-6f4b9855c6",
				),
				map[string]string{},
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: workload.KindReplicaSet,
				OwnerName: "runtime-enforcer-controller-manager-6f4b9855c6",
			},
		},
		{
			name: "replicaset with pod-template-hash becomes deployment",
			pod: ownedPod(
				"runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				controllerRef(
					"apps/v1",
					string(workload.KindReplicaSet),
					"runtime-enforcer-controller-manager-6f4b9855c6",
				),
				map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "6f4b9855c6",
				},
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: workload.KindDeployment,
				OwnerName: "runtime-enforcer-controller-manager",
			},
		},
		{
			name: "statefulset",
			pod: ownedPod(
				"db-0",
				controllerRef("apps/v1", string(workload.KindStatefulSet), "db"),
				nil,
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: workload.KindStatefulSet,
				OwnerName: "db",
			},
		},
		{
			name: "daemonset",
			pod: ownedPod(
				"agent-node1",
				controllerRef("apps/v1", string(workload.KindDaemonSet), "agent"),
				nil,
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: workload.KindDaemonSet,
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
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: workload.Kind("Job"),
				OwnerName: "ubuntu-job",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, extractWorkloadRef(tt.pod))
		})
	}
}

func TestWorkloadRefFromPod(t *testing.T) {
	t.Parallel()

	pod := ownedPod(
		"frontend-abc123-xyz",
		controllerRef("apps/v1", string(workload.KindReplicaSet), "frontend-abc123"),
		map[string]string{appsv1.DefaultDeploymentUniqueLabelKey: "abc123"},
	)

	cl := fake.NewClientBuilder().
		WithScheme(newWorkloadTestScheme(t)).
		WithObjects(pod).
		Build()

	got, err := workloadRefFromPod(context.Background(), cl, testNamespace, pod.Name)
	require.NoError(t, err)
	require.Equal(t, securityv1alpha1.WorkloadRef{
		Namespace: testNamespace,
		OwnerKind: workload.KindDeployment,
		OwnerName: "frontend",
	}, got)

	_, err = workloadRefFromPod(context.Background(), cl, testNamespace, "missing")
	require.True(t, apierrors.IsNotFound(err))
}
