package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func ownedPod(name string, owner metav1.OwnerReference, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			Labels:          labels,
			OwnerReferences: []metav1.OwnerReference{owner},
		},
	}
}

func TestWorkloadKeyFromPod(t *testing.T) {
	t.Parallel()

	rsOwner := metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       string(ownerkind.KindReplicaSet),
		Name:       "frontend-abc123",
		UID:        "rs-uid",
		Controller: new(true),
	}
	stsOwner := metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       string(ownerkind.KindStatefulSet),
		Name:       "db",
		UID:        "sts-uid",
		Controller: new(true),
	}
	dsOwner := metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       string(ownerkind.KindDaemonSet),
		Name:       "agent",
		UID:        "ds-uid",
		Controller: new(true),
	}
	jobOwner := metav1.OwnerReference{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Name:       "cron-job-1",
		UID:        "job-uid",
		Controller: new(true),
	}

	tests := []struct {
		name    string
		objs    []client.Object
		podName string
		want    topology.WorkloadKey
		wantErr error
	}{
		{
			name: "deployment via replicaset hash heuristic",
			objs: []client.Object{
				ownedPod("frontend-abc123-xyz", rsOwner, map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "abc123",
				}),
			},
			podName: "frontend-abc123-xyz",
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindDeployment,
				OwnerName: "frontend",
			},
		},
		{
			name: "replicaset without pod-template-hash unsupported",
			objs: []client.Object{
				ownedPod("frontend-abc123-xyz", rsOwner, nil),
			},
			podName: "frontend-abc123-xyz",
			wantErr: errUnsupportedWorkloadKind,
		},
		{
			name: "statefulset",
			objs: []client.Object{
				ownedPod("db-0", stsOwner, nil),
			},
			podName: "db-0",
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindStatefulSet,
				OwnerName: "db",
			},
		},
		{
			name: "daemonset",
			objs: []client.Object{
				ownedPod("agent-node1", dsOwner, nil),
			},
			podName: "agent-node1",
			want: topology.WorkloadKey{
				Namespace: testNamespace,
				OwnerKind: ownerkind.KindDaemonSet,
				OwnerName: "agent",
			},
		},
		{
			name: "unsupported job owner",
			objs: []client.Object{
				ownedPod("cron-job-1-pod", jobOwner, nil),
			},
			podName: "cron-job-1-pod",
			wantErr: errUnsupportedWorkloadKind,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cl := fake.NewClientBuilder().
				WithScheme(newWorkloadTestScheme(t)).
				WithObjects(tt.objs...).
				Build()

			got, err := workloadKeyFromPod(context.Background(), cl, testNamespace, tt.podName)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
