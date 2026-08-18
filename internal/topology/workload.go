package topology

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rancher-sandbox/network-enforcer/internal/ownerkind"
)

// WorkloadKeyFromPod fetches the Pod and resolves it to a WorkloadKey.
// Callers should use ownerkind.IsValidEndpoint to decide whether the result is
// supported.
func WorkloadKeyFromPod(
	ctx context.Context,
	c client.Client,
	namespace, podName string,
) (WorkloadKey, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, &pod); err != nil {
		return WorkloadKey{}, fmt.Errorf("getting Pod %s/%s: %w", namespace, podName, err)
	}
	return ExtractWorkloadKey(&pod), nil
}

// ExtractWorkloadKey resolves a Pod to its owning workload from controller
// OwnerReferences. Deployment pods are owned by a ReplicaSet; we infer the
// Deployment name from the pod-template-hash label. StatefulSet and DaemonSet
// own pods directly.
//
// Heuristics for additional kinds (Job/CronJob, OpenShift DeploymentConfig)
// live in runtime-enforcer's former getPodInfo and can be ported when needed:
// https://github.com/rancher-sandbox/runtime-enforcer/pull/219/changes#diff-65f18bba13a51ac9c01c9f32f9c222070bb8f3dda11868f44c75889265381f5fL45
func ExtractWorkloadKey(pod *corev1.Pod) WorkloadKey {
	namespace := pod.Namespace
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return WorkloadKey{
			Namespace: namespace,
			OwnerKind: ownerkind.KindPod,
			OwnerName: pod.Name,
		}
	}

	kind, name := ref.Kind, ref.Name
	if kind == string(ownerkind.KindReplicaSet) {
		hash := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
		if hash == "" || !strings.HasSuffix(name, hash) {
			return WorkloadKey{
				Namespace: namespace,
				OwnerKind: ownerkind.KindReplicaSet,
				OwnerName: name,
			}
		}
		kind = string(ownerkind.KindDeployment)
		name = strings.TrimSuffix(name, "-"+hash)
	}

	return WorkloadKey{
		Namespace: namespace,
		OwnerKind: ownerkind.Kind(kind),
		OwnerName: name,
	}
}
