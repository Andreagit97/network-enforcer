package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rancher-sandbox/network-enforcer/internal/ownerkind"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
)

// errUnsupportedWorkloadKind is returned when a pod's controlling owner is not
// a supported workload kind (Deployment, StatefulSet, DaemonSet).
var errUnsupportedWorkloadKind = errors.New("unsupported workload kind")

// workloadKeyFromPod resolves a Pod to its owning workload from the pod's
// controller OwnerReference. Deployment pods are owned by a ReplicaSet; we
// infer the Deployment name from the pod-template-hash label.
// StatefulSet and DaemonSet own pods directly.
func workloadKeyFromPod(
	ctx context.Context,
	c client.Client,
	namespace, podName string,
) (topology.WorkloadKey, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, &pod); err != nil {
		return topology.WorkloadKey{}, fmt.Errorf("getting Pod %s/%s: %w", namespace, podName, err)
	}

	ref := metav1.GetControllerOf(&pod)
	if ref == nil {
		return topology.WorkloadKey{}, fmt.Errorf("pod %s/%s has no controller owner", namespace, podName)
	}

	kind, name := ref.Kind, ref.Name
	if kind == string(ownerkind.KindReplicaSet) {
		hash := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
		if hash == "" || !strings.HasSuffix(name, hash) {
			return topology.WorkloadKey{}, fmt.Errorf("%w: %s", errUnsupportedWorkloadKind, ownerkind.KindReplicaSet)
		}
		kind = string(ownerkind.KindDeployment)
		name = strings.TrimSuffix(name, "-"+hash)
	}

	ownerKind, ok := ownerkind.IsValidEndpoint(kind)
	if !ok {
		return topology.WorkloadKey{}, fmt.Errorf("%w: %s", errUnsupportedWorkloadKind, kind)
	}

	return topology.WorkloadKey{
		Namespace: namespace,
		OwnerKind: ownerKind,
		OwnerName: name,
	}, nil
}

func lookupPodSelectorForWorkload(
	ctx context.Context,
	c client.Client,
	wk topology.WorkloadKey,
) (metav1.LabelSelector, error) {
	switch wk.OwnerKind { //nolint:exhaustive // we don't support all workload kinds
	case ownerkind.KindDeployment:
		var deploy appsv1.Deployment
		if err := c.Get(ctx, types.NamespacedName{Name: wk.OwnerName, Namespace: wk.Namespace}, &deploy); err != nil {
			return metav1.LabelSelector{}, fmt.Errorf(
				"looking up Deployment %s/%s: %w",
				wk.Namespace,
				wk.OwnerName,
				err,
			)
		}
		return *deploy.Spec.Selector, nil
	case ownerkind.KindStatefulSet:
		var sts appsv1.StatefulSet
		if err := c.Get(ctx, types.NamespacedName{Name: wk.OwnerName, Namespace: wk.Namespace}, &sts); err != nil {
			return metav1.LabelSelector{}, fmt.Errorf(
				"looking up StatefulSet %s/%s: %w",
				wk.Namespace,
				wk.OwnerName,
				err,
			)
		}
		return *sts.Spec.Selector, nil
	case ownerkind.KindDaemonSet:
		var ds appsv1.DaemonSet
		if err := c.Get(ctx, types.NamespacedName{Name: wk.OwnerName, Namespace: wk.Namespace}, &ds); err != nil {
			return metav1.LabelSelector{}, fmt.Errorf("looking up DaemonSet %s/%s: %w", wk.Namespace, wk.OwnerName, err)
		}
		return *ds.Spec.Selector, nil
	default:
		return metav1.LabelSelector{}, fmt.Errorf("unsupported workload kind: %s", string(wk.OwnerKind))
	}
}
