package workload

import (
	"context"
	"fmt"
	"strings"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Get fetches the Pod and resolves it to a Workload.
func Get(
	ctx context.Context,
	c client.Client,
	namespace, podName string,
) (securityv1alpha1.WorkloadRef, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, &pod); err != nil {
		return securityv1alpha1.WorkloadRef{}, fmt.Errorf("getting Pod %s/%s: %w", namespace, podName, err)
	}
	ref := GetNameAndKind(&pod)
	ref.SetIdentity(pod.Spec.ServiceAccountName)
	labelSelector, err := lookupPodSelectorForWorkload(ctx, c, &ref)
	if err != nil {
		return securityv1alpha1.WorkloadRef{}, fmt.Errorf(
			"failed to lookup %s %s/%s label selector: %w",
			ref.OwnerKind,
			ref.Namespace,
			ref.OwnerName,
			err,
		)
	}
	ref.Selector = *labelSelector
	return ref, nil
}

// GetNameAndKind resolves a Pod to its owning workload from controller
// OwnerReferences. Deployment pods are owned by a ReplicaSet; we infer the
// Deployment name from the pod-template-hash label. StatefulSet and DaemonSet
// own pods directly.
//
// Heuristics for additional kinds (Job/CronJob, OpenShift DeploymentConfig)
// live in runtime-enforcer's former getPodInfo and can be ported when needed:
// https://github.com/rancher-sandbox/runtime-enforcer/pull/219/changes#diff-65f18bba13a51ac9c01c9f32f9c222070bb8f3dda11868f44c75889265381f5fL45
func GetNameAndKind(pod *corev1.Pod) securityv1alpha1.WorkloadRef {
	namespace := pod.Namespace
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return securityv1alpha1.WorkloadRef{
			Namespace: namespace,
			OwnerKind: securityv1alpha1.WorkloadKindPod,
			OwnerName: pod.Name,
		}
	}

	kind, name := ref.Kind, ref.Name
	if kind == string(securityv1alpha1.WorkloadKindReplicaSet) {
		hash := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
		if hash == "" || !strings.HasSuffix(name, hash) {
			return securityv1alpha1.WorkloadRef{
				Namespace: namespace,
				OwnerKind: securityv1alpha1.WorkloadKindReplicaSet,
				OwnerName: name,
			}
		}
		kind = string(securityv1alpha1.WorkloadKindDeployment)
		name = strings.TrimSuffix(name, "-"+hash)
	}

	return securityv1alpha1.WorkloadRef{
		Namespace: namespace,
		OwnerKind: securityv1alpha1.WorkloadKind(kind),
		OwnerName: name,
	}
}

func lookupPodSelectorForWorkload(
	ctx context.Context,
	c client.Client,
	wk *securityv1alpha1.WorkloadRef,
) (*metav1.LabelSelector, error) {
	key := types.NamespacedName{Name: wk.OwnerName, Namespace: wk.Namespace}
	switch wk.OwnerKind { //nolint:exhaustive // we don't support all workload kinds
	case securityv1alpha1.WorkloadKindDeployment:
		var deploy appsv1.Deployment
		if err := c.Get(ctx, key, &deploy); err != nil {
			return nil, err
		}
		return deploy.Spec.Selector, nil
	case securityv1alpha1.WorkloadKindStatefulSet:
		var sts appsv1.StatefulSet
		if err := c.Get(ctx, key, &sts); err != nil {
			return nil, err
		}
		return sts.Spec.Selector, nil
	case securityv1alpha1.WorkloadKindDaemonSet:
		var ds appsv1.DaemonSet
		if err := c.Get(ctx, key, &ds); err != nil {
			return nil, err
		}
		return ds.Spec.Selector, nil
	default:
		return nil, fmt.Errorf("unsupported workload kind: %s", string(wk.OwnerKind))
	}
}
