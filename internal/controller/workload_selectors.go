package controller

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
)

// workloadRefFromPod fetches the Pod and resolves it to a WorkloadRef.
// Callers should use workload.IsValidEndpoint to decide whether the result is
// supported.
func workloadRefFromPod(
	ctx context.Context,
	c client.Client,
	namespace, podName string,
) (securityv1alpha1.WorkloadRef, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, &pod); err != nil {
		return securityv1alpha1.WorkloadRef{}, fmt.Errorf("getting Pod %s/%s: %w", namespace, podName, err)
	}
	return extractWorkloadRef(&pod), nil
}

// extractWorkloadRef resolves a Pod to its owning workload from controller
// OwnerReferences. Deployment pods are owned by a ReplicaSet; we infer the
// Deployment name from the pod-template-hash label. StatefulSet and DaemonSet
// own pods directly.
//
// Heuristics for additional kinds (Job/CronJob, OpenShift DeploymentConfig)
// live in runtime-enforcer's former getPodInfo and can be ported when needed:
// https://github.com/rancher-sandbox/runtime-enforcer/pull/219/changes#diff-65f18bba13a51ac9c01c9f32f9c222070bb8f3dda11868f44c75889265381f5fL45
func extractWorkloadRef(pod *corev1.Pod) securityv1alpha1.WorkloadRef {
	namespace := pod.Namespace
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return securityv1alpha1.WorkloadRef{
			Namespace: namespace,
			OwnerKind: workload.KindPod,
			OwnerName: pod.Name,
		}
	}

	kind, name := ref.Kind, ref.Name
	if kind == string(workload.KindReplicaSet) {
		hash := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
		if hash == "" || !strings.HasSuffix(name, hash) {
			return securityv1alpha1.WorkloadRef{
				Namespace: namespace,
				OwnerKind: workload.KindReplicaSet,
				OwnerName: name,
			}
		}
		kind = string(workload.KindDeployment)
		name = strings.TrimSuffix(name, "-"+hash)
	}

	return securityv1alpha1.WorkloadRef{
		Namespace: namespace,
		OwnerKind: workload.Kind(kind),
		OwnerName: name,
	}
}

func getProposalName(workloadRef securityv1alpha1.WorkloadRef, direction networkingv1.PolicyType) string {
	return fmt.Sprintf(
		"%s-%s-%s",
		strings.ToLower(string(workloadRef.OwnerKind)),
		workloadRef.OwnerName,
		strings.ToLower(string(direction)),
	)
}

func getProposalMetadata(
	workloadRef securityv1alpha1.WorkloadRef,
	direction networkingv1.PolicyType,
) *securityv1alpha1.WorkloadNetworkPolicyProposal {
	return &securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getProposalName(workloadRef, direction),
			Namespace: workloadRef.Namespace,
		},
	}
}

func lookupPodSelectorForWorkload(
	ctx context.Context,
	c client.Client,
	wk securityv1alpha1.WorkloadRef,
) (metav1.LabelSelector, error) {
	switch wk.OwnerKind { //nolint:exhaustive // we don't support all workload kinds
	case workload.KindDeployment:
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
	case workload.KindStatefulSet:
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
	case workload.KindDaemonSet:
		var ds appsv1.DaemonSet
		if err := c.Get(ctx, types.NamespacedName{Name: wk.OwnerName, Namespace: wk.Namespace}, &ds); err != nil {
			return metav1.LabelSelector{}, fmt.Errorf("looking up DaemonSet %s/%s: %w", wk.Namespace, wk.OwnerName, err)
		}
		return *ds.Spec.Selector, nil
	default:
		return metav1.LabelSelector{}, fmt.Errorf("unsupported workload kind: %s", string(wk.OwnerKind))
	}
}
