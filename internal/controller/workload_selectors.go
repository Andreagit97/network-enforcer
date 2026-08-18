package controller

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

func getProposalName(wk securityv1alpha1.WorkloadRef, direction networkingv1.PolicyType) string {
	return fmt.Sprintf(
		"%s-%s-%s",
		strings.ToLower(string(wk.OwnerKind)),
		wk.OwnerName,
		strings.ToLower(string(direction)),
	)
}

func getProposalMetadata(
	wk securityv1alpha1.WorkloadRef,
	direction networkingv1.PolicyType,
) *securityv1alpha1.WorkloadNetworkPolicyProposal {
	return &securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getProposalName(wk, direction),
			Namespace: wk.Namespace,
		},
	}
}

func lookupPodSelectorForWorkload(
	ctx context.Context,
	c client.Client,
	wk securityv1alpha1.WorkloadRef,
) (metav1.LabelSelector, error) {
	switch wk.OwnerKind { //nolint:exhaustive // we don't support all workload kinds
	case securityv1alpha1.WorkloadKindDeployment:
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
	case securityv1alpha1.WorkloadKindStatefulSet:
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
	case securityv1alpha1.WorkloadKindDaemonSet:
		var ds appsv1.DaemonSet
		if err := c.Get(ctx, types.NamespacedName{Name: wk.OwnerName, Namespace: wk.Namespace}, &ds); err != nil {
			return metav1.LabelSelector{}, fmt.Errorf("looking up DaemonSet %s/%s: %w", wk.Namespace, wk.OwnerName, err)
		}
		return *ds.Spec.Selector, nil
	default:
		return metav1.LabelSelector{}, fmt.Errorf("unsupported workload kind: %s", string(wk.OwnerKind))
	}
}
