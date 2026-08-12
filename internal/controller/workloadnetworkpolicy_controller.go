package controller

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

// WorkloadNetworkPolicyReconciler reconciles WorkloadNetworkPolicy resources.
type WorkloadNetworkPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles WorkloadNetworkPolicy create / update / delete.
func (r *WorkloadNetworkPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var wnp securityv1alpha1.WorkloadNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &wnp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if wnp.Spec.IsKubernetesBackend() {
		return ctrl.Result{}, r.reconcileK8sPolicy(ctx, log, &wnp)
	}
	// todo!: implement this logic for istio.
	log.Info("Skipping reconcile for non-kubernetes backend", "backend", wnp.Spec.Backend)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadNetworkPolicy{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Named("workloadnetworkpolicy").
		Complete(r)
}
