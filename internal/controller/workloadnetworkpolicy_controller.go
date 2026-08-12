package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

// WorkloadNetworkPolicyReconciler reconciles WorkloadNetworkPolicy resources.
//
// In protect mode it creates/updates the corresponding
// networking.k8s.io/NetworkPolicy owned by the WorkloadNetworkPolicy.
// In monitor mode it ensures the NetworkPolicy is absent, so that flipping
// mode from protect to monitor removes data-plane enforcement.
type WorkloadNetworkPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles WorkloadNetworkPolicy create / update / delete.
//
// When spec.mode is "protect" the reconciler ensures a
// networking.k8s.io/NetworkPolicy exists with spec matching
// spec.policyTemplate and an owner reference pointing to the
// WorkloadNetworkPolicy (so that deleting the WNP garbage-collects
// the NetworkPolicy).
//
// When spec.mode is "monitor" the reconciler ensures the NetworkPolicy
// is absent.
func (r *WorkloadNetworkPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var wnp securityv1alpha1.WorkloadNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &wnp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !wnp.Spec.IsKubernetesBackend() {
		// todo!: implement this logic for istio.
		log.Info("Skipping reconcile for non-kubernetes backend", "backend", wnp.Spec.Backend)
		return ctrl.Result{}, nil
	}

	if wnp.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeProtect {
		return r.reconcileProtect(ctx, log, &wnp)
	}

	return r.reconcileMonitor(ctx, log, &wnp)
}

func (r *WorkloadNetworkPolicyReconciler) reconcileProtect(
	ctx context.Context,
	log logr.Logger,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) (ctrl.Result, error) {
	if err := r.validateOwnership(ctx, wnp); err != nil {
		return ctrl.Result{}, err
	}

	desired := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wnp.Name,
			Namespace: wnp.Namespace,
		},
	}

	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, desired, func() error {
		wnp.Spec.Kubernetes.DeepCopyInto(&desired.Spec)

		return controllerutil.SetControllerReference(wnp, desired, r.Scheme)
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to reconcile NetworkPolicy: %w", err)
	}

	log.Info("Reconciled NetworkPolicy", "name", desired.Name, "namespace", desired.Namespace)
	return ctrl.Result{}, nil
}

func (r *WorkloadNetworkPolicyReconciler) reconcileMonitor(
	ctx context.Context,
	log logr.Logger,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) (ctrl.Result, error) {
	if err := r.validateOwnership(ctx, wnp); err != nil {
		return ctrl.Result{}, err
	}

	existing := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wnp.Name,
			Namespace: wnp.Namespace,
		},
	}

	err := r.Delete(ctx, existing)
	if err == nil {
		log.Info("Deleted NetworkPolicy", "name", existing.Name, "namespace", existing.Namespace)
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to delete NetworkPolicy: %w", err)
	}

	return ctrl.Result{}, nil
}

// validateOwnership checks that any existing NetworkPolicy with the same name
// as wnp is owned by this WorkloadNetworkPolicy. Returns nil if no NetworkPolicy
// exists or if the existing one is properly owned.
func (r *WorkloadNetworkPolicyReconciler) validateOwnership(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) error {
	key := client.ObjectKey{Name: wnp.Name, Namespace: wnp.Namespace}
	existing := &networkingv1.NetworkPolicy{}
	if err := r.Get(ctx, key, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get NetworkPolicy: %w", err)
		}
		return nil
	}
	if !metav1.IsControlledBy(existing, wnp) {
		return fmt.Errorf(
			"refusing to manage existing NetworkPolicy %s/%s not controlled by WorkloadNetworkPolicy",
			existing.Namespace,
			existing.Name,
		)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadNetworkPolicy{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Named("workloadnetworkpolicy").
		Complete(r)
}
