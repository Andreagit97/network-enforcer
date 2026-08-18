package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	// DefaultEventChannelBufferSize defines the channel buffer size used to
	// deliver events to learning_controller.
	// This is a arbitrary number right now and can be fine-tuned or made configurable in the future.
	defaultEventChannelBufferSize = 4096
)

type LearningReconciler struct {
	client.Client

	Scheme    *runtime.Scheme
	eventChan chan event.TypedGenericEvent[types.LearningEvent]
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicyproposals,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicies,verbs=get;list;watch

func NewLearningReconciler(
	client client.Client,
) *LearningReconciler {
	return &LearningReconciler{
		Client: client,
		eventChan: make(
			chan event.TypedGenericEvent[types.LearningEvent],
			defaultEventChannelBufferSize,
		),
	}
}

func (r *LearningReconciler) GetEnqueueFunc() func(types.LearningEvent) bool {
	return r.enqueueEvent
}

func (r *LearningReconciler) enqueueEvent(evt types.LearningEvent) bool {
	select {
	case r.eventChan <- event.TypedGenericEvent[types.LearningEvent]{Object: evt}:
		return true
	default:
		return false
	}
}

func (r *LearningReconciler) updateProposal(
	ctx context.Context,
	wk securityv1alpha1.WorkloadRef,
	evt types.LearningEvent,
) error {
	// Istio Ambient L4 authorization is enforced on the receiving side,
	// so learning always targets the ingress proposal.
	proposal := getProposalMetadata(wk, networkingv1.PolicyTypeIngress)
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, proposal, func() error {
		// Populate the Istio backend only when creating the resource the first time.
		if proposal.Spec.Istio == nil {
			workloadSelector, err := lookupPodSelectorForWorkload(ctx, r.Client, wk)
			if err != nil {
				return fmt.Errorf("resolving workload selector: %w", err)
			}
			proposal.Spec.Backend = securityv1alpha1.PolicyBackendIstio
			proposal.Spec.Istio = &securityv1alpha1.IstioAuthorizationPolicySpec{
				Selector: workloadSelector,
			}
		}

		upsertIstioLearnedRule(proposal.Spec.Istio, evt.Source.Identity, evt.DstPort)
		return nil
	}); err != nil {
		return fmt.Errorf("create or update proposal %s/%s: %w", proposal.Namespace, proposal.Name, err)
	}
	return nil
}

// upsertIstioLearnedRule merges a learned (principal, port) into the Istio ruleset.
// Learning only updates rules that target exactly one source principal (a single
// From with a single principal). In Istio, every From/principal in a rule shares
// the same To ports, so adding a port to a multi-source rule would also allow
// that port for the other principals. When no such single-principal rule exists,
// a new rule is appended.
func upsertIstioLearnedRule(
	spec *securityv1alpha1.IstioAuthorizationPolicySpec,
	principal, port string,
) {
	for i := range spec.Rules {
		rule := &spec.Rules[i]
		if len(rule.From) != 1 {
			continue
		}
		principals := rule.From[0].Source.Principals
		if len(principals) != 1 || principals[0] != principal {
			continue
		}
		if len(rule.To) == 0 {
			rule.To = []securityv1alpha1.IstioTo{
				{Operation: securityv1alpha1.IstioOperation{Ports: []string{port}}},
			}
			return
		}
		for _, to := range rule.To {
			if slices.Contains(to.Operation.Ports, port) {
				return
			}
		}
		// Port is new, attach it to the first To entry.
		rule.To[0].Operation.Ports = append(rule.To[0].Operation.Ports, port)
		return
	}

	spec.Rules = append(spec.Rules, securityv1alpha1.IstioAuthorizationPolicyRule{
		From: []securityv1alpha1.IstioFrom{
			{Source: securityv1alpha1.IstioSource{Principals: []string{principal}}},
		},
		To: []securityv1alpha1.IstioTo{
			{Operation: securityv1alpha1.IstioOperation{Ports: []string{port}}},
		},
	})
}

func (r *LearningReconciler) processIstioLearningEvent(ctx context.Context, req types.LearningEvent) error {
	// For istio proposals are inbound, so we always need to search for inbound proposal for
	// the destination.
	wk, err := workload.Get(ctx, r.Client, req.Dest.Namespace, req.Dest.OwnerName)
	if err != nil {
		return fmt.Errorf("resolving destination workload for %s/%s: %w", req.Dest.Namespace, req.Dest.OwnerName, err)
	}
	if !wk.IsSupported() {
		return nil
	}

	proposalName := getProposalName(wk, networkingv1.PolicyTypeIngress)
	policies, err := checkExistingPolicy(ctx, r.Client, wk.Namespace, proposalName)
	if err != nil {
		return fmt.Errorf("checking existing policies for %s/%s: %w", wk.Namespace, proposalName, err)
	}

	switch len(policies) {
	case 0:
		// no policy associated with the proposal
		return r.updateProposal(ctx, wk, req)
	case 1:
		// we do nothing, we already have a policy
		return nil
	default:
		return errors.New("multiple policies associated with the same proposal")
	}
}

// Reconcile maintains a retry mechanism with exponential backoff when processing learning events.
func (r *LearningReconciler) Reconcile(
	ctx context.Context,
	req types.LearningEvent,
) (ctrl.Result, error) {
	return ctrl.Result{}, r.processIstioLearningEvent(ctx, req)
}

type ProcessEventHandler struct {
}

func (e ProcessEventHandler) Create(
	_ context.Context,
	_ event.TypedCreateEvent[types.LearningEvent],
	_ workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {

}

func (e ProcessEventHandler) Update(
	_ context.Context,
	_ event.TypedUpdateEvent[types.LearningEvent],
	_ workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {

}

func (e ProcessEventHandler) Delete(
	_ context.Context,
	_ event.TypedDeleteEvent[types.LearningEvent],
	_ workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {

}

func (e ProcessEventHandler) Generic(
	_ context.Context,
	evt event.TypedGenericEvent[types.LearningEvent],
	q workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {
	q.AddRateLimited(evt.Object)
}

// SetupWithManager sets up the controller with the Manager.
func (r *LearningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.TypedControllerManagedBy[types.LearningEvent](mgr).
		Named("learningController").
		WatchesRawSource(
			source.TypedChannel(
				r.eventChan,
				&ProcessEventHandler{},
			),
		).
		Complete(r)
}
