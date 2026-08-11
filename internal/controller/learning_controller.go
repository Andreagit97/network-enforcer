package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/rancher-sandbox/network-enforcer/internal/topology"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
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
	workload topology.WorkloadKey,
) error {
	// Istio Ambient L4 authorization is enforced on the receiving side,
	// so learning always targets the ingress proposal.
	proposal := getProposalMetadata(workload, networkingv1.PolicyTypeIngress)
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, proposal, func() error {
		// Recompute the selector only when creating the resource the first time.
		if len(proposal.Spec.PolicyTypes) == 0 {
			workloadSelector, err := selectorFromWorkloadKey(ctx, r.Client, workload)
			if err != nil {
				return fmt.Errorf("resolving workload selector: %w", err)
			}
			proposal.Spec.PodSelector = workloadSelector
			proposal.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
		}
		// todo!: implement the proposal population
		return nil
	}); err != nil {
		return fmt.Errorf("create or update proposal %s/%s: %w", proposal.Namespace, proposal.Name, err)
	}
	return nil
}

func (r *LearningReconciler) processIstioLearningEvent(ctx context.Context, req types.LearningEvent) error {
	// For istio proposals are inbound, so we always need to search for inbound proposal for
	// the destination.
	if req.DstName == "" || req.DstNamespace == "" {
		return nil
	}

	workload, err := workloadKeyFromPod(ctx, r.Client, req.DstNamespace, req.DstName)
	if err != nil {
		if errors.Is(err, errUnsupportedWorkloadKind) {
			return nil
		}
		return fmt.Errorf("resolving destination workload for %s/%s: %w", req.DstNamespace, req.DstName, err)
	}

	proposalName := getProposalName(workload, networkingv1.PolicyTypeIngress)
	policies, err := checkExistingPolicy(ctx, r.Client, workload.Namespace, proposalName)
	if err != nil {
		return fmt.Errorf("checking existing policies for %s/%s: %w", workload.Namespace, proposalName, err)
	}

	switch len(policies) {
	case 0:
		// no policy associated with the proposal
		return r.updateProposal(ctx, workload)
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
