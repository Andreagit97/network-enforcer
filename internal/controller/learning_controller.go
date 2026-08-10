package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	proposalName, proposalNamespace string,
) error {
	proposal := &securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proposalName,
			Namespace: proposalNamespace,
		},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, proposal, func() error {
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
	// todo!: for now we use the name of the pod not the workload. we need to change this in the future.
	proposalName := req.DstName + "-" + strings.ToLower(string(networkingv1.PolicyTypeIngress))

	policies, err := checkExistingPolicy(ctx, r.Client, req.DstNamespace, proposalName)
	if err != nil {
		return fmt.Errorf("checking existing policies for %s/%s: %w", req.DstNamespace, proposalName, err)
	}

	switch len(policies) {
	case 0:
		// no policy associated with the proposal
		return r.updateProposal(ctx, proposalName, req.DstNamespace)
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
