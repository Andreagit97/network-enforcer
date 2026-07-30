package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
)

// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods;services;namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicyproposals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicies,verbs=get;list;watch

type TopologyScanner struct {
	client                 client.Client
	store                  *topology.Store
	log                    *slog.Logger
	interval               time.Duration
	monitorViolationBuffer *violationbuf.Buffer
	monitorViolationLogger otellog.Logger
}

func NewTopologyScanner(
	c client.Client,
	store *topology.Store,
	logger *slog.Logger,
	drainInterval time.Duration,
	violationBuffer *violationbuf.Buffer,
	eventLogger otellog.Logger,
) *TopologyScanner {
	return &TopologyScanner{
		client:                 c,
		store:                  store,
		log:                    logger.With("component", "topology-scanner"),
		interval:               drainInterval,
		monitorViolationBuffer: violationBuffer,
		monitorViolationLogger: eventLogger,
	}
}

func (ts *TopologyScanner) Start(ctx context.Context) error {
	ts.log.InfoContext(ctx, "starting", "drain interval", ts.interval.String())

	ticker := time.NewTicker(ts.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ts.scan(ctx)
		}
	}
}

func getProposalName(workload topology.WorkloadKey, direction networkingv1.PolicyType) string {
	return fmt.Sprintf(
		"%s-%s-%s",
		strings.ToLower(string(workload.OwnerKind)),
		workload.OwnerName,
		strings.ToLower(string(direction)),
	)
}

func getProposalMetadata(
	workload topology.WorkloadKey,
	direction networkingv1.PolicyType,
) *securityv1alpha1.WorkloadNetworkPolicyProposal {
	return &securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getProposalName(workload, direction),
			Namespace: workload.Namespace,
		},
	}
}

func (ts *TopologyScanner) connectionLogger(
	workload *topology.WorkloadKey,
	direction networkingv1.PolicyType,
) *slog.Logger {
	return ts.log.With(
		slog.Group("connection",
			slog.Group("workload",
				"name", workload.OwnerName,
				"kind", workload.OwnerKind,
				"namespace", workload.Namespace,
			),
			"direction", direction,
		),
	)
}

func (ts *TopologyScanner) updateProposal(
	ctx context.Context,
	workload topology.WorkloadKey,
	direction networkingv1.PolicyType,
	peers sets.Set[topology.Peer],
) error {
	proposal := getProposalMetadata(workload, direction)
	if _, err := controllerutil.CreateOrUpdate(ctx, ts.client, proposal, func() error {
		// we recompute the selector only if we are creating the resource the first time.
		// we could continuously recompute the selector if we want to keep track of updates.
		// the policyTypes should be empty only when the resource is new.
		if len(proposal.Spec.PolicyTypes) == 0 {
			workloadSelector, err := selectorFromWorkloadKey(ctx, ts.client, workload)
			if err != nil {
				return fmt.Errorf("resolving workload selector: %w", err)
			}
			proposal.Spec.PodSelector = workloadSelector
			proposal.Spec.PolicyTypes = []networkingv1.PolicyType{direction}
		}
		return ts.buildSpec(ctx, direction, &proposal.Spec, peers)
	}); err != nil {
		return fmt.Errorf("create or update proposal %s/%s: %w", proposal.Namespace, proposal.Name, err)
	}
	return nil
}

func (ts *TopologyScanner) sendMonitorViolations(
	ctx context.Context,
	workload topology.WorkloadKey,
	policy *securityv1alpha1.WorkloadNetworkPolicy,
	direction networkingv1.PolicyType,
	peers sets.Set[topology.Peer],
) error {
	violations, err := ts.getMonitorViolations(ctx, workload, policy, direction, peers)
	if err != nil {
		return err
	}

	for _, violation := range violations {
		if ts.monitorViolationBuffer.Record(violation) {
			ts.log.WarnContext(ctx, "Monitor violation dropped", "violation", violation)
		}

		if ts.monitorViolationLogger == nil {
			continue
		}

		var rec otellog.Record
		const eventNamePolicyViolationDetected = "policy_violation"
		rec.SetEventName(eventNamePolicyViolationDetected)
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetBody(otellog.StringValue(eventNamePolicyViolationDetected))
		rec.SetTimestamp(time.Now())
		rec.AddAttributes(
			otellog.String("timestamp", violation.Timestamp.UTC().Format(time.RFC3339)),
			otellog.String("direction", string(violation.Direction)),
			otellog.String("source.namespace", violation.SrcNamespace),
			// todo!: the `violationbuf.ViolationRecord` doesn't contain a `kind` field,
			// we need to understand what we want as final format.
			// otellog.String("source.workload.kind", ""),
			otellog.String("source.workload.name", violation.SrcName),
			otellog.String("dest.namespace", violation.DstNamespace),
			// otellog.String("dest.workload.kind", ""),
			otellog.String("dest.workload.name", violation.DstName),
			otellog.String("protocol", string(violation.Protocol)),
			otellog.Int64("dstPort", int64(violation.DstPort)),
			otellog.String("action", string(violation.Action)),
			otellog.String("denyingPolicy.namespace", violation.DenyingPolicyNamespace),
			otellog.String("denyingPolicy.name", violation.DenyingPolicyName),
		)
		ts.monitorViolationLogger.Emit(ctx, rec)
	}

	return nil
}

func newViolationRecord(
	workload topology.WorkloadKey,
	policyName string,
	direction networkingv1.PolicyType,
	peer topology.Peer,
) violationbuf.ViolationRecord {
	violation := violationbuf.ViolationRecord{
		Timestamp:              time.Now(),
		NodeName:               "", // we don't populate it at the moment, since we don't really need it.
		Direction:              direction,
		SrcNamespace:           workload.Namespace,
		SrcName:                workload.OwnerName,
		DstNamespace:           peer.Namespace,
		DstName:                peer.OwnerName,
		Protocol:               peer.Protocol,
		DstPort:                peer.DstPort,
		Action:                 securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
		DenyingPolicyNamespace: workload.Namespace,
		DenyingPolicyName:      policyName,
	}
	// the src and dst are already in the right order if the direction is egress.
	// example: client (src) -> server (dst)
	// In case of ingress direction we have this:
	// example: server (src) -> client (dst)
	// so we need to invert src and dst
	if direction == networkingv1.PolicyTypeIngress {
		violation.SrcNamespace, violation.SrcName, violation.DstNamespace, violation.DstName = violation.DstNamespace, violation.DstName, violation.SrcNamespace, violation.SrcName
	}
	return violation
}

func (ts *TopologyScanner) getMonitorViolations(
	ctx context.Context,
	workload topology.WorkloadKey,
	policy *securityv1alpha1.WorkloadNetworkPolicy,
	direction networkingv1.PolicyType,
	peers sets.Set[topology.Peer],
) ([]violationbuf.ViolationRecord, error) {
	var violations []violationbuf.ViolationRecord
	switch direction {
	case networkingv1.PolicyTypeEgress:
		for _, peer := range peers.UnsortedList() {
			rule, err := ts.buildEgressRuleFromPeer(ctx, peer)
			if err != nil {
				return nil, fmt.Errorf("resolving egress peer selector: %w", err)
			}
			if !containsRule(rule, policy.Spec.PolicyTemplate.Egress, securityv1alpha1.EgressRuleEqual) {
				violations = append(violations, newViolationRecord(workload, policy.Name, direction, peer))
			}
		}
	case networkingv1.PolicyTypeIngress:
		for _, peer := range peers.UnsortedList() {
			rule, err := ts.buildIngressRuleFromPeer(ctx, peer)
			if err != nil {
				return nil, fmt.Errorf("resolving ingress peer selector: %w", err)
			}

			if !containsRule(rule, policy.Spec.PolicyTemplate.Ingress, securityv1alpha1.IngressRuleEqual) {
				violations = append(violations, newViolationRecord(workload, policy.Name, direction, peer))
			}
		}
	default:
		return nil, fmt.Errorf("unknown direction: %s", direction)
	}
	return violations, nil
}

func (ts *TopologyScanner) reconcileConnection(
	ctx context.Context,
	workload topology.WorkloadKey,
	direction networkingv1.PolicyType,
	peers sets.Set[topology.Peer],
) error {
	if peers.Len() == 0 {
		return errors.New("no peers associated to the workload")
	}

	// we first check if we already have a policy associated to the workload.
	// we use the promoted label to associate the policy with the proposal.
	proposalName := getProposalName(workload, direction)
	policies, err := checkExistingPolicy(ctx, ts.client, workload.Namespace, proposalName)
	if err != nil {
		return fmt.Errorf("checking existing policies for %s/%s: %w", workload.Namespace, proposalName, err)
	}

	switch len(policies) {
	case 0:
		// no policy associated with the proposal
		return ts.updateProposal(ctx, workload, direction, peers)
	case 1:
		// we have just one policy
		policy := policies[0]
		// we check the mode
		if policy.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeProtect {
			// we do nothing, the violation are reported by the cni
			return nil
		}
		// we are in monitor mode we need to report violations
		return ts.sendMonitorViolations(ctx, workload, &policy, direction, peers)
	default:
		return errors.New("multiple policies associated with the same proposal")
	}
}

func (ts *TopologyScanner) reconcileConnections(
	ctx context.Context,
	connections map[topology.WorkloadKey]sets.Set[topology.Peer],
	direction networkingv1.PolicyType,
) {
	for workload, peers := range connections {
		ts.connectionLogger(&workload, direction).InfoContext(ctx, "Reconciling connection",
			"peers", len(peers))
		if err := ts.reconcileConnection(ctx, workload, direction, peers); err != nil {
			ts.connectionLogger(&workload, direction).WarnContext(ctx, "Could not reconcile connection",
				"error", err)
		}
	}
}

func (ts *TopologyScanner) scan(ctx context.Context) {
	// todo!: it would be nice to drain only connections that are correctly reconciled.
	// at the moment we just log a warning and we drop the connection.
	// we should implement some strategies to handle this more gracefully.
	connections := ts.store.DrainFlows()
	ts.log.InfoContext(
		ctx,
		"Drain flows",
		"egress policies",
		len(connections.Egress),
		"ingress policies",
		len(connections.Ingress),
	)
	ts.reconcileConnections(ctx, connections.Egress, networkingv1.PolicyTypeEgress)
	ts.reconcileConnections(ctx, connections.Ingress, networkingv1.PolicyTypeIngress)
}

func containsRule[T any](newRule T, existing []T, equalFn func(T, T) bool) bool {
	for _, rule := range existing {
		if equalFn(newRule, rule) {
			return true
		}
	}
	return false
}

func (ts *TopologyScanner) buildSpec(
	ctx context.Context,
	direction networkingv1.PolicyType,
	spec *networkingv1.NetworkPolicySpec,
	deltaPeers sets.Set[topology.Peer],
) error {
	switch direction {
	case networkingv1.PolicyTypeEgress:
		deltaRules, err := ts.buildEgressRules(ctx, deltaPeers)
		if err != nil {
			return err
		}
		for _, rule := range deltaRules {
			if containsRule(rule, spec.Egress, securityv1alpha1.EgressRuleEqual) {
				continue
			}
			spec.Egress = append(spec.Egress, rule)
		}
	case networkingv1.PolicyTypeIngress:
		deltaRules, err := ts.buildIngressRules(ctx, deltaPeers)
		if err != nil {
			return err
		}

		for _, rule := range deltaRules {
			if containsRule(rule, spec.Ingress, securityv1alpha1.IngressRuleEqual) {
				continue
			}
			spec.Ingress = append(spec.Ingress, rule)
		}
	default:
		return fmt.Errorf("unknown direction: %s", direction)
	}

	return nil
}

func (ts *TopologyScanner) buildEgressRuleFromPeer(
	ctx context.Context,
	peer topology.Peer,
) (networkingv1.NetworkPolicyEgressRule, error) {
	policyPeer, policyPort, err := ts.buildPeerRuleParts(ctx, peer)
	if err != nil {
		return networkingv1.NetworkPolicyEgressRule{}, fmt.Errorf("resolving egress peer selector: %w", err)
	}

	return networkingv1.NetworkPolicyEgressRule{
		To:    []networkingv1.NetworkPolicyPeer{policyPeer},
		Ports: []networkingv1.NetworkPolicyPort{policyPort},
	}, nil
}

func (ts *TopologyScanner) buildIngressRuleFromPeer(
	ctx context.Context,
	peer topology.Peer,
) (networkingv1.NetworkPolicyIngressRule, error) {
	policyPeer, policyPort, err := ts.buildPeerRuleParts(ctx, peer)
	if err != nil {
		return networkingv1.NetworkPolicyIngressRule{}, fmt.Errorf("resolving ingress peer selector: %w", err)
	}

	return networkingv1.NetworkPolicyIngressRule{
		From:  []networkingv1.NetworkPolicyPeer{policyPeer},
		Ports: []networkingv1.NetworkPolicyPort{policyPort},
	}, nil
}

func (ts *TopologyScanner) buildEgressRules(
	ctx context.Context,
	peers sets.Set[topology.Peer],
) ([]networkingv1.NetworkPolicyEgressRule, error) {
	peerList := peers.UnsortedList()

	rules := make([]networkingv1.NetworkPolicyEgressRule, 0, len(peerList))
	for _, peer := range peerList {
		rule, err := ts.buildEgressRuleFromPeer(ctx, peer)
		if err != nil {
			return nil, fmt.Errorf("resolving egress peer selector: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (ts *TopologyScanner) buildIngressRules(
	ctx context.Context,
	peers sets.Set[topology.Peer],
) ([]networkingv1.NetworkPolicyIngressRule, error) {
	peerList := peers.UnsortedList()

	rules := make([]networkingv1.NetworkPolicyIngressRule, 0, len(peerList))
	for _, peer := range peerList {
		rule, err := ts.buildIngressRuleFromPeer(ctx, peer)
		if err != nil {
			return nil, fmt.Errorf("resolving ingress peer selector: %w", err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func (ts *TopologyScanner) buildPeerRuleParts(
	ctx context.Context,
	peer topology.Peer,
) (networkingv1.NetworkPolicyPeer, networkingv1.NetworkPolicyPort, error) {
	peerSelector, err := selectorFromWorkloadKey(ctx, ts.client, peer.WorkloadKey)
	if err != nil {
		return networkingv1.NetworkPolicyPeer{}, networkingv1.NetworkPolicyPort{}, err
	}

	port := intstr.FromInt32(peer.DstPort)

	policyPeer := networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				corev1.LabelMetadataName: peer.Namespace,
			},
		},
		PodSelector: &peerSelector,
	}
	policyPort := networkingv1.NetworkPolicyPort{
		Protocol: &peer.Protocol,
		Port:     &port,
	}

	return policyPeer, policyPort, nil
}
