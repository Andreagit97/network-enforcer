package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	otellog "go.opentelemetry.io/otel/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	agentv1 "github.com/rancher-sandbox/network-enforcer/proto/agent/v1"
)

const eventNamePolicyViolationAcknowledged = "policy_violation_acknowledged"

type AgentClientPoolAPI interface {
	UpdatePool(ctx context.Context, reader client.Reader) (map[string]grpcexporter.AgentClientAPI, error)
	MarkStaleAgentClient(nodeName string)
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicies/status,verbs=get;patch;update

// WorkloadNetworkPolicyStatusSync scrapes cniwatcher pods, correlates denies
// to the owning WNP, and writes status/annotations via two-phase patch.
// When eventLogger is set it emits policy_violation_acknowledged after a
// successful status patch (ordering guard, no duplicate logs on retry).
type WorkloadNetworkPolicyStatusSync struct {
	client.Client

	agentClientPool        AgentClientPoolAPI
	updateInterval         time.Duration
	eventLogger            otellog.Logger
	logger                 logr.Logger
	monitorViolationBuffer *violationbuf.Buffer
}

type WorkloadNetworkPolicyStatusSyncConfig struct {
	AgentPoolConf  grpcexporter.AgentClientPoolConfig
	UpdateInterval time.Duration
	// EventLogger for OTLP policy_violation_acknowledged; nil = disabled.
	EventLogger            otellog.Logger
	MonitorViolationBuffer *violationbuf.Buffer
}

func NewWorkloadNetworkPolicyStatusSync(
	c client.Client,
	config *WorkloadNetworkPolicyStatusSyncConfig,
) (*WorkloadNetworkPolicyStatusSync, error) {
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("invalid update interval: %v", config.UpdateInterval)
	}

	return &WorkloadNetworkPolicyStatusSync{
		Client:                 c,
		updateInterval:         config.UpdateInterval,
		eventLogger:            config.EventLogger,
		monitorViolationBuffer: config.MonitorViolationBuffer,
	}, nil
}

// Start implements manager.Runnable. Runs the periodic sync loop.
func (r *WorkloadNetworkPolicyStatusSync) Start(ctx context.Context) error {
	r.logger = log.FromContext(ctx).WithName("WorkloadNetworkPolicyStatusSync")
	interval := r.updateInterval
	r.logger.Info("Starting with", "interval", interval.String())

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Closing")
			return nil
		case <-time.After(interval):
			if err := r.sync(ctx); err != nil {
				r.logger.Error(err, "Failed to sync")
			}
		}
	}
}

func convertMonitorViolations(
	monitorViolation []violationbuf.ViolationRecord,
) []*agentv1.ViolationRecord {
	result := make([]*agentv1.ViolationRecord, 0, len(monitorViolation))
	for _, v := range monitorViolation {
		result = append(result,
			&agentv1.ViolationRecord{
				Timestamp:              timestamppb.New(v.Timestamp),
				NodeName:               v.NodeName,
				Direction:              string(v.Direction),
				SourceNamespace:        v.SrcNamespace,
				SourceName:             v.SrcName,
				SourceWorkloads:        v.SrcWorkloads,
				SourceLabels:           v.SrcLabels,
				DestNamespace:          v.DstNamespace,
				DestName:               v.DstName,
				DestWorkloads:          v.DstWorkloads,
				DestLabels:             v.DstLabels,
				Protocol:               string(v.Protocol),
				DstPort:                v.DstPort,
				Action:                 string(v.Action),
				DenyingPolicyNamespace: v.DenyingPolicyNamespace,
				DenyingPolicyName:      v.DenyingPolicyName,
			})
	}
	return result
}

// sync runs one cycle: discover agents, scrape, correlate, patch.
func (r *WorkloadNetworkPolicyStatusSync) sync(ctx context.Context) error {
	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &wnpList); err != nil {
		return fmt.Errorf("failed to list WorkloadNetworkPolicies: %w", err)
	}
	if len(wnpList.Items) == 0 {
		r.logger.V(1).Info("No WorkloadNetworkPolicies found, skipping sync")
		return nil
	}

	// Build index of WNP by NamespacedName for quick lookup.
	wnpByKey := make(map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy, len(wnpList.Items))
	for i := range wnpList.Items {
		key := types.NamespacedName{Namespace: wnpList.Items[i].Namespace, Name: wnpList.Items[i].Name}
		wnpByKey[key] = &wnpList.Items[i]
	}

	// Build ownership index: NetworkPolicy key -> owning WNP key.
	ownedIndex, err := r.buildOwnershipIndex(ctx, wnpByKey)
	if err != nil {
		return fmt.Errorf("failed to build ownership index: %w", err)
	}

	// monitor violations coming from the topology scraper
	monitorViolation := convertMonitorViolations(r.monitorViolationBuffer.Drain())
	// Group scraped violations by the owning WNP
	violationsByWNP := r.correlateViolationsToWNPs(monitorViolation, ownedIndex, wnpByKey)

	// Process every WNP: those with scraped violations get them merged;
	// those without still get clearAllowedViolations + acknowledgeViolationsFromAnnotations.
	for key, wnp := range wnpByKey {
		if err = r.processWorkloadNetworkPolicy(ctx, wnp, violationsByWNP[key]); err != nil {
			r.logger.Error(err, "Failed to process WorkloadNetworkPolicy",
				"policy", key)
		}
	}

	return nil
}

// buildOwnershipIndex maps NetworkPolicy keys to their owning WNP key.
func (r *WorkloadNetworkPolicyStatusSync) buildOwnershipIndex(
	ctx context.Context,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (map[types.NamespacedName]*types.NamespacedName, error) {
	var npList networkingv1.NetworkPolicyList
	if err := r.List(ctx, &npList); err != nil {
		return nil, fmt.Errorf("failed to list NetworkPolicies: %w", err)
	}

	apiVersion := securityv1alpha1.GroupVersion.String()
	wnpKind := "WorkloadNetworkPolicy"

	index := make(map[types.NamespacedName]*types.NamespacedName, len(npList.Items))
	for _, np := range npList.Items {
		npKey := types.NamespacedName{Namespace: np.Namespace, Name: np.Name}
		if wnpKey, ok := findWNPOwnerRef(
			np.OwnerReferences, np.Namespace, apiVersion, wnpKind, wnpByKey,
		); ok {
			index[npKey] = &wnpKey
		} else {
			// we store a nil pointer to indicate no owner
			index[npKey] = nil
		}
	}
	return index, nil
}

// findWNPOwnerRef returns the owning WNP NamespacedName from a
// NetworkPolicy's OwnerReferences that matches a known WNP.
func findWNPOwnerRef(
	refs []metav1.OwnerReference,
	namespace, apiVersion, kind string,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (types.NamespacedName, bool) {
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller &&
			ref.APIVersion == apiVersion &&
			ref.Kind == kind {
			wnpKey := types.NamespacedName{Namespace: namespace, Name: ref.Name}
			if _, ok := wnpByKey[wnpKey]; ok {
				return wnpKey, true
			}
		}
	}
	return types.NamespacedName{}, false
}

// correlateViolationsToWNPs groups scraped violations by the owning WNP.
// Violations with no owning WNP are dropped; deleted denying NetPols log a warning.
func (r *WorkloadNetworkPolicyStatusSync) correlateViolationsToWNPs(
	scraped []*agentv1.ViolationRecord,
	ownedIndex map[types.NamespacedName]*types.NamespacedName,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) map[types.NamespacedName][]securityv1alpha1.ViolationRecord {
	result := make(map[types.NamespacedName][]securityv1alpha1.ViolationRecord)

	for _, v := range scraped {
		// the k8s network policy should have the same name of the
		// workload network policy.
		wnpKey := types.NamespacedName{
			Namespace: v.GetDenyingPolicyNamespace(),
			Name:      v.GetDenyingPolicyName(),
		}

		// if we don't find a WNP, we can't correlate the violation and so we log a warning
		if _, ok := wnpByKey[wnpKey]; !ok {
			r.logger.Info(
				"Denying WorkloadNetworkPolicy not found; violation may be caused by a policy not managed by us",
				"denyingPolicy",
				wnpKey.String(),
			)
			continue
		}

		// In protect mode it is possible that a k8s network policy has the same name of one of our WNPs
		// but it is not owned by us. if it is the case we should already have some errors when we try
		// to create the WNPs but we check also here to avoid wrong violation assignment
		owner, ok := ownedIndex[wnpKey]
		if ok && owner == nil {
			// we have an error only in case of policy presence and without owner
			r.logger.Error(
				errors.New(
					"found a Network policy with same name of WNP but not managed by us, cannot register violation",
				),
				// todo!: we should use slog.Logger here to be compliant with the repo and to avoid this duplication.
				"found a Network policy with same name of WNP but not managed by us, cannot register violation",
				"denyingPolicy",
				wnpKey.String(),
			)
			continue
		}

		result[wnpKey] = append(result[wnpKey], convertProtoViolation(v))
	}

	return result
}

// convertProtoViolation converts a protobuf ViolationRecord to the API type.
func convertProtoViolation(v *agentv1.ViolationRecord) securityv1alpha1.ViolationRecord {
	ownerKind, ownerName := parseWorkload(v.GetSourceWorkloads())
	if ownerName == "" {
		ownerName = v.GetSourceName()
	}
	source := securityv1alpha1.WorkloadRef{
		Namespace: v.GetSourceNamespace(),
		OwnerKind: ownerKind,
		OwnerName: ownerName,
	}

	destKind, destName := parseWorkload(v.GetDestWorkloads())
	if destName == "" {
		destName = v.GetDestName()
	}
	dest := securityv1alpha1.WorkloadRef{
		Namespace: v.GetDestNamespace(),
		OwnerKind: destKind,
		OwnerName: destName,
	}

	return securityv1alpha1.ViolationRecord{
		ViolationInfo: securityv1alpha1.ViolationInfo{
			Timestamp:              metav1.NewTime(v.GetTimestamp().AsTime()),
			Source:                 source,
			Dest:                   dest,
			Protocol:               corev1.Protocol(v.GetProtocol()),
			DstPort:                v.GetDstPort(),
			Action:                 securityv1alpha1.WorkloadNetworkPolicyMode(v.GetAction()),
			DenyingPolicyNamespace: v.GetDenyingPolicyNamespace(),
			DenyingPolicyName:      v.GetDenyingPolicyName(),
		},
	}
}

// parseWorkload splits the first element of workloads at the first '/'.
// Returns (kind, name) or ("", workload) if no separator is found.
func parseWorkload(workloads []string) (string, string) {
	if len(workloads) == 0 {
		return "", ""
	}
	wl := workloads[0]
	const splitParts = 2
	parts := strings.SplitN(wl, "/", splitParts)
	if len(parts) == splitParts {
		return parts[0], parts[1]
	}
	return "", wl
}

// processWorkloadNetworkPolicy patches status then annotations using a
// MergeFrom base. Acknowledged-violation OTLP logs are emitted only after
// the status patch succeeds (ordering guard — prevents duplicate logs on
// retry), matching the runtime-enforcer approach.
func (r *WorkloadNetworkPolicyStatusSync) processWorkloadNetworkPolicy(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	violations []securityv1alpha1.ViolationRecord,
) error {
	now := metav1.NewTime(time.Now())

	patchBase := client.MergeFrom(wnp.DeepCopy())
	newPolicy := wnp.DeepCopy()

	acknowledged := newPolicy.RecomputeStatus(violations, now)

	r.logger.V(1).Info("Updating WorkloadNetworkPolicy status",
		"policy", wnp.NamespacedName(),
		"violations", len(violations),
		"acknowledged", len(acknowledged),
		"activeCount", newPolicy.Status.ActiveViolationCount)

	if err := r.Status().Patch(ctx, newPolicy.DeepCopy(), patchBase); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy status for %s: %w",
			wnp.NamespacedName(), err)
	}

	r.emitAcknowledgedViolations(ctx, acknowledged)

	if err := r.Patch(ctx, newPolicy.DeepCopy(), patchBase); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy annotations for %s: %w",
			wnp.NamespacedName(), err)
	}

	return nil
}

func (r *WorkloadNetworkPolicyStatusSync) emitAcknowledgedViolations(
	ctx context.Context,
	acknowledgements []securityv1alpha1.AcknowledgedViolationRecord,
) {
	for _, ack := range acknowledgements {
		r.emitAcknowledgedViolationOtelLog(ctx, ack)
	}
}

func (r *WorkloadNetworkPolicyStatusSync) emitAcknowledgedViolationOtelLog(
	ctx context.Context,
	ack securityv1alpha1.AcknowledgedViolationRecord,
) {
	violation := ack.Violation
	var rec otellog.Record
	rec.SetEventName(eventNamePolicyViolationAcknowledged)
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetBody(otellog.StringValue(eventNamePolicyViolationAcknowledged))
	rec.SetTimestamp(time.Now())
	rec.AddAttributes(
		otellog.Int64("id", violation.ID),
		otellog.String("timestamp", violation.Timestamp.UTC().Format(time.RFC3339)),
		otellog.String("reason", ack.Reason),
		otellog.String("source.namespace", violation.Source.Namespace),
		otellog.String("source.workload.kind", violation.Source.OwnerKind),
		otellog.String("source.workload.name", violation.Source.OwnerName),
		otellog.String("dest.namespace", violation.Dest.Namespace),
		otellog.String("dest.workload.kind", violation.Dest.OwnerKind),
		otellog.String("dest.workload.name", violation.Dest.OwnerName),
		otellog.String("protocol", string(violation.Protocol)),
		otellog.Int64("dstPort", int64(violation.DstPort)),
		otellog.String("action", string(violation.Action)),
		otellog.String("denyingPolicy.namespace", violation.DenyingPolicyNamespace),
		otellog.String("denyingPolicy.name", violation.DenyingPolicyName),
	)

	if r.eventLogger != nil {
		r.eventLogger.Emit(ctx, rec)
	}
}

var _ manager.Runnable = (*WorkloadNetworkPolicyStatusSync)(nil)
