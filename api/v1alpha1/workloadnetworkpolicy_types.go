/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// WorkloadNetworkPolicyMode selects how a WorkloadNetworkPolicy is interpreted
// at runtime.
// +kubebuilder:validation:Enum=monitor;protect
type WorkloadNetworkPolicyMode string

const (
	// WorkloadNetworkPolicyModeMonitor records observed traffic against the
	// policy without enforcing it (dry-run).
	WorkloadNetworkPolicyModeMonitor WorkloadNetworkPolicyMode = "monitor"

	// WorkloadNetworkPolicyModeProtect enforces the policy on the cluster.
	WorkloadNetworkPolicyModeProtect WorkloadNetworkPolicyMode = "protect"
)

// WorkloadNetworkPolicySpec defines the desired state of a WorkloadNetworkPolicy.
type WorkloadNetworkPolicySpec struct {
	PolicyBackendSpec `json:",inline"`

	// Mode controls whether the policy is observed (monitor) or actively
	// enforced (protect). Defaults to monitor.
	// +kubebuilder:default=monitor
	// +optional
	Mode WorkloadNetworkPolicyMode `json:"mode,omitempty"`
}

// WorkloadRef identifies a Kubernetes workload by its namespace, owner kind,
// and owner name. Identity is the provider-specific workload identity (SPIFFE
// for Istio, numeric security ID for Cilium, empty for Calico); it is needed
// for exact attribution, e.g. matching Istio principals in a policy rule.
type WorkloadRef struct {
	// Namespace is the Kubernetes namespace of the workload.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// OwnerKind is the kind of the owner resource (e.g. Deployment, StatefulSet,
	// DaemonSet).
	// +optional
	OwnerKind string `json:"ownerKind,omitempty"`
	// OwnerName is the name of the owner resource.
	// +optional
	OwnerName string `json:"ownerName,omitempty"`
	// Identity is the provider-specific workload identity: SPIFFE for Istio,
	// numeric security ID for Cilium, empty for Calico.
	// +optional
	Identity string `json:"identity,omitempty"`
}

// ViolationInfo holds the details of a single network policy violation without
// the controller-assigned ID. Backend scrapers produce observations in this
// shape (see violation.Observation); the controller assigns the ID
// when it persists the record into wnp.Status.Violations.
// +kubebuilder:object:generate=true
type ViolationInfo struct {
	// Timestamp is when the violation last occurred.
	Timestamp metav1.Time `json:"timestamp"`
	// Source is the workload that initiated the traffic.
	// +optional
	Source WorkloadRef `json:"source,omitempty"`
	// Dest is the workload that received the traffic.
	// +optional
	Dest WorkloadRef `json:"dest,omitempty"`
	// Protocol is the L4 protocol (TCP, UDP).
	Protocol corev1.Protocol `json:"protocol"`
	// DstPort is the destination port. 0 when unavailable.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +optional
	DstPort int32 `json:"dstPort,omitempty"`
	// Action is the enforcement action taken (monitor or protect).
	Action WorkloadNetworkPolicyMode `json:"action"`
	// DenyingPolicyNamespace is the namespace of the NetworkPolicy that denied
	// the flow.
	// +optional
	DenyingPolicyNamespace string `json:"denyingPolicyNamespace,omitempty"`
	// DenyingPolicyName is the name of the NetworkPolicy that denied the flow.
	// +optional
	DenyingPolicyName string `json:"denyingPolicyName,omitempty"`
}

// ViolationRecord holds the details of a single network policy violation.
// It embeds ViolationInfo (the violation without the ID) so that the two
// types cannot drift apart: every violation field is defined once, in
// ViolationInfo.
type ViolationRecord struct {
	ViolationInfo `json:",inline"`

	// ID is a per-policy unique identifier allocated by the controller
	// when the record is first observed. It is stable across re-scrapes
	// of the same logical violation, so consumers can refer to a single
	// record by ID (for example when correlating with external events).
	//
	// Stored as int64 (not uint64) for compatibility with the Kubernetes
	// field-management machinery used by controller-runtime's test
	// fixtures; the counter is monotonically increasing and never goes
	// negative, so the sign bit is never set in practice.
	ID int64 `json:"id"`
}

// AcknowledgedViolationRecord wraps a ViolationRecord together with the
// acknowledgement reason and timestamp.
type AcknowledgedViolationRecord struct {
	// Violation is the violation record that was acknowledged.
	Violation ViolationRecord `json:"violation"`
	// Reason is an optional field to indicate why this violation was
	// acknowledged.
	// +optional
	Reason string `json:"reason,omitempty"`
	// AcknowledgedAt is the time when the violation was acknowledged.
	// +optional
	AcknowledgedAt metav1.Time `json:"acknowledgedAt,omitempty"`
}

// WorkloadNetworkPolicyStatus defines the observed state of a
// WorkloadNetworkPolicy.
type WorkloadNetworkPolicyStatus struct {
	// ObservedGeneration is the most recent generation observed for this
	// WorkloadNetworkPolicy. It corresponds to the resource's
	// metadata.generation, which is updated by the API server when the
	// spec changes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ViolationCount is the total number of violation records ever
	// observed for this policy, including those that have already been
	// trimmed out of Violations or cleared because the flow is now
	// permitted by the policy template. It is not guaranteed to be strongly
	// consistent and may be temporarily outdated.
	// +kubebuilder:default=0
	// +optional
	ViolationCount int64 `json:"violationCount"`
	// ActiveViolationCount is the number of currently active (non-cleared)
	// violation records. It is always equal to len(Violations) and is
	// updated in the same status write.
	// +kubebuilder:default=0
	// +optional
	ActiveViolationCount int64 `json:"activeViolationCount"`
	// Violations is the list of the most recent violation records
	// (max maxViolationRecords). Oldest entries are dropped when the
	// limit is reached.
	// +optional
	Violations []ViolationRecord `json:"violations,omitempty"`
	// AcknowledgedViolations is the list of the most recent violation
	// records that have been acknowledged by users (max maxViolationRecords).
	// Oldest entries are dropped when the limit is reached.
	// +optional
	AcknowledgedViolations []AcknowledgedViolationRecord `json:"acknowledgedViolations,omitempty"`
}

// MaxViolationRecords is the maximum number of ViolationRecords and
// AcknowledgedViolationRecords kept in status.
const MaxViolationRecords = 100

// WorkloadNetworkPolicy is the schema for the runtime network policy API.
// Spec carries a backend-specific policy payload (Kubernetes or Istio) and a
// mode (monitor or protect). The resource is intentionally namespaced and uses
// the `security.rancher.io` group to avoid colliding with the upstream
// `networking.k8s.io/NetworkPolicy` kind.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wnp
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Active Violations",type=integer,JSONPath=`.status.activeViolationCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type WorkloadNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec WorkloadNetworkPolicySpec `json:"spec"`
	// +optional
	Status WorkloadNetworkPolicyStatus `json:"status,omitempty"`
}

// WorkloadNetworkPolicyList is a list of WorkloadNetworkPolicy.
// +kubebuilder:object:root=true
type WorkloadNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []WorkloadNetworkPolicy `json:"items"`
}

func (wnp *WorkloadNetworkPolicy) NamespacedName() types.NamespacedName {
	if wnp == nil {
		return types.NamespacedName{}
	}

	return types.NamespacedName{
		Namespace: wnp.Namespace,
		Name:      wnp.Name,
	}
}

func (wnp *WorkloadNetworkPolicy) SetPromotedLabel(proposalName string) error {
	if wnp == nil {
		return errors.New("WorkloadNetworkPolicy is nil")
	}

	// k8s labels must have 63 chars or less.
	// We catch here the error instead of letting the API server handle it.
	const maxLabelValueLength = 63
	if len(proposalName) > maxLabelValueLength {
		return fmt.Errorf("proposalName %q is too long", proposalName)
	}

	if wnp.Labels == nil {
		wnp.SetLabels(map[string]string{})
	}

	wnp.Labels[PolicyPromotedFromLabelKey] = proposalName
	return nil
}

func (wnp *WorkloadNetworkPolicy) HasPromotedLabel(proposalName string) bool {
	if wnp == nil {
		return false
	}
	return wnp.Labels[PolicyPromotedFromLabelKey] == proposalName
}
