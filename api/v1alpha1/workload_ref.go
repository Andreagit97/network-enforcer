package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadKind identifies the Kubernetes owner resource kind for a workload.
type WorkloadKind string

const (
	WorkloadKindDeployment  WorkloadKind = "Deployment"
	WorkloadKindStatefulSet WorkloadKind = "StatefulSet"
	WorkloadKindDaemonSet   WorkloadKind = "DaemonSet"
	WorkloadKindReplicaSet  WorkloadKind = "ReplicaSet"
	WorkloadKindPod         WorkloadKind = "Pod"
	WorkloadKindService     WorkloadKind = "Service"
	WorkloadKindCronJob     WorkloadKind = "CronJob"
	WorkloadKindJob         WorkloadKind = "Job"
)

// WorkloadRef identifies a Kubernetes workload.
type WorkloadRef struct {
	// Namespace is the Kubernetes namespace of the workload.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// OwnerKind is the kind of the owner resource.
	// +optional
	OwnerKind WorkloadKind `json:"ownerKind,omitempty"`
	// OwnerName is the name of the owner resource.
	// +optional
	OwnerName string `json:"ownerName,omitempty"`
	// Identity is the istio-specific workload identity.
	// This field is not populated for other providers.
	// +optional
	Identity string `json:"identity,omitempty"`
	// Selector is the label selector for the workload.
	// +optional
	Selector metav1.LabelSelector `json:"selector,omitempty"`
}

func (r *WorkloadRef) IsSupported() bool {
	switch r.OwnerKind { //nolint:exhaustive // some kinds like Service are not valid endpoints for now.
	case WorkloadKindDeployment, WorkloadKindStatefulSet, WorkloadKindDaemonSet:
		return true
	default:
		return false
	}
}

// spiffeIdentity builds the prefix-free Istio principal form for a pod's
// service account. Pods with no explicit service account run as `default`.
func spiffeIdentity(namespace, serviceAccount string) string {
	// istioTrustDomain is the SPIFFE trust domain assumed for source identities
	// resolved from pod state. Istio's default trust domain is cluster.local; the
	// canonical, prefix-free principal form consumed by istioRuleAllowsSource is
	// `<trustDomain>/ns/<namespace>/sa/<serviceAccount>`.
	//
	// LIMITATION: this is fixed to the Istio default. The protect/monitor events
	// carry only the peer address (not src.identity), so the identity is
	// reconstructed here rather than reported. In a mesh configured with a custom
	// trust domain, the reconstructed identity will not equal the learned rule
	// principals, so these violations will not be cleared by istioRuleAllowsSource.
	// Making this configurable (or plumbing the real src.identity through the
	// protect/monitor OTLP events) is left for follow-up.
	const istioTrustDomain = "cluster.local"

	// defaultServiceAccountName is the service account a pod runs as when none is
	// set explicitly, used to reconstruct its SPIFFE identity.
	const defaultServiceAccountName = "default"

	if serviceAccount == "" {
		serviceAccount = defaultServiceAccountName
	}
	return fmt.Sprintf("%s/ns/%s/sa/%s", istioTrustDomain, namespace, serviceAccount)
}

func (r *WorkloadRef) SetIdentity(serviceAccountName string) {
	r.Identity = spiffeIdentity(r.Namespace, serviceAccountName)
}
