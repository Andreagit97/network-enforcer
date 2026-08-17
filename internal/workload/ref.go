package workload

// Kind identifies the Kubernetes owner resource kind for a workload.
type Kind string

const (
	KindDeployment  Kind = "Deployment"
	KindStatefulSet Kind = "StatefulSet"
	KindDaemonSet   Kind = "DaemonSet"
	KindReplicaSet  Kind = "ReplicaSet"
	KindPod         Kind = "Pod"
	KindService     Kind = "Service"
	KindCronJob     Kind = "CronJob"
)

// Ref identifies a Kubernetes workload by namespace, owner kind and owner name.
type Ref struct {
	// Namespace is the Kubernetes namespace of the workload.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// OwnerKind is the kind of the owner resource (e.g. Deployment, StatefulSet,
	// DaemonSet).
	// +optional
	OwnerKind Kind `json:"ownerKind,omitempty"`
	// OwnerName is the name of the owner resource.
	// +optional
	OwnerName string `json:"ownerName,omitempty"`
	// Identity is the provider-specific workload identity: SPIFFE for Istio,
	// numeric security ID for Cilium, empty for Calico.
	// +optional
	Identity string `json:"identity,omitempty"`
	// Labels are the Kubernetes labels of the workload.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

func IsValidEndpoint(kind Kind) (Kind, bool) {
	switch kind { //nolint:exhaustive // some kinds like Service are not valid endpoints for now.
	case KindDeployment, KindStatefulSet, KindDaemonSet:
		return kind, true
	default:
		return "", false
	}
}
