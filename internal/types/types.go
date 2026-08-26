package types

import (
	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// todo!: revisit this file, many types should be removed.

type CNIType string

const (
	CNITypeAWSVPC  CNIType = "aws-vpc"
	CNITypeCalico  CNIType = "calico"
	CNITypeCilium  CNIType = "cilium"
	CNITypeFlannel CNIType = "flannel"
	CNITypeUnknown CNIType = "unknown"
)

const (
	DefaultGoldmaneEndpoint = "goldmane.calico-system.svc:7443"
	DefaultHubbleEndpoint   = "unix:///var/run/cilium/hubble.sock"
)

type PodOrServiceType string

const (
	PodOrServiceTypePod             PodOrServiceType = "pod"
	PodOrServiceTypeService         PodOrServiceType = "service"
	PodOrServiceTypeExternalService PodOrServiceType = "external-service"
)

type Protocol string

const (
	ProtocolTCP     Protocol = "TCP"
	ProtocolUDP     Protocol = "UDP"
	ProtocolUnknown Protocol = "Unknown"
)

type Policy struct {
	metav1.TypeMeta `json:",inline"`

	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (p Policy) String() string {
	if p.Namespace != "" {
		return p.APIVersion + "/" + p.Kind + "/" + p.Namespace + "/" + p.Name
	}
	return p.APIVersion + "/" + p.Kind + "/" + p.Name
}

type PolicyDenyEvent struct {
	Timestamp int64  `json:"timestamp"`
	NodeName  string `json:"node_name"`
	// e.g. "aws-vpc", "calico", "cilium", "flannel"
	CNIType string `json:"cni_type"`
	// "TCP", "UDP"
	Protocol     corev1.Protocol `json:"protocol"`
	SrcNamespace string          `json:"source_namespace"`
	SrcName      string          `json:"source_name"`
	SrcLabels    []string        `json:"source_labels"`
	DstNamespace string          `json:"destination_namespace"`
	DstName      string          `json:"destination_name"`
	DstLabels    []string        `json:"destination_labels"`
	SrcWorkloads []string        `json:"source_workloads,omitempty"`
	DstWorkloads []string        `json:"destination_workloads,omitempty"`
	// Destination port. 0 when unavailable (e.g. backends that don't expose it).
	// Calico and Cilium parsers populate this from their flow results.
	DstPort int32 `json:"dst_port,omitempty"`
	// The K8s NetworkPolicies or CiliumNetworkPolicies denying the egress of the flow
	EgressEnforcedBy []Policy `json:"egress_enforced_by,omitempty"`
	// The K8s NetworkPolicies or CiliumNetworkPolicies denying the ingress of the flow
	IngressEnforcedBy []Policy `json:"ingress_enforced_by,omitempty"`
}

type Provider string

const (
	ProviderIstio  Provider = "istio"
	ProviderCilium Provider = "cilium"
	ProviderCalico Provider = "calico"
)

// LearningEvent represents a learning event in the network enforcer.
type LearningEvent struct {
	Source   *securityv1alpha1.WorkloadRef  `json:"source"`
	Dest     *securityv1alpha1.WorkloadRef  `json:"dest"`
	DstPort  int32                          `json:"dst_port"`
	Protocol corev1.Protocol                `json:"protocol"` // "TCP", "UDP"
	Backend  securityv1alpha1.PolicyBackend `json:"backend"`
}
