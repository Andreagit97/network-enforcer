package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
)

// PolicyBackend selects which data-plane policy model is used.
// +kubebuilder:validation:Enum=kubernetes;istio
type PolicyBackend string

const (
	PolicyBackendKubernetes PolicyBackend = "kubernetes"
	PolicyBackendIstio      PolicyBackend = "istio"
)

// PolicyBackendSpec contains the backend-specific policy payload.
// +kubebuilder:validation:XValidation:rule="self.backend == 'kubernetes' ? (has(self.kubernetes) && !has(self.istio)) : (self.backend == 'istio' ? (has(self.istio) && !has(self.kubernetes)) : false)",message="backend must match exactly one populated backend spec"
type PolicyBackendSpec struct {
	// Backend selects which backend policy model this object carries.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="backend is immutable"
	Backend PolicyBackend `json:"backend"`

	// Kubernetes contains the policy expressed as a standard Kubernetes
	// NetworkPolicySpec.
	// +optional
	Kubernetes *networkingv1.NetworkPolicySpec `json:"kubernetes,omitempty"`

	// Istio contains a constrained L4 policy model rendered as an Istio
	// AuthorizationPolicy by the reconciler.
	// +optional
	Istio *IstioAuthorizationPolicySpec `json:"istio,omitempty"`
}

func (s PolicyBackendSpec) IsKubernetesBackend() bool {
	return s.Backend == PolicyBackendKubernetes
}
