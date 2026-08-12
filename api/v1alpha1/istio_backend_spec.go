package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type IstioAuthorizationPolicySpec struct {
	// Selector selects the destination workloads where the policy is enforced.
	Selector metav1.LabelSelector `json:"selector"`

	// Rules is the ruleset.
	// +optional
	Rules []IstioAuthorizationPolicyRule `json:"rules,omitempty"`
}

type IstioAuthorizationPolicyRule struct {
	// From defines source identities for the rule.
	// +optional
	From []IstioFrom `json:"from,omitempty"`

	// To defines destination operations for the rule.
	// +optional
	To []IstioTo `json:"to,omitempty"`
}

type IstioFrom struct {
	// Source defines the source identities for the rule.
	// +optional
	Source IstioSource `json:"source,omitempty"`
}

type IstioSource struct {
	// Principals are the source SPIFFE identities.
	// +optional
	Principals []string `json:"principals,omitempty"`
}

type IstioTo struct {
	// Operation defines the destination operations for the rule.
	// +optional
	Operation IstioOperation `json:"operation,omitempty"`
}

type IstioOperation struct {
	// Ports is the list of destination ports.
	// +optional
	Ports []string `json:"ports,omitempty"`
}
