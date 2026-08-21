package controller

import (
	"fmt"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *LearningReconciler) evaluateMonitorViolation(
	policy securityv1alpha1.WorkloadNetworkPolicy,
	workload *securityv1alpha1.WorkloadRef,
	peer *securityv1alpha1.WorkloadRef,
	protocol corev1.Protocol,
	direction networkingv1.PolicyType,
	dstPort int,
) error {
	policyPeer, policyPort := buildPeerAndPort(peer, protocol, dstPort)
	spec := policy.Spec.Kubernetes
	switch direction {
	case networkingv1.PolicyTypeEgress:
		if !containsEgressPeerPort(spec.Egress, policyPeer, policyPort) {
			return r.sendMonitorViolation(policy.Name, workload, peer, protocol, direction, dstPort)
		}
	case networkingv1.PolicyTypeIngress:
		if !containsIngressPeerPort(spec.Ingress, policyPeer, policyPort) {
			return r.sendMonitorViolation(policy.Name, workload, peer, protocol, direction, dstPort)
		}
	default:
		return fmt.Errorf("unknown policy direction %q", direction)
	}
	return nil
}

func containsEgressPeerPort(
	rules []networkingv1.NetworkPolicyEgressRule,
	peer networkingv1.NetworkPolicyPeer,
	port networkingv1.NetworkPolicyPort,
) bool {
	for _, rule := range rules {
		if len(rule.To) != 1 || !securityv1alpha1.PolicyPeerEqual(rule.To[0], peer) {
			continue
		}
		for _, existingPort := range rule.Ports {
			if securityv1alpha1.PolicyPortEqual(existingPort, port) {
				return true
			}
		}
	}

	return false
}

func containsIngressPeerPort(
	rules []networkingv1.NetworkPolicyIngressRule,
	peer networkingv1.NetworkPolicyPeer,
	port networkingv1.NetworkPolicyPort,
) bool {
	for _, rule := range rules {
		if len(rule.From) != 1 || !securityv1alpha1.PolicyPeerEqual(rule.From[0], peer) {
			continue
		}
		for _, existingPort := range rule.Ports {
			if securityv1alpha1.PolicyPortEqual(existingPort, port) {
				return true
			}
		}
	}

	return false
}

func (r *LearningReconciler) sendMonitorViolation(
	policyName string,
	workload *securityv1alpha1.WorkloadRef,
	peer *securityv1alpha1.WorkloadRef,
	protocol corev1.Protocol,
	direction networkingv1.PolicyType,
	dstPort int,
) error {
	obs := generateViolationObservation(policyName, workload, peer, protocol, direction, dstPort)
	if r.violationBuffer.Record(obs) {
		return fmt.Errorf("violation buffer full, dropping violation observation: %v", obs)
	}
	return nil
}

func generateViolationObservation(
	policyName string,
	workload *securityv1alpha1.WorkloadRef,
	peer *securityv1alpha1.WorkloadRef,
	protocol corev1.Protocol,
	direction networkingv1.PolicyType,
	dstPort int,
) violation.Observation {
	source := *workload
	dest := *peer
	if direction == networkingv1.PolicyTypeIngress {
		source, dest = *peer, *workload
	}

	observation := violation.Observation{
		ViolationInfo: securityv1alpha1.ViolationInfo{
			Timestamp: metav1.NewTime(time.Now()),
			Source:    source,
			Dest:      dest,
			Protocol:  protocol,
			// todo!: the real fix here is to turn all the `dstPort` reference into int32.
			//nolint:gosec // dstPort is always in the range 0 - 65536
			DstPort:                int32(dstPort),
			Action:                 securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
			DenyingPolicyNamespace: workload.Namespace,
			DenyingPolicyName:      policyName,
		},
		Provider: securityv1alpha1.PolicyBackendKubernetes,
	}
	return observation
}
