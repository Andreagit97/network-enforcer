package e2e_test

import (
	"context"
	"testing"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

func assertEqualKubernetesWNPP(
	t assert.TestingT,
	expected, actual securityv1alpha1.WorkloadNetworkPolicyProposal,
) {
	// Metadata
	assert.Equal(t, expected.Name, actual.Name, "network policy proposal name does not match expected")
	assert.Equal(t, expected.Namespace, actual.Namespace, "network policy proposal namespace does not match expected")
	assert.Equal(
		t,
		expected.Spec.Backend,
		actual.Spec.Backend,
		"network policy proposal backend does not match expected",
	)
	assert.NotNil(t, actual.Spec.Kubernetes, "network policy proposal kubernetes spec is nil")
	k8sPolicySpec := actual.Spec.Kubernetes
	expectedK8sPolicySpec := expected.Spec.Kubernetes

	// Spec
	assert.ElementsMatch(
		t,
		expectedK8sPolicySpec.PolicyTypes,
		k8sPolicySpec.PolicyTypes,
		"network policy proposal policy types do not match expected",
	)
	assert.Equal(
		t,
		expectedK8sPolicySpec.PodSelector,
		k8sPolicySpec.PodSelector,
		"network policy proposal pod selector does not match expected",
	)
	assert.ElementsMatch(
		t,
		expectedK8sPolicySpec.Ingress,
		k8sPolicySpec.Ingress,
		"network policy proposal ingress rules do not match expected",
	)
	assert.ElementsMatch(
		t,
		expectedK8sPolicySpec.Egress,
		k8sPolicySpec.Egress,
		"network policy proposal egress rules do not match expected",
	)
}

const neverAssertionTime = 7 * time.Second

func TestKubernetesFlow(t *testing.T) {
	if !loadSuiteConfig().IsKubernetesProvider() {
		t.Skip("Skipping Kubernetes flow test: selected provider is not cilium or calico")
	}

	feature := features.New("Kubernetes learning, monitor and protect").
		Setup(setupTestNamespace).
		Setup(setupSimpleAppWorkload).
		Assess("Learn the client to server flow",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppTCPServicePort)
			}).
		Assess("Check the Kubernetes proposals are generated", assessKubernetesProposalGenerated).
		Assess("Promote proposals into monitor policies", assessPolicyProposalsPromoted).
		Assess("Send traffic to UDP service in monitor mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolUDP, simpleAppUDPServicePort)
			}).
		Assess("Check violations in monitor mode", assessViolationsInMonitorMode).
		Assess("Check proposals are not regenerated in monitor mode", assessProposalsAreNotRegenerated).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessKubernetesProposalGenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	tcpProtocol := corev1.ProtocolTCP
	udpProtocol := corev1.ProtocolUDP
	dstPort := intstr.FromInt32(simpleAppTCPServicePort)
	dnsPort := intstr.FromInt32(53)

	expectedClientEgressProposal := securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment-" + simpleAppClientDeploymentName + "-egress",
			Namespace: namespace,
		},
		Spec: securityv1alpha1.WorkloadNetworkPolicyProposalSpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": simpleAppClientDeploymentName},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port:     &dstPort,
									Protocol: &tcpProtocol,
								},
							},
							To: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{corev1.LabelMetadataName: namespace},
									},
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
									},
								},
							},
						},
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port:     &dnsPort,
									Protocol: &udpProtocol,
								},
							},
							To: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{corev1.LabelMetadataName: "kube-system"},
									},
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"k8s-app": "kube-dns"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	expectedServerIngressProposal := securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment-" + simpleAppServerDeploymentName + "-ingress",
			Namespace: namespace,
		},
		Spec: securityv1alpha1.WorkloadNetworkPolicyProposalSpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{corev1.LabelMetadataName: namespace},
									},
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": simpleAppClientDeploymentName},
									},
								},
							},
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port:     &dstPort,
									Protocol: &tcpProtocol,
								},
							},
						},
					},
				},
			},
		},
	}

	var proposals securityv1alpha1.WorkloadNetworkPolicyProposalList
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		err := getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).List(ctx, &proposals)
		assert.NoError(c, err, "failed to list network policy proposals")
		if err != nil {
			return
		}

		proposalsByName := make(map[string]securityv1alpha1.WorkloadNetworkPolicyProposal, len(proposals.Items))
		for _, proposal := range proposals.Items {
			proposalsByName[proposal.Name] = proposal
		}

		clientEgressProposal, found := proposalsByName[expectedClientEgressProposal.Name]
		if assert.True(c, found, "expected client egress policy proposal was not generated") {
			assertEqualKubernetesWNPP(c, expectedClientEgressProposal, clientEgressProposal)
		}

		serverIngressProposal, found := proposalsByName[expectedServerIngressProposal.Name]
		if assert.True(c, found, "expected server ingress policy proposal was not generated") {
			assertEqualKubernetesWNPP(c, expectedServerIngressProposal, serverIngressProposal)
		}
	}, defaultOperationTimeout, 3*time.Second, "expected policy proposals were not generated")

	require.Len(t, proposals.Items, 2, "expected exactly 2 policy proposals to be generated")
	// We return the proposals so that other tests can use them
	return context.WithValue(ctx, key("proposals"), proposals.Items)
}

func assessPolicyProposalsPromoted(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()

	// we recover the proposal from the context.
	proposals := ctx.Value(key("proposals")).([]securityv1alpha1.WorkloadNetworkPolicyProposal)
	client := getSecurityV1Alpha1Client(ctx)

	policies := make([]securityv1alpha1.WorkloadNetworkPolicy, 0, len(proposals))
	for _, proposal := range proposals {
		// We promote the proposal to a policy.
		require.Eventually(t, func() bool {
			proposal.SetPromotionLabel(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)
			return client.Update(ctx, &proposal) == nil
		}, defaultOperationTimeout, 1*time.Second,
			"failed to promote network policy proposal %q", proposal.NamespacedName().String())

		// We expect the policy to be created.
		var policy securityv1alpha1.WorkloadNetworkPolicy
		require.Eventually(t, func() bool {
			return client.Get(ctx, proposal.Name, proposal.Namespace, &policy) == nil
		}, defaultOperationTimeout, 1*time.Second, "Network policy %q is not created", proposal.NamespacedName().String())

		// Check the policy specs are correct.
		require.True(t, policy.HasPromotedLabel(proposal.Name))
		require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, policy.Spec.Mode)
		require.Equal(t, proposal.Spec.PolicyBackendSpec, policy.Spec.PolicyBackendSpec)
		policies = append(policies, policy)

		// We expect the proposal to be deleted
		require.Eventually(t, func() bool {
			return apierrors.IsNotFound(client.Get(ctx, proposal.Name, proposal.Namespace, &proposal))
		}, defaultOperationTimeout, 1*time.Second, "network policy proposal %q was not deleted", proposal.NamespacedName().String())
	}
	return context.WithValue(ctx, key("policies"), policies)
}

func assessViolationsInMonitorMode(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
	client := getSecurityV1Alpha1Client(ctx)

	for _, storedPolicy := range storedPolicies {
		require.Never(t, func() bool {
			var policy securityv1alpha1.WorkloadNetworkPolicy
			if err := client.Get(ctx, storedPolicy.Name, storedPolicy.Namespace, &policy); err != nil {
				return false
			}
			// the spec shouldn't change
			return !apiequality.Semantic.DeepEqual(storedPolicy.Spec.PolicyBackendSpec, policy.Spec.PolicyBackendSpec)
		}, neverAssertionTime, 1*time.Second, "Network policy is updated, but it should not be", storedPolicy.NamespacedName().String())

		var policy securityv1alpha1.WorkloadNetworkPolicy
		require.Eventually(t, func() bool {
			if err := client.Get(ctx, storedPolicy.Name, storedPolicy.Namespace, &policy); err != nil {
				return false
			}

			if len(policy.Status.Violations) == 0 {
				t.Logf("Network policy %q has no violations", policy.NamespacedName().String())
				return false
			}
			return true
		}, defaultOperationTimeout, 1*time.Second)

		// Both ingress and egress policy should have a violation since the traffic is flowing in the cluster.
		namespace := getNamespace(ctx)
		require.Len(t, policy.Status.Violations, 1)
		require.Empty(t, policy.Status.AcknowledgedViolations)
		require.Equal(t, int64(1), policy.Status.ViolationCount)
		require.Equal(t, int64(1), policy.Status.ActiveViolationCount)
		violation := policy.Status.Violations[0]
		require.Equal(t, simpleAppClientDeploymentName, violation.Source.OwnerName)
		require.Equal(t, securityv1alpha1.WorkloadKindDeployment, violation.Source.OwnerKind)
		require.Equal(t, namespace, violation.Source.Namespace)
		require.Equal(t, simpleAppServerDeploymentName, violation.Dest.OwnerName)
		require.Equal(t, securityv1alpha1.WorkloadKindDeployment, violation.Dest.OwnerKind)
		require.Equal(t, namespace, violation.Dest.Namespace)
		require.Equal(t, corev1.ProtocolUDP, violation.Protocol)
		require.Equal(t, simpleAppUDPServerPort, violation.DstPort)
		require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, violation.Action)
		require.Equal(t, policy.Name, violation.DenyingPolicyName)
		require.Equal(t, policy.Namespace, violation.DenyingPolicyNamespace)
	}
	return ctx
}

func assessProposalsAreNotRegenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()

	// we recover the proposal from the context.
	storedProposals := ctx.Value(key("proposals")).([]securityv1alpha1.WorkloadNetworkPolicyProposal)
	client := getSecurityV1Alpha1Client(ctx)

	for _, proposal := range storedProposals {
		require.Never(t, func() bool {
			var p securityv1alpha1.WorkloadNetworkPolicyProposal
			// the error should be always not found
			return !apierrors.IsNotFound(client.Get(ctx, proposal.Name, proposal.Namespace, &p))
		}, neverAssertionTime, 1*time.Second, "Network policy proposal %q is created, but it should not be", proposal.NamespacedName().String())
	}
	return ctx
}
