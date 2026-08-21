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
		Assess("Check the Kubernetes ingress proposal is generated", assessKubernetesProposalGenerated).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessKubernetesProposalGenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	// todo!: use corev1 default value
	const namespaceLabelKey = "kubernetes.io/metadata.name"
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
										MatchLabels: map[string]string{namespaceLabelKey: namespace},
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
										MatchLabels: map[string]string{namespaceLabelKey: "kube-system"},
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
										MatchLabels: map[string]string{namespaceLabelKey: namespace},
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
