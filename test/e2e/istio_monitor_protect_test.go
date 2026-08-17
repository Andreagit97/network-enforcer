package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	"istio.io/api/annotation"
	istiosecurityv1beta1 "istio.io/api/security/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// istioIngressProposalName is the name of the learned ingress proposal for the
// server workload (Istio ambient only produces ingress proposals).
const istioIngressProposalName = "deployment-" + simpleAppServerDeploymentName + "-ingress"

// simpleAppViolatingServerPort is a TCP port the server listens on that is NOT
// part of the learned policy. Traffic to it violates the policy: in monitor
// mode it is observed (dry-run) and still flows, in protect mode it is blocked.
const simpleAppViolatingServerPort = int32(18082)

// TestIstioMonitorProtectFlow exercises the full Istio lifecycle: after the
// learning phase produces a proposal, it promotes it to a monitor policy
// (dry-run AuthorizationPolicy, violations observed but traffic allowed) and
// then to protect mode (real enforcement, violating traffic blocked and
// recorded as a violation).
func TestIstioMonitorProtectFlow(t *testing.T) {
	feature := features.New("Istio ambient monitor and protect").
		Setup(setupTestNamespace).
		Setup(labelNamespaceAmbient).
		Setup(setupSimpleAppWorkload).
		Assess("Learn the client to server flow",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP)
			}).
		Assess("Check the Istio ingress proposal is generated", assessIstioProposalGenerated).
		Assess("Promote the proposal to a monitor policy", promoteIstioProposalToMonitor).
		Assess("Check the monitor AuthorizationPolicy", checkIstioAuthorizationPolicy(v1alpha1.WorkloadNetworkPolicyModeMonitor)).
		Assess("Matching traffic is still allowed in monitor mode", matchingTrafficAllowed).
		Assess("Violating traffic is observed in monitor mode", violatingTrafficObserved).
		Assess("Switch the policy to protect mode", switchIstioPolicyToProtect).
		Assess("Check the protect AuthorizationPolicy", checkIstioAuthorizationPolicy(v1alpha1.WorkloadNetworkPolicyModeProtect)).
		Assess("Matching traffic is still allowed in protect mode", matchingTrafficAllowed).
		Assess("Violating traffic is blocked in protect mode", violatingTrafficBlocked).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

// promoteIstioProposalToMonitor promotes the learned proposal into a
// WorkloadNetworkPolicy in monitor mode and waits for the proposal to be
// consumed.
func promoteIstioProposalToMonitor(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getSecurityV1Alpha1Client(ctx)

	var proposal v1alpha1.WorkloadNetworkPolicyProposal
	require.NoError(t, client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &proposal),
		"failed to get learned proposal %q", istioIngressProposalName)

	proposal.SetPromotionLabel(v1alpha1.WorkloadNetworkPolicyModeMonitor)
	require.NoError(t, client.Update(ctx, &proposal),
		"failed to promote proposal %q to monitor mode", proposal.NamespacedName().String())

	require.Eventually(t, func() bool {
		var policy v1alpha1.WorkloadNetworkPolicy
		return client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &policy) == nil
	}, defaultOperationTimeout, 1*time.Second,
		"WorkloadNetworkPolicy %q was not created after promotion", istioIngressProposalName)

	require.Eventually(t, func() bool {
		var p v1alpha1.WorkloadNetworkPolicyProposal
		return apierrors.IsNotFound(
			client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &p),
		)
	}, defaultOperationTimeout, 1*time.Second,
		"proposal %q was not deleted after promotion", istioIngressProposalName)

	return ctx
}

// checkIstioAuthorizationPolicy asserts the AuthorizationPolicy reconciled from
// the WorkloadNetworkPolicy: same name/namespace, ALLOW action, the learned
// selector and rules, and the dry-run annotation only in monitor mode.
func checkIstioAuthorizationPolicy(
	mode v1alpha1.WorkloadNetworkPolicyMode,
) func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		t.Helper()
		namespace := getNamespace(ctx)
		client := getSecurityV1Alpha1Client(ctx)

		var ap istiosecurityv1.AuthorizationPolicy
		require.Eventually(t, func() bool {
			if err := client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &ap); err != nil {
				t.Logf("AuthorizationPolicy %q not available yet: %v", istioIngressProposalName, err)
				return false
			}
			_, hasDryRun := ap.Annotations[annotation.IoIstioDryRun.Name]
			return (mode == v1alpha1.WorkloadNetworkPolicyModeMonitor) == hasDryRun
		}, defaultOperationTimeout, 1*time.Second,
			"AuthorizationPolicy %q is not in the expected %q state", istioIngressProposalName, mode)

		require.Equal(t, istiosecurityv1beta1.AuthorizationPolicy_ALLOW, ap.Spec.GetAction(),
			"AuthorizationPolicy action does not match expected")
		require.Equal(t,
			map[string]string{"app": simpleAppServerDeploymentName},
			ap.Spec.GetSelector().GetMatchLabels(),
			"AuthorizationPolicy selector does not match expected",
		)

		require.Len(t, ap.Spec.GetRules(), 1, "AuthorizationPolicy should have exactly one rule")
		rule := ap.Spec.GetRules()[0]
		require.Len(t, rule.GetFrom(), 1, "rule should have exactly one From")
		require.Equal(t,
			[]string{istioPrincipal(namespace, simpleAppClientServiceAccount)},
			rule.GetFrom()[0].GetSource().GetPrincipals(),
			"rule principals do not match expected",
		)
		require.Len(t, rule.GetTo(), 1, "rule should have exactly one To")
		require.Equal(t,
			[]string{strconv.FormatInt(int64(simpleAppTCPServicePort), 10)},
			rule.GetTo()[0].GetOperation().GetPorts(),
			"rule ports do not match expected",
		)

		if mode == v1alpha1.WorkloadNetworkPolicyModeMonitor {
			require.Equal(t, "true", ap.Annotations[annotation.IoIstioDryRun.Name],
				"monitor AuthorizationPolicy should carry the dry-run annotation")
		} else {
			require.NotContains(t, ap.Annotations, annotation.IoIstioDryRun.Name,
				"protect AuthorizationPolicy should not carry the dry-run annotation")
		}
		return ctx
	}
}

// matchingTrafficAllowed asserts the client can still reach the server on the
// learned (policy-allowed) port.
func matchingTrafficAllowed(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP)
}

// violatingTrafficObserved sends TCP traffic to a port the policy does not
// allow: in monitor (dry-run) mode the traffic still flows, and the rejection
// is recorded as a monitor violation on the policy.
func violatingTrafficObserved(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	serverPodIP := getServerPodIP(ctx, t)

	require.Eventually(t, func() bool {
		stdout, err := trySendViolatingTraffic(ctx, t, serverPodIP)
		return err == nil && strings.Contains(stdout, violatingPayload)
	}, defaultOperationTimeout, 1*time.Second,
		"violating traffic should still flow in monitor (dry-run) mode")

	assertViolationWithAction(ctx, t, v1alpha1.WorkloadNetworkPolicyModeMonitor)
	return ctx
}

// switchIstioPolicyToProtect flips the WorkloadNetworkPolicy to protect mode.
func switchIstioPolicyToProtect(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getSecurityV1Alpha1Client(ctx)

	require.Eventually(t, func() bool {
		var policy v1alpha1.WorkloadNetworkPolicy
		if err := client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &policy); err != nil {
			return false
		}
		policy.Spec.Mode = v1alpha1.WorkloadNetworkPolicyModeProtect
		return client.Update(ctx, &policy) == nil
	}, defaultOperationTimeout, 1*time.Second,
		"failed to switch policy %q to protect mode", istioIngressProposalName)

	return ctx
}

// violatingTrafficBlocked asserts TCP traffic to the non-policy port is now
// blocked by the enforced AuthorizationPolicy and recorded as a protect
// violation. The destination ztunnel rejects the connection, but the
// client-side nc may still exit 0: the reliable signal is the missing echo.
func violatingTrafficBlocked(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	serverPodIP := getServerPodIP(ctx, t)

	require.Eventually(t, func() bool {
		stdout, err := trySendViolatingTraffic(ctx, t, serverPodIP)
		if strings.Contains(stdout, violatingPayload) {
			t.Logf("violating traffic still echoed in protect mode (err=%v)", err)
			return false
		}
		return true
	}, defaultOperationTimeout, 1*time.Second,
		"violating traffic should be blocked in protect mode")

	assertViolationWithAction(ctx, t, v1alpha1.WorkloadNetworkPolicyModeProtect)
	return ctx
}

const violatingPayload = "violating-e2e-payload"

// trySendViolatingTraffic sends a TCP payload to the server pod on the
// violating port. It returns the exec error so callers can distinguish allowed
// (no error, echoed payload) from blocked (error) traffic.
func trySendViolatingTraffic(
	ctx context.Context,
	t *testing.T,
	serverPodIP string,
) (string, error) {
	t.Helper()
	cmd := []string{
		"sh",
		"-c",
		fmt.Sprintf(
			"printf %s | nc -w 2 %s %d",
			strconv.Quote(violatingPayload),
			serverPodIP,
			simpleAppViolatingServerPort,
		),
	}

	namespace := getNamespace(ctx)
	r := getSecurityV1Alpha1Client(ctx)
	var stdout, stderr bytes.Buffer

	execCtx, cancel := context.WithTimeout(ctx, defaultPodExecTimeout)
	defer cancel()

	err := r.ExecInDeployment(
		execCtx,
		namespace,
		simpleAppClientDeploymentName,
		cmd,
		&stdout,
		&stderr,
	)
	return stdout.String(), err
}

// getServerPodIP returns the IP of the server pod in the test namespace.
func getServerPodIP(ctx context.Context, t *testing.T) string {
	t.Helper()
	namespace := getNamespace(ctx)

	var pods corev1.PodList
	require.NoError(t, getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).List(ctx, &pods),
		"failed to list pods in namespace %q", namespace)
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, simpleAppServerDeploymentName+"-") && pod.Status.PodIP != "" {
			return pod.Status.PodIP
		}
	}
	t.Fatalf("no running server pod found in namespace %q", namespace)
	return ""
}

// assertViolationWithAction polls the policy status until a violation with the
// given action appears, then asserts the Istio ALLOW-miss violation semantics:
// TCP, destination is the server pod, and no denying policy name (Istio only
// reports policy names for explicit DENY policies; ALLOW-miss violations are
// correlated by destination workload).
func assertViolationWithAction(
	ctx context.Context,
	t *testing.T,
	action v1alpha1.WorkloadNetworkPolicyMode,
) {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getSecurityV1Alpha1Client(ctx)

	var policy v1alpha1.WorkloadNetworkPolicy
	require.Eventually(t, func() bool {
		if err := client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &policy); err != nil {
			return false
		}
		for _, v := range policy.Status.Violations {
			if v.Action == action {
				return true
			}
		}
		t.Logf("no %q violation yet; current violations: %+v", action, policy.Status.Violations)
		return false
	}, defaultOperationTimeout, 1*time.Second,
		"expected a %q violation on policy %q", action, istioIngressProposalName)

	require.Equal(t, int64(len(policy.Status.Violations)), policy.Status.ActiveViolationCount,
		"ActiveViolationCount should equal the number of stored violations")
	require.GreaterOrEqual(t, policy.Status.ViolationCount, int64(len(policy.Status.Violations)),
		"ViolationCount should be at least the number of stored violations")

	var found bool
	for _, v := range policy.Status.Violations {
		if v.Action != action {
			continue
		}
		require.Equal(t, corev1.ProtocolTCP, v.Protocol, "violation protocol does not match expected")
		require.Equal(t, namespace, v.Dest.Namespace, "violation destination namespace does not match expected")
		require.True(t, strings.HasPrefix(v.Dest.OwnerName, simpleAppServerDeploymentName+"-"),
			"violation destination should be the server pod, got %q", v.Dest.OwnerName)
		require.Empty(t, v.DenyingPolicyName,
			"ALLOW-miss violations carry no denying policy name (attribution limitation)")
		found = true
		break
	}
	require.True(t, found, "no violation with action %q found for detailed assertion", action)
}
