package e2e_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
)

// ambientNamespaceLabel is the namespace label that enrolls a namespace (and
// the workloads created in it afterwards) in the Istio ambient mesh.
const ambientNamespaceLabel = "istio.io/dataplane-mode"

// istioProvider selects the Istio ambient data-plane provider.
const istioProvider = "istio"

// Istio ambient mesh install (official Istio Helm charts).
const (
	istioRepoURL       = "https://istio-release.storage.googleapis.com/charts"
	istioRepoLocalName = defaultNamespacePref + "-istio"
	istioNamespace     = "istio-system"
	istioChartVersion  = "1.30.3"
)

// istioChartInstall describes a single Helm chart that is part of the Istio
// ambient mesh install.
type istioChartInstall struct {
	releaseName string
	chart       string
	args        []string
}

// installProviderMesh sets up the data-plane provider selected via
// E2E_PROVIDER. Only the Istio provider is supported today; calico and cilium
// will be added back as first-class providers.
func installProviderMesh() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		switch getSuiteConfig(ctx).provider {
		case istioProvider:
			return installIstioMesh()(ctx, cfg)
		default:
			return ctx, fmt.Errorf("unsupported provider: %q", getSuiteConfig(ctx).provider)
		}
	}
}

// installIstioMesh installs an Istio ambient mesh using the official Istio
// Helm charts, in dependency order:
//
//  1. istio/base   — cluster-wide CRDs
//  2. istio/istiod — control plane (pilot), with ambient and authz dry-run support
//  3. istio/cni    — chained CNI node agent, required to redirect ambient
//     workloads' traffic to the per-node ztunnel
//  4. istio/ztunnel — node-level L4 proxy that produces the access logs
//     network-enforcer consumes for learning/monitor/protect
//
// Each chart is installed with --wait so failures are attributable to a single
// component. The version is pinned to match the setup validated in RFC 0004.
func installIstioMesh() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		manager := helm.New(cfg.KubeconfigFile())
		if err := addLocalChartRepo(ctx, manager, istioRepoLocalName, istioRepoURL); err != nil {
			return ctx, err
		}

		logger := getSetupLogger(ctx)
		charts := []istioChartInstall{
			{
				releaseName: "istio-base",
				chart:       istioRepoLocalName + "/base",
				args: []string{
					"--set", "defaultRevision=default",
				},
			},
			{
				releaseName: "istiod",
				chart:       istioRepoLocalName + "/istiod",
				args: []string{
					"--set", "profile=ambient",
					// observe monitor-mode (dry-run) authorization decisions in ztunnel logs
					"--set", "pilot.env.AMBIENT_ENABLE_DRY_RUN_AUTHORIZATION_POLICY=true",
				},
			},
			{
				releaseName: "istio-cni",
				chart:       istioRepoLocalName + "/cni",
				args: []string{
					"--set", "profile=ambient",
				},
			},
			{
				releaseName: "ztunnel",
				chart:       istioRepoLocalName + "/ztunnel",
				args: []string{
					// surface monitor-mode policy decisions in ztunnel logs
					"--set", "env.AUTHZ_POLICY_INFO_LOGGING=true",
					// emit logs as JSON: the istio-fluent-bit pipeline (ztunnel_json
					// parser + Lua) expects the flat dotted-key JSON format
					"--set", "logAsJson=true",
				},
			},
		}

		for _, c := range charts {
			opts := []helm.Option{
				helm.WithName(c.releaseName),
				helm.WithNamespace(istioNamespace),
				helm.WithChart(c.chart),
				helm.WithVersion(istioChartVersion),
				helm.WithArgs("--create-namespace"),
				helm.WithWait(),
				helm.WithTimeout(defaultHelmTimeout.String()),
			}
			for _, arg := range c.args {
				opts = append(opts, helm.WithArgs(arg))
			}
			logger.InfoContext(ctx, "🛠️ installing istio chart",
				"release", c.releaseName, "chart", c.chart, "version", istioChartVersion)
			if err := manager.RunInstall(opts...); err != nil {
				return ctx, fmt.Errorf("install %s chart: %w", c.releaseName, err)
			}
		}

		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("create resources client: %w", err)
		}

		logger.InfoContext(ctx, "⏲️ waiting for istiod")
		if err = wait.For(
			conditions.New(r).DeploymentAvailable("istiod", istioNamespace),
			wait.WithTimeout(defaultOperationTimeout),
		); err != nil {
			return ctx, fmt.Errorf("wait istiod deployment ready: %w", err)
		}

		// ztunnel and istio-cni run as DaemonSets. Every node must be ready
		// before we deploy test workloads, otherwise a pod created before the
		// CNI node agent is ready on its node would bypass the mesh entirely.
		// (the istio-cni chart names its DaemonSet "istio-cni-node").
		for _, dsName := range []string{"ztunnel", "istio-cni-node"} {
			logger.InfoContext(ctx, "⏲️ waiting for "+dsName)
			if err = wait.For(
				conditions.New(r).DaemonSetReady(&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: dsName, Namespace: istioNamespace},
				}),
				wait.WithTimeout(defaultOperationTimeout),
			); err != nil {
				return ctx, fmt.Errorf("wait %s daemonset ready: %w", dsName, err)
			}
		}

		return ctx, nil
	}
}

// labelNamespaceAmbient enrolls the test namespace in the ambient mesh. It must
// run before the test workloads are created: the istio-cni plugin decides, at
// pod creation time, whether to redirect a pod's traffic to the local ztunnel.
func labelNamespaceAmbient(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	r := getSecurityV1Alpha1Client(ctx)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	require.NoError(t, r.Get(ctx, namespace, "", ns), "failed to get test namespace %q", namespace)
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	ns.Labels[ambientNamespaceLabel] = "ambient"
	require.NoError(t, r.Update(ctx, ns), "failed to label test namespace %q as ambient", namespace)
	return ctx
}

// TestIstioLearningFlow is the smoke test for the Istio path: it validates the
// whole learning data path (ztunnel access log → istio-fluent-bit → OTLP →
// istio scraper → learning controller → WorkloadNetworkPolicyProposal) with a
// single TCP connection between two in-mesh workloads.
func TestIstioLearningFlow(t *testing.T) {
	feature := features.New("Istio ambient learning").
		Setup(setupTestNamespace).
		Setup(labelNamespaceAmbient).
		Setup(setupSimpleAppWorkload).
		Assess("Send TCP traffic to the service",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP)
			}).
		Assess("Check the Istio ingress proposal is generated", assessIstioProposalGenerated).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessIstioProposalGenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	expected := v1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment-" + simpleAppServerDeploymentName + "-ingress",
			Namespace: namespace,
		},
		Spec: v1alpha1.WorkloadNetworkPolicyProposalSpec{
			PolicyBackendSpec: v1alpha1.PolicyBackendSpec{
				Backend: v1alpha1.PolicyBackendIstio,
				Istio: &v1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
					},
					Rules: []v1alpha1.IstioAuthorizationPolicyRule{
						{
							From: []v1alpha1.IstioFrom{
								{Source: v1alpha1.IstioSource{
									Principals: []string{istioPrincipal(namespace, simpleAppClientServiceAccount)},
								}},
							},
							To: []v1alpha1.IstioTo{
								{Operation: v1alpha1.IstioOperation{
									Ports: []string{strconv.FormatInt(int64(simpleAppTCPServicePort), 10)},
								}},
							},
						},
					},
				},
			},
		},
	}

	var proposal v1alpha1.WorkloadNetworkPolicyProposal
	require.Eventually(t, func() bool {
		err := getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).
			Get(ctx, expected.Name, namespace, &proposal)
		if err == nil {
			return true
		}
		t.Logf("Istio ingress proposal %q not available yet: %v", expected.Name, err)
		return false
	}, defaultOperationTimeout, 3*time.Second,
		"expected Istio ingress proposal %q was not generated", expected.Name)

	require.Equal(t, expected.Spec.Backend, proposal.Spec.Backend, "proposal backend does not match expected")
	require.NotNil(t, proposal.Spec.Istio, "proposal has no Istio backend spec")
	require.Equal(
		t,
		expected.Spec.Istio.Selector,
		proposal.Spec.Istio.Selector,
		"proposal selector does not match expected",
	)
	require.ElementsMatch(
		t,
		expected.Spec.Istio.Rules,
		proposal.Spec.Istio.Rules,
		"proposal rules do not match expected",
	)

	return ctx
}

// istioPrincipal returns the SPIFFE principal (without the spiffe:// prefix)
// Istio uses to identify a workload in the given namespace and service account.
func istioPrincipal(namespace, serviceAccount string) string {
	return fmt.Sprintf("cluster.local/ns/%s/sa/%s", namespace, serviceAccount)
}
