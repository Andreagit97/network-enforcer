package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

type cniType string

const (
	calico cniType = "calico"
	cilium cniType = "cilium"
)

func addLocalChartRepo(manager *helm.Manager, logger *slog.Logger, localRepoName, repoURL string) error {
	logger.Info("⬇️ adding local helm repo",
		"localName", localRepoName,
		"url", repoURL)
	if err := manager.RunRepo(helm.WithArgs("add", localRepoName, repoURL)); err != nil {
		return fmt.Errorf("failed to add local helm repo: %w", err)
	}
	if err := manager.RunRepo(helm.WithArgs("update")); err != nil {
		return fmt.Errorf("failed to update helm repos: %w", err)
	}
	return nil
}

func installCilium(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
	const (
		namespace     = "kube-system"
		version       = "1.19.4"
		daemonSetName = "cilium"
		operatorName  = "cilium-operator"
		repoLocalName = defaultNamespacePref + "-cilium"
		repoURL       = "https://helm.cilium.io/"
		chartPath     = "/cilium"
	)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	manager := helm.New(cfg.KubeconfigFile())
	// Add the repo locally if not present
	logger.InfoContext(ctx, "adding cilium local repo", "repo", repoLocalName, "url", repoURL)
	if err := manager.RunRepo(helm.WithArgs("add", repoLocalName, repoURL)); err != nil {
		return ctx, fmt.Errorf(
			"failed to add cilium local repo: %w",
			err,
		)
	}
	// Update the repo.
	logger.InfoContext(ctx, "updating helm repos")
	if err := manager.RunRepo(helm.WithArgs("update")); err != nil {
		return ctx, fmt.Errorf(
			"failed to update helm repos : %w",
			err,
		)
	}

	helmOpts := []helm.Option{
		helm.WithName("cilium"),
		helm.WithNamespace(namespace),
		helm.WithChart(repoLocalName + chartPath),
		helm.WithVersion(version),
		helm.WithArgs("--set", "hubble.enabled=true"),
		// with this option cilium sends ICMP packets for egress denied traffic
		helm.WithArgs("--set", "policyDenyResponse=icmp"),

		helm.WithWait(),
		helm.WithTimeout(defaultHelmTimeout.String()),
	}

	logger.InfoContext(ctx, "installing cilium chart", "chart", repoLocalName+chartPath, "version", version)
	if err := manager.RunInstall(helmOpts...); err != nil {
		return ctx, fmt.Errorf("installing cilium chart: %w", err)
	}

	// Wait the Controller to be ready
	r, err := resources.New(cfg.Client().RESTConfig())
	if err != nil {
		return ctx, fmt.Errorf("create resources client: %w", err)
	}

	logger.InfoContext(ctx, "waiting for", "operator", operatorName)
	if err = wait.For(
		conditions.New(r).DeploymentAvailable(operatorName, namespace),
		wait.WithTimeout(defaultOperationTimeout),
	); err != nil {
		return ctx, fmt.Errorf("wait cilium operator deployment ready: %w", err)
	}

	logger.InfoContext(ctx, "waiting for", "daemonset", daemonSetName)
	if err = wait.For(
		conditions.New(r).DaemonSetReady(
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      daemonSetName,
					Namespace: namespace,
				},
			}),
		wait.WithTimeout(defaultOperationTimeout),
	); err != nil {
		return ctx, fmt.Errorf("wait cilium daemonset ready: %w", err)
	}
	return ctx, nil
}

func installCNI(t cniType) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		switch t {
		case calico:
			return installCalico(ctx, cfg)
		case cilium:
			return installCilium(ctx, cfg)
		default:
			return ctx, fmt.Errorf("unknown CNI type: %s", t)
		}
	}
}
