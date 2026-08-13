package e2e_test

import (
	"os"
	"slices"
	"strings"
	"time"
)

const (
	defaultChartPath               = "../../charts/network-enforcer"
	defaultLogsDir                 = "./logs"
	defaultControllerImage         = "ghcr.io/rancher-sandbox/network-enforcer/controller:latest"
	defaultReleaseName             = "network-enforcer"
	defaultReleaseNS               = "network-enforcer"
	defaultNamespacePref           = "network-enforcer-e2e"
	defaultKindConfigPath          = "./clusters/istio.yaml"
	defaultWnpStatusUpdateInterval = 3 * time.Second // we reduce the time here to have faster feedback from the controller

	// Istio ambient mesh install (official Istio Helm charts).
	istioRepoURL       = "https://istio-release.storage.googleapis.com/charts"
	istioRepoLocalName = defaultNamespacePref + "-istio"
	istioNamespace     = "istio-system"
	istioChartVersion  = "1.30.3"
)

const (
	defaultHelmTimeout      = 3 * time.Minute
	defaultOperationTimeout = 2 * time.Minute
	defaultPodExecTimeout   = 45 * time.Second

	// Environment variables used in e2e tests.
	// the value of this envVar is the name of the cluster to create.
	installClusterOnlyEnvVar = "E2E_INSTALL_CLUSTER_ONLY"
	// set to "true" to skip cluster creation, image loading, and cluster destroy.
	useExistingClusterEnvVar = "E2E_USE_EXISTING_CLUSTER"
	// comma-separated list of optional dependencies to install: "istio", "cert-manager".
	// Empty/unset means all. "none" means none.
	e2eDependenciesEnvVar = "E2E_DEPENDENCIES"
)

type suiteConfig struct {
	kindConfigPath          string
	logsDir                 string
	chartPath               string
	releaseName             string
	releaseNS               string
	controllerImage         string
	namespacePrefix         string
	wnpStatusUpdateInterval time.Duration
	installClusterOnly      string
	useExistingCluster      bool
	hasNoDependencies       bool
	dependencies            []string
}

func loadSuiteConfig() suiteConfig {
	dependencies := os.Getenv(e2eDependenciesEnvVar)
	return suiteConfig{
		logsDir:                 defaultLogsDir,
		chartPath:               defaultChartPath,
		releaseName:             defaultReleaseName,
		releaseNS:               defaultReleaseNS,
		controllerImage:         defaultControllerImage,
		namespacePrefix:         defaultNamespacePref,
		kindConfigPath:          defaultKindConfigPath,
		wnpStatusUpdateInterval: defaultWnpStatusUpdateInterval,
		installClusterOnly:      readEnvOrDefault(installClusterOnlyEnvVar, ""),
		useExistingCluster:      readEnvOrDefault(useExistingClusterEnvVar, "") != "",
		hasNoDependencies:       dependencies == "none",
		dependencies: func() []string {
			if d := strings.TrimSpace(dependencies); d != "" {
				return strings.Split(d, ",")
			}
			return nil
		}(),
	}
}

func readEnvOrDefault(name, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	return value
}

// hasE2EDependency returns true if name is an active e2e dependency.
// An empty E2E_DEPENDENCIES value means all dependencies are active.
// The special value "none" disables all.
func (c *suiteConfig) HasE2EDependency(name string) bool {
	if c.hasNoDependencies {
		return false
	}
	if len(c.dependencies) == 0 {
		// unset or empty
		return true
	}
	return slices.Contains(c.dependencies, name)
}
