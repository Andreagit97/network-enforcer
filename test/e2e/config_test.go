package e2e_test

import (
	"os"
	"slices"
	"strings"
	"time"
)

const (
	defaultChartPath                   = "../../charts/network-enforcer"
	defaultLogsDir                     = "./logs"
	defaultControllerImage             = "ghcr.io/rancher-sandbox/network-enforcer/controller:latest"
	defaultCNIWatcherImage             = "ghcr.io/rancher-sandbox/network-enforcer/cniwatcher:latest"
	defaultReleaseName                 = "network-enforcer"
	defaultReleaseNS                   = "network-enforcer"
	defaultNamespacePref               = "network-enforcer-e2e"
	defaultCNI                         = cilium
	defaultDrainFlowsInterval          = 3 * time.Second // we reduce the time here to have faster feedback on the learning phase
	defaultWnpStatusUpdateInterval     = 3 * time.Second // we reduce the time here to have faster feedback from the controller
	defaultOTelCollectorDeploymentName = "network-enforcer-otel-collector"
	defaultPolicyDenyMetricName        = "network_enforcer_policy_denies"

	noCNIConfigPath = "./clusters/no-cni.yaml"
)

const (
	defaultHelmTimeout      = 3 * time.Minute
	defaultOperationTimeout = 2 * time.Minute
	defaultPodExecTimeout   = 45 * time.Second

	// Environment variables used in e2e tests.
	cniEnvVar        = "E2E_CNI"
	cniVersionEnvVar = "E2E_CNI_VERSION"
	// the value of this envVar is the name of the cluster to create.
	installClusterOnlyEnvVar = "E2E_INSTALL_CLUSTER_ONLY"
	// set to "true" to skip cluster creation, image loading, and cluster destroy.
	useExistingClusterEnvVar = "E2E_USE_EXISTING_CLUSTER"
	// comma-separated list of optional dependencies to install: "cni", "cert-manager".
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
	cniWatcherImage         string
	namespacePrefix         string
	cni                     cniType
	cniVersion              string
	drainFlowsInterval      time.Duration
	wnpStatusUpdateInterval time.Duration
	installClusterOnly      string
	useExistingCluster      bool
	hasNoDependencies       bool
	dependencies            []string
}

func loadSuiteConfig() suiteConfig {
	dependencies := os.Getenv(e2eDependenciesEnvVar)
	return suiteConfig{
		logsDir:         defaultLogsDir,
		chartPath:       defaultChartPath,
		releaseName:     defaultReleaseName,
		releaseNS:       defaultReleaseNS,
		controllerImage: defaultControllerImage,
		cniWatcherImage: defaultCNIWatcherImage,
		namespacePrefix: defaultNamespacePref,
		cni:             cniType(readEnvOrDefault(cniEnvVar, string(defaultCNI))),
		// we don't have a default value here, it will be set by CNI specific code.
		cniVersion:              readEnvOrDefault(cniVersionEnvVar, ""),
		kindConfigPath:          noCNIConfigPath,
		drainFlowsInterval:      defaultDrainFlowsInterval,
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
