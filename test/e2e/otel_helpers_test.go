package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

func findPodByPrefix(ctx context.Context, namespace, prefix string) (string, error) {
	var pods corev1.PodList
	if err := getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).List(ctx, &pods); err != nil {
		return "", fmt.Errorf("list pods in %s: %w", namespace, err)
	}
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, prefix) && pod.Status.Phase == corev1.PodRunning {
			return pod.Name, nil
		}
	}
	return "", fmt.Errorf("no running pod with prefix %q in namespace %q", prefix, namespace)
}

func portForwardPod(
	config *envconf.Config,
	namespace, podName string,
	remotePort int,
) (int, chan struct{}, error) {
	restConfig := config.Client().RESTConfig()

	restClient, err := rest.RESTClientFor(
		&rest.Config{
			Host:            restConfig.Host,
			TLSClientConfig: restConfig.TLSClientConfig,
			BearerToken:     restConfig.BearerToken,
			BearerTokenFile: restConfig.BearerTokenFile,
			APIPath:         "/api",
			ContentConfig: rest.ContentConfig{
				GroupVersion:         &schema.GroupVersion{Version: "v1"},
				NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
			},
		},
	)
	if err != nil {
		return 0, nil, fmt.Errorf("creating REST client: %w", err)
	}

	url := restClient.
		Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").
		URL()

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return 0, nil, fmt.Errorf("creating round tripper: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)

	stopCh := make(chan struct{})
	readyCh := make(chan struct{})
	ports := []string{fmt.Sprintf("0:%d", remotePort)}
	fw, err := portforward.New(dialer, ports, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		return 0, nil, fmt.Errorf("creating port forwarder: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- fw.ForwardPorts()
	}()

	select {
	case <-readyCh:
	case fwErr := <-errCh:
		return 0, nil, fmt.Errorf("port forward failed: %w", fwErr)
	case <-time.After(10 * time.Second):
		close(stopCh)
		return 0, nil, errors.New("timed out waiting for port forward to be ready")
	}

	forwardedPorts, err := fw.GetPorts()
	if err != nil {
		close(stopCh)
		return 0, nil, fmt.Errorf("getting forwarded ports: %w", err)
	}
	if len(forwardedPorts) == 0 {
		close(stopCh)
		return 0, nil, errors.New("port forward returned no ports")
	}

	return int(forwardedPorts[0].Local), stopCh, nil
}

func fetchURL(url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func assertMetricHasLabel(t *testing.T, body, labelKey, labelValue string) {
	t.Helper()

	expected := fmt.Sprintf(`%s="%s"`, labelKey, labelValue)
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, defaultPolicyDenyMetricName) && strings.Contains(line, expected) {
			return
		}
	}
	assert.Failf(t, "metric label not found",
		"expected metric %q to have label %s=%q\nmetrics:\n%s",
		defaultPolicyDenyMetricName, labelKey, labelValue, body)
}

func assertMetricHasLabelKey(t *testing.T, body, labelKey string) {
	t.Helper()

	needle := labelKey + `="`
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, defaultPolicyDenyMetricName) && strings.Contains(line, needle) {
			return
		}
	}
	assert.Failf(t, "metric label key not found",
		"expected metric %q to have label key %q\nmetrics:\n%s",
		defaultPolicyDenyMetricName, labelKey, body)
}

// metricLabelValue returns the first Prometheus label value for labelKey on a
// sample for defaultPolicyDenyMetricName. Escaped \" sequences are unescaped.
// ok is false when no matching sample/label is found.
func metricLabelValue(body, labelKey string) (string, bool) {
	prefix := labelKey + `="`
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, defaultPolicyDenyMetricName) || !strings.Contains(line, prefix) {
			continue
		}
		start := strings.Index(line, prefix)
		if start < 0 {
			continue
		}
		start += len(prefix)
		end := start
		for end < len(line) {
			if line[end] == '"' && (end == start || line[end-1] != '\\') {
				break
			}
			end++
		}
		if end >= len(line) || line[end] != '"' {
			continue
		}
		return strings.ReplaceAll(line[start:end], `\"`, `"`), true
	}
	return "", false
}

// assertMetricLabelContains checks that a Prometheus sample for
// defaultPolicyDenyMetricName has labelKey whose value contains substr.
// Slice attributes are exported as JSON arrays (e.g. ["app=http-client"]),
// so substring match is intentional.
func assertMetricLabelContains(t *testing.T, body, labelKey, substr string) {
	t.Helper()

	value, ok := metricLabelValue(body, labelKey)
	if ok && strings.Contains(value, substr) {
		return
	}
	assert.Failf(t, "metric label substring not found",
		"expected metric %q label %s to contain %q\nmetrics:\n%s",
		defaultPolicyDenyMetricName, labelKey, substr, body)
}

// assertMetricHasAnyLabelContainingAny fails unless at least one of labelKeys
// contains at least one of the expected substrings on a sample for
// defaultPolicyDenyMetricName.
func assertMetricHasAnyLabelContainingAny(t *testing.T, body string, labelKeys, expectedSubstrs []string) {
	t.Helper()

	for _, key := range labelKeys {
		value, ok := metricLabelValue(body, key)
		if !ok {
			continue
		}
		for _, want := range expectedSubstrs {
			if strings.Contains(value, want) {
				return
			}
		}
	}
	assert.Failf(t, "expected policy identity not found in metric labels",
		"expected metric %q labels %v to contain one of %v\nmetrics:\n%s",
		defaultPolicyDenyMetricName, labelKeys, expectedSubstrs, body)
}

// checkPolicyDenyOTLPLog verifies that protect mode deny events observed by
// cniwatcher were exported as OTLP logs.
func checkPolicyDenyOTLPLog(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Helper()

	namespace := getNamespace(ctx)
	suiteCfg := getSuiteConfig(ctx)

	collectorPodName, err := findPodByPrefix(ctx, suiteCfg.releaseNS, defaultOTelCollectorDeploymentName)
	require.NoError(t, err, "should find OTEL collector pod")

	localPort, stopCh, err := portForwardPod(config, suiteCfg.releaseNS, collectorPodName, 9090)
	require.NoError(t, err, "should port-forward to collector prometheus port")
	defer close(stopCh)

	promURL := fmt.Sprintf("http://localhost:%d/metrics", localPort)

	var metricsBody string
	require.Eventually(t, func() bool {
		_, cmd := getProtoCmd(corev1.ProtocolUDP)
		_, _ = execInSimpleClientDeployment(ctx, t, cmd)

		body, fetchErr := fetchURL(promURL)
		if fetchErr != nil {
			t.Logf("failed to fetch metrics: %v", fetchErr)
			return false
		}
		metricsBody = body
		return strings.Contains(body, defaultPolicyDenyMetricName)
	}, defaultOperationTimeout, 2*time.Second,
		"%s metric should appear on the collector Prometheus endpoint", defaultPolicyDenyMetricName)

	assertMetricHasLabel(t, metricsBody, "cni_type", string(suiteCfg.cni))
	assertMetricHasLabel(t, metricsBody, "network_protocol", string(corev1.ProtocolUDP))
	assertMetricHasLabel(t, metricsBody, "source_namespace", namespace)
	assertMetricHasLabel(t, metricsBody, "destination_namespace", namespace)
	assertMetricHasLabelKey(t, metricsBody, "source_name")
	assertMetricHasLabelKey(t, metricsBody, "destination_name")
	assertMetricHasLabelKey(t, metricsBody, "node_name")
	assertMetricHasLabel(t, metricsBody, "destination_port",
		strconv.FormatInt(int64(simpleAppUDPServerPort), 10))

	assertMetricLabelContains(t, metricsBody, "source_labels", "app="+simpleAppClientDeploymentName)
	assertMetricLabelContains(t, metricsBody, "destination_labels", "app="+simpleAppServerDeploymentName)
	// Calico does not expose source/destination workloads on deny flows in this test.
	if suiteCfg.cni == cilium {
		assertMetricLabelContains(t, metricsBody, "source_workloads", "Deployment/"+simpleAppClientDeploymentName)
		assertMetricLabelContains(t, metricsBody, "destination_workloads", "Deployment/"+simpleAppServerDeploymentName)
	}
	// Calico reports the denying policy on one side (src=egress or dst=ingress).
	if suiteCfg.cni == calico {
		storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
		policies := make([]string, 0, len(storedPolicies))
		for _, p := range storedPolicies {
			policies = append(policies, p.Name)
		}
		assertMetricHasAnyLabelContainingAny(t, metricsBody,
			[]string{"egress_enforced_by", "ingress_enforced_by"}, policies)
	}
	return ctx
}
