// Package istio holds the Istio-specific enrichment of network policy
// violations: resolving the source peer IP and destination pod name observed on
// the destination ztunnel back to their owning Kubernetes workloads and SPIFFE
// identities, and correlating ALLOW-miss violations to the owning
// WorkloadNetworkPolicy. It is Istio-specific because the reconstruction assumes
// Istio's ztunnel peer-address model and its SPIFFE principal form.
package istio

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
)

// istioTrustDomain is the SPIFFE trust domain assumed for source identities
// resolved from pod state. Istio's default trust domain is cluster.local; the
// canonical, prefix-free principal form consumed by istioRuleAllowsSource is
// `<trustDomain>/ns/<namespace>/sa/<serviceAccount>`.
//
// LIMITATION: this is fixed to the Istio default. The protect/monitor events
// carry only the peer address (not src.identity), so the identity is
// reconstructed here rather than reported. In a mesh configured with a custom
// trust domain, the reconstructed identity will not equal the learned rule
// principals, so these violations will not be cleared by istioRuleAllowsSource.
// Making this configurable (or plumbing the real src.identity through the
// protect/monitor OTLP events) is left for follow-up.
const istioTrustDomain = "cluster.local"

// defaultServiceAccountName is the service account a pod runs as when none is
// set explicitly, used to reconstruct its SPIFFE identity.
const defaultServiceAccountName = "default"

// Enricher resolves the source and destination workloads of an Istio violation
// from live pod state, using a status.podIP field index registered via
// controller.SetupPodIPIndexer, and correlates ALLOW-miss violations to the
// owning WorkloadNetworkPolicy. It is safe to use a nil *Enricher (or one with a
// nil client): Enrich is then a no-op passthrough.
type Enricher struct {
	client client.Client
}

// NewEnricher returns an Enricher backed by the given client. The client must
// read from a cache that has the PodIPIndexField index registered (see
// controller.SetupPodIPIndexer).
func NewEnricher(c client.Client) *Enricher {
	return &Enricher{client: c}
}

// Enrich resolves the source (by peer IP) and destination (by pod name) of an
// observation to their owning workloads and SPIFFE identities, and for an
// ALLOW-miss violation resolves the owning WorkloadNetworkPolicy so the
// controller can correlate it without a further pod lookup. Resolution is
// best-effort: on any lookup failure it logs and keeps the scraper-derived
// values, so enrichment never makes an observation worse than it was.
func (e *Enricher) Enrich(
	ctx context.Context,
	logger *slog.Logger,
	obs violation.Observation,
) violation.Observation {
	if e == nil || e.client == nil {
		return obs
	}

	if src, applicable, err := e.resolveSourceWorkload(ctx, obs); err != nil {
		logger.ErrorContext(ctx, "Failed to resolve violation source workload", "error", err)
	} else if applicable {
		obs.Source = src
	}

	return e.enrichDest(ctx, logger, obs)
}

// enrichDest resolves the destination pod to its owning workload and to the
// WorkloadNetworkPolicy that selects it (WNP violations are always ALLOW-miss).
// Both use the same pod fetch. On a miss the observation keeps its
// scraper-derived destination, and the owning WNP is left unresolved so the
// controller drops the (uncorrelatable) violation.
func (e *Enricher) enrichDest(
	ctx context.Context,
	logger *slog.Logger,
	obs violation.Observation,
) violation.Observation {
	dstNamespace := obs.Dest.Namespace
	dstPod := obs.Dest.OwnerName
	if dstNamespace == "" || dstPod == "" {
		return obs
	}

	var pod corev1.Pod
	if err := e.client.Get(ctx, types.NamespacedName{Namespace: dstNamespace, Name: dstPod}, &pod); err != nil {
		logger.ErrorContext(ctx, "Failed to fetch violation destination pod, keeping raw destination",
			"namespace", dstNamespace, "pod", dstPod, "error", err)
		return obs
	}

	obs.Dest = workloadRefFromPod(&pod)

	// A WNP violation is always an ALLOW-miss: the event carries no denying policy,
	// so the owning WNP is not knowable from it. Resolve it here by matching the
	// destination pod's labels against WNP selectors and record it in the
	// DenyingPolicy fields, which for an ALLOW-miss carry the *owning*
	// (selector-matched) WNP rather than a policy that literally denied the flow.
	// The controller then correlates by name.
	if ns, name, ok := e.resolveOwningPolicy(ctx, logger, dstNamespace, &pod); ok {
		obs.DenyingPolicyNamespace = ns
		obs.DenyingPolicyName = name
	}

	return obs
}

// resolveOwningPolicy finds the WorkloadNetworkPolicy that owns the destination
// pod of an ALLOW-miss violation by matching the pod's labels against each WNP's
// selector. Reconstructing the WNP name is not possible because users may name
// their WNPs freely, so we search instead.
//
// It reports false when no WNP selects the pod (or the list fails); the caller
// then leaves the owning policy unresolved.
func (e *Enricher) resolveOwningPolicy(
	ctx context.Context,
	logger *slog.Logger,
	namespace string,
	pod *corev1.Pod,
) (string, string, bool) {
	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := e.client.List(ctx, &wnpList, client.InNamespace(namespace)); err != nil {
		logger.ErrorContext(ctx, "Failed to list WorkloadNetworkPolicies for ALLOW-miss correlation",
			"namespace", namespace, "error", err)
		return "", "", false
	}

	podLabels := labels.Set(pod.Labels)

	// Collect every WNP whose selector matches, then pick deterministically. A
	// WNP is 1:1 with a workload (RFC 0003), so a single match is expected; more
	// than one means overlapping selectors.
	var matches []string
	for i := range wnpList.Items {
		wnp := &wnpList.Items[i]
		selector, ok := wnpIstioSelector(wnp)
		if !ok {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			logger.ErrorContext(ctx, "Invalid selector on WorkloadNetworkPolicy",
				"policy", wnp.Name, "error", err)
			continue
		}
		if sel.Empty() {
			// An empty selector matches every pod. Treating it as a match would
			// let a mis-configured WNP capture ALLOW-miss violations for unrelated
			// workloads in the namespace, so skip it and never correlate by it.
			logger.InfoContext(ctx, "WorkloadNetworkPolicy has an empty selector; skipping for ALLOW-miss correlation",
				"policy", wnp.Name)
			continue
		}
		if sel.Matches(podLabels) {
			matches = append(matches, wnp.Name)
		}
	}

	switch len(matches) {
	case 0:
		logger.InfoContext(ctx, "No WorkloadNetworkPolicy selects the ALLOW-miss violation destination pod",
			"namespace", namespace, "pod", pod.Name)
		return "", "", false
	case 1:
		return namespace, matches[0], true
	default:
		sort.Strings(matches)
		logger.InfoContext(
			ctx,
			"Multiple WorkloadNetworkPolicies select the ALLOW-miss violation destination pod; using the first",
			"namespace", namespace,
			"pod", pod.Name,
			"selected", matches[0],
		)
		return namespace, matches[0], true
	}
}

// wnpIstioSelector returns the Istio workload selector for a WorkloadNetworkPolicy
// and whether it has one. This path only correlates Istio-enforced violations, so
// a WNP on any other backend reports no selector and is skipped.
func wnpIstioSelector(wnp *securityv1alpha1.WorkloadNetworkPolicy) (*metav1.LabelSelector, bool) {
	if wnp.Spec.Backend == securityv1alpha1.PolicyBackendIstio && wnp.Spec.Istio != nil {
		return &wnp.Spec.Istio.Selector, true
	}
	return nil, false
}

// peerIPFromAddr extracts the host from an Istio peer `ip:port` address. A false
// result means the value is not an `ip:port` (so source resolution does not
// apply); it is a valid no-op, not an error to propagate.
func peerIPFromAddr(addr string) (string, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false
	}
	return host, true
}

// spiffeIdentity builds the prefix-free Istio principal form for a pod's
// service account. Pods with no explicit service account run as `default`.
func spiffeIdentity(namespace, serviceAccount string) string {
	if serviceAccount == "" {
		serviceAccount = defaultServiceAccountName
	}
	return fmt.Sprintf("%s/ns/%s/sa/%s", istioTrustDomain, namespace, serviceAccount)
}

// resolveSourceWorkload resolves the client (source) workload of an Istio
// violation from its peer address. Istio emits these events on the destination
// ztunnel and identifies the client only by `ip:port`, so the source is
// resolved by listing pods on the status.podIP field index.
//
// A non-nil error means the peer IP could not be resolved to exactly one pod
// (the List errored, no pod carries the IP, or several do — e.g. host-network
// pods sharing the node IP); the caller keeps the scraper-derived source and logs
// the failure once. When the error is nil, the bool reports whether resolution
// applies to this record:
//   - false: Source.OwnerName is not an `ip:port`, so there is nothing to
//     resolve; the caller keeps the scraper-derived source.
//   - true: the peer IP resolved to exactly one pod (the returned WorkloadRef).
//
// Because resolution is best-effort, the same logical flow can flip between
// resolved and unresolved across events (pod churn / pod not yet cached), so a
// source may be attributed for one event and left as the raw peer address for
// another.
func (e *Enricher) resolveSourceWorkload(
	ctx context.Context,
	obs violation.Observation,
) (securityv1alpha1.WorkloadRef, bool, error) {
	peerIP, ok := peerIPFromAddr(obs.Source.OwnerName)
	if !ok {
		// Not an `ip:port` source address; nothing to resolve.
		return securityv1alpha1.WorkloadRef{}, false, nil
	}

	var podList corev1.PodList
	if err := e.client.List(ctx, &podList, client.MatchingFields{PodIPIndexField: peerIP}); err != nil {
		return securityv1alpha1.WorkloadRef{}, false,
			fmt.Errorf("listing pods for source peer IP %s: %w", peerIP, err)
	}

	switch len(podList.Items) {
	case 1:
		return workloadRefFromPod(&podList.Items[0]), true, nil
	case 0:
		// The peer pod is not in the cache (not yet observed, already deleted, or
		// host-networked). Surface it as an error so the caller logs it once.
		return securityv1alpha1.WorkloadRef{}, false,
			fmt.Errorf("no pod found for source peer IP %s", peerIP)
	default:
		// Multiple pods share the peer IP (e.g. host-network pods sharing the node
		// IP); we cannot attribute the source to one of them.
		return securityv1alpha1.WorkloadRef{}, false,
			fmt.Errorf("%d pods found for source peer IP %s", len(podList.Items), peerIP)
	}
}

// workloadRefFromPod builds a WorkloadRef for a resolved pod (source or
// destination), including its Istio SPIFFE identity so it can drive rule
// clearing.
func workloadRefFromPod(pod *corev1.Pod) securityv1alpha1.WorkloadRef {
	wk := topology.ExtractWorkloadKey(pod)
	return securityv1alpha1.WorkloadRef{
		Namespace: wk.Namespace,
		OwnerKind: string(wk.OwnerKind),
		OwnerName: wk.OwnerName,
		Identity:  spiffeIdentity(pod.Namespace, pod.Spec.ServiceAccountName),
	}
}
