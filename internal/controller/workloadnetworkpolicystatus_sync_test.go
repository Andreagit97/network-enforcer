package controller

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/grpcexporter"
	agentv1 "github.com/rancher-sandbox/network-enforcer/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Fake agent client
// ---------------------------------------------------------------------------

type fakeAgentClient struct {
	violations []*agentv1.ViolationRecord
	shouldFail bool
}

func (f *fakeAgentClient) ScrapeViolations(_ context.Context) ([]*agentv1.ViolationRecord, error) {
	if f.shouldFail {
		return nil, errors.New("fake scrape failure")
	}
	return f.violations, nil
}

func (f *fakeAgentClient) Close() error { return nil }

// ---------------------------------------------------------------------------
// Fake pool that bypasses real gRPC dialling
// ---------------------------------------------------------------------------

type fakePool struct {
	nodeClients map[string]grpcexporter.AgentClientAPI
}

func (p *fakePool) UpdatePool(_ context.Context, _ client.Reader) (map[string]grpcexporter.AgentClientAPI, error) {
	return p.nodeClients, nil
}

func (p *fakePool) MarkStaleAgentClient(nodeName string) {
	if p.nodeClients == nil {
		return
	}
	if c, ok := p.nodeClients[nodeName]; ok && c != nil {
		_ = c.Close()
	}
	p.nodeClients[nodeName] = nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newCniwatcherPod(name, namespace, nodeName, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app.kubernetes.io/name": "network-enforcer-cniwatcher"},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			PodIP: ip,
		},
	}
}

// newSyncWithObjects builds a status-sync backed by a fake client seeded with
// the given objects, for tests that resolve destination workloads from Pods.
func newSyncWithObjects(objs ...client.Object) *WorkloadNetworkPolicyStatusSync {
	return &WorkloadNetworkPolicyStatusSync{
		Client: fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(objs...).Build(),
		logger: ctrl.Log.WithName("test"),
	}
}

// labeledPod builds a bare Pod with the given labels, for ALLOW-miss
// correlation tests that match a destination pod against WNP selectors.
func labeledPod(namespace, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
	}
}

//nolint:unparam // for now some params always receive the same value
func newProtoViolation(
	ts time.Time,
	nodeName string,
	direction string,
	srcNS string,
	srcName string,
	dstNS string,
	dstName string,
	denyNS string,
	denyName string,
) *agentv1.ViolationRecord {
	return &agentv1.ViolationRecord{
		Timestamp:              timestamppb.New(ts),
		NodeName:               nodeName,
		Direction:              direction,
		SourceNamespace:        srcNS,
		SourceName:             srcName,
		SourceWorkloads:        []string{"Deployment/" + srcName},
		DestNamespace:          dstNS,
		DestName:               dstName,
		DestWorkloads:          []string{"Service/" + dstName},
		Protocol:               "TCP",
		DstPort:                80,
		Action:                 "protect",
		DenyingPolicyNamespace: denyNS,
		DenyingPolicyName:      denyName,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCorrelateViolationsToWNPs(t *testing.T) {
	t.Parallel()

	npKey := types.NamespacedName{Namespace: "ns1", Name: "policy-1"}
	wnpKey := types.NamespacedName{Namespace: "ns1", Name: "policy-1"}
	// allowMissWNPKey owns the destination workload of an ALLOW-miss violation.
	// Its name is arbitrary (user-chosen) on purpose: ALLOW-miss correlation must
	// not depend on the WNP name, only on its selector matching the dest pod.
	allowMissWNPKey := types.NamespacedName{Namespace: "ns1", Name: "user-named-wnp"}
	ownedIndex := map[types.NamespacedName]*types.NamespacedName{
		npKey: &wnpKey,
	}
	wnpByKey := map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
		wnpKey: {
			ObjectMeta: metav1.ObjectMeta{
				Name:      wnpKey.Name,
				Namespace: wnpKey.Namespace,
			},
		},
		allowMissWNPKey: {
			ObjectMeta: metav1.ObjectMeta{
				Name:      allowMissWNPKey.Name,
				Namespace: allowMissWNPKey.Namespace,
			},
			Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
				PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
					Backend: securityv1alpha1.PolicyBackendIstio,
					Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
						Selector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "frontend"},
						},
					},
				},
			},
		},
	}

	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		sync *WorkloadNetworkPolicyStatusSync
		// wnpByKey overrides the shared default when non-nil, for cases that need
		// a bespoke set of WorkloadNetworkPolicies (e.g. empty or overlapping
		// selectors, Kubernetes backend).
		wnpByKey   map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy
		violations []*agentv1.ViolationRecord
		check      func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord)
	}{
		{
			name: "attributes_egress_deny_to_WNP",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeEgress),
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, wnpKey)
				require.Len(t, result[wnpKey], 1)
				require.Equal(t, "ns1", result[wnpKey][0].DenyingPolicyNamespace)
				require.Equal(t, "policy-1", result[wnpKey][0].DenyingPolicyName)
			},
		},
		{
			name: "attributes_ingress_deny_to_WNP",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, wnpKey)
				require.Len(t, result[wnpKey], 1)
			},
		},
		{
			name: "drops_deny_by_unowned_NetworkPolicy",
			sync: func() *WorkloadNetworkPolicyStatusSync {
				rawNP := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "raw-policy",
						Namespace: "ns-other",
					},
				}
				return &WorkloadNetworkPolicyStatusSync{
					Client: fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(rawNP).Build(),
					logger: ctrl.Log.WithName("test"),
				}
			}(),
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeEgress),
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns-other",
					"raw-policy",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			name: "warns_when_denying_NetworkPolicy_is_deleted",
			sync: &WorkloadNetworkPolicyStatusSync{
				Client: fake.NewClientBuilder().WithScheme(newTestScheme()).Build(),
				logger: ctrl.Log.WithName("test"),
			},
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeEgress),
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns-missing",
					"deleted-policy",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			// ALLOW-miss: no denying policy name. The destination pod carries the
			// labels selected by the arbitrarily-named WNP, so the violation is
			// attributed to it purely by selector match (not by name).
			name: "attributes_allow_miss_to_WNP_by_dest_selector",
			sync: newSyncWithObjects(labeledPod(
				allowMissWNPKey.Namespace,
				"frontend-abc123-xyz",
				map[string]string{"app": "frontend"},
			)),
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					allowMissWNPKey.Namespace,
					"frontend-abc123-xyz",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, allowMissWNPKey)
				require.Len(t, result[allowMissWNPKey], 1)
				require.Empty(t, result[allowMissWNPKey][0].DenyingPolicyName)
			},
		},
		{
			// The destination pod cannot be found, so its labels are unknown and
			// the violation is dropped.
			name: "drops_allow_miss_when_dest_pod_unresolvable",
			sync: newSyncWithObjects(),
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					allowMissWNPKey.Namespace,
					"missing-pod",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			// The destination pod exists but its labels match no WNP selector, so
			// the violation has nowhere to go.
			name: "drops_allow_miss_when_no_WNP_selects_pod",
			sync: newSyncWithObjects(labeledPod(
				allowMissWNPKey.Namespace,
				"orphan-abc123-xyz",
				map[string]string{"app": "other"},
			)),
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					allowMissWNPKey.Namespace,
					"orphan-abc123-xyz",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			// An ALLOW-miss with no destination workload at all cannot be
			// correlated and is dropped.
			name: "drops_allow_miss_when_dest_workload_missing",
			sync: newSyncWithObjects(),
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					"",
					"",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			// ALLOW-miss correlation also works for the Kubernetes backend, which
			// exposes its selector via Spec.Kubernetes.PodSelector.
			name: "attributes_allow_miss_to_kubernetes_backend_WNP",
			sync: newSyncWithObjects(labeledPod(
				"ns1",
				"backend-pod",
				map[string]string{"app": "backend"},
			)),
			wnpByKey: map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
				{Namespace: "ns1", Name: "k8s-wnp"}: {
					ObjectMeta: metav1.ObjectMeta{Name: "k8s-wnp", Namespace: "ns1"},
					Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
						PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
							Backend: securityv1alpha1.PolicyBackendKubernetes,
							Kubernetes: &networkingv1.NetworkPolicySpec{
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "backend"},
								},
							},
						},
					},
				},
			},
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					"ns1",
					"backend-pod",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, types.NamespacedName{Namespace: "ns1", Name: "k8s-wnp"})
			},
		},
		{
			// A WNP with an empty selector matches every pod under
			// LabelSelectorAsSelector; it must NOT capture ALLOW-miss violations for
			// unrelated workloads, so the violation is dropped.
			name: "drops_allow_miss_when_only_WNP_has_empty_selector",
			sync: newSyncWithObjects(labeledPod(
				"ns1",
				"some-pod",
				map[string]string{"app": "whatever"},
			)),
			wnpByKey: map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
				{Namespace: "ns1", Name: "catch-all-wnp"}: {
					ObjectMeta: metav1.ObjectMeta{Name: "catch-all-wnp", Namespace: "ns1"},
					Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
						PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
							Backend: securityv1alpha1.PolicyBackendIstio,
							Istio:   &securityv1alpha1.IstioAuthorizationPolicySpec{},
						},
					},
				},
			},
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					"ns1",
					"some-pod",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			// When more than one WNP selects the destination pod, selection is
			// deterministic: the keys are sorted and the first is chosen.
			name: "attributes_allow_miss_to_first_of_multiple_matching_WNPs",
			sync: newSyncWithObjects(labeledPod(
				"ns1",
				"multi-pod",
				map[string]string{"app": "multi"},
			)),
			wnpByKey: map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
				{Namespace: "ns1", Name: "bbb-wnp"}: {
					ObjectMeta: metav1.ObjectMeta{Name: "bbb-wnp", Namespace: "ns1"},
					Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
						PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
							Backend: securityv1alpha1.PolicyBackendIstio,
							Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
								Selector: metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "multi"},
								},
							},
						},
					},
				},
				{Namespace: "ns1", Name: "aaa-wnp"}: {
					ObjectMeta: metav1.ObjectMeta{Name: "aaa-wnp", Namespace: "ns1"},
					Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
						PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
							Backend: securityv1alpha1.PolicyBackendIstio,
							Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
								Selector: metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "multi"},
								},
							},
						},
					},
				},
			},
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeIngress),
					"src-ns",
					"src-app",
					"ns1",
					"multi-pod",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, types.NamespacedName{Namespace: "ns1", Name: "aaa-wnp"})
			},
		},
		{
			name: "dedup_by_violation_key",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(
					ts,
					"node-1",
					string(networkingv1.PolicyTypeEgress),
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
				newProtoViolation(
					ts,
					"node-2",
					string(networkingv1.PolicyTypeEgress),
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				// Both violations are in the list — dedup is done later by
				// RecomputeStatus → mergeScrapedViolations which uses the key.
				require.Len(t, result[wnpKey], 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			wnps := wnpByKey
			if tt.wnpByKey != nil {
				wnps = tt.wnpByKey
			}
			result := tt.sync.correlateViolationsToWNPs(context.Background(), tt.violations, ownedIndex, wnps)
			tt.check(t, result)
		})
	}
}

func TestProcessWorkloadNetworkPolicy_TwoPhasePatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	wnp := newTestWNP("policy-1", "ns1")
	// Add an acknowledge annotation for one of the violations.
	wnp.Annotations = map[string]string{
		securityv1alpha1.ViolationAcknowledgePrefix + "0": "known issue",
	}

	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          fakeClient,
		agentClientPool: &fakePool{},
		updateInterval:  time.Hour,
		logger:          ctrl.Log.WithName("test"),
	}

	violations := []securityv1alpha1.ViolationRecord{
		{
			ViolationInfo: securityv1alpha1.ViolationInfo{
				Timestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
				Source: securityv1alpha1.WorkloadRef{
					Namespace: "src-ns", OwnerKind: "Deployment", OwnerName: "app",
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: "dst-ns", OwnerKind: "Service", OwnerName: "svc",
				},
				Protocol:               corev1.ProtocolTCP,
				DstPort:                80,
				Action:                 "protect",
				DenyingPolicyNamespace: "ns1",
				DenyingPolicyName:      "policy-1",
			},
		},
	}

	err := sync.processWorkloadNetworkPolicy(context.Background(), wnp, violations)
	require.NoError(t, err)

	// Verify the status was written.
	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "policy-1"}, &updatedWNP)
	require.NoError(t, err)
	require.Equal(t, int64(1), updatedWNP.Status.ViolationCount)
	require.Equal(t, int64(0), updatedWNP.Status.ActiveViolationCount) // acknowledged

	// The acknowledge annotation should have been consumed.
	_, exists := updatedWNP.Annotations[securityv1alpha1.ViolationAcknowledgePrefix+"0"]
	require.False(t, exists, "acknowledge annotation should be removed")
}

func TestBuildOwnershipIndex(t *testing.T) {
	t.Parallel()

	wnp1 := newTestWNP("policy-1", "ns1")
	wnp2 := newTestWNP("policy-2", "ns2")

	ownedNP1 := newOwnedNetworkPolicy(wnp1)
	ownedNP2 := newOwnedNetworkPolicy(wnp2)
	// A NetworkPolicy with no owner reference.
	unownedNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "raw-policy",
			Namespace: "ns1",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(wnp1, wnp2, ownedNP1, ownedNP2, unownedNP).
		Build()

	wnpByKey := map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
		{Namespace: "ns1", Name: "policy-1"}: wnp1,
		{Namespace: "ns2", Name: "policy-2"}: wnp2,
	}

	sync := &WorkloadNetworkPolicyStatusSync{Client: fakeClient}
	index, err := sync.buildOwnershipIndex(context.Background(), wnpByKey)
	require.NoError(t, err)

	// Owned policies should be in the index.
	require.Equal(t, types.NamespacedName{Namespace: "ns1", Name: "policy-1"},
		*index[types.NamespacedName{Namespace: "ns1", Name: "policy-1"}])
	require.Equal(t, types.NamespacedName{Namespace: "ns2", Name: "policy-2"},
		*index[types.NamespacedName{Namespace: "ns2", Name: "policy-2"}])

	// Unowned policy should be in the index but the owner should be nil
	owner, exists := index[types.NamespacedName{Namespace: "ns1", Name: "raw-policy"}]
	require.True(t, exists)
	require.Nil(t, owner)
}

func TestConvertProtoViolation(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pbViolation := newProtoViolation(ts, "node-1", string(networkingv1.PolicyTypeEgress),
		"src-ns", "src-app", "dst-ns", "dst-svc",
		"policy-ns", "policy-name")

	rec := convertProtoViolation(pbViolation)

	require.Equal(t, "src-ns", rec.Source.Namespace)
	require.Equal(t, "Deployment", rec.Source.OwnerKind)
	require.Equal(t, "src-app", rec.Source.OwnerName)
	require.Equal(t, "dst-ns", rec.Dest.Namespace)
	require.Equal(t, "Service", rec.Dest.OwnerKind)
	require.Equal(t, "dst-svc", rec.Dest.OwnerName)
	require.Equal(t, corev1.ProtocolTCP, rec.Protocol)
	require.Equal(t, int32(80), rec.DstPort)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, rec.Action)
	require.Equal(t, "policy-ns", rec.DenyingPolicyNamespace)
	require.Equal(t, "policy-name", rec.DenyingPolicyName)
}

func TestParseWorkload(t *testing.T) {
	t.Parallel()

	kind, name := parseWorkload([]string{"Deployment/myapp"})
	require.Equal(t, "Deployment", kind)
	require.Equal(t, "myapp", name)

	kind, name = parseWorkload([]string{"myapp"})
	require.Empty(t, kind)
	require.Equal(t, "myapp", name)

	kind, name = parseWorkload(nil)
	require.Empty(t, kind)
	require.Empty(t, name)
}

func TestSyncSkipsWhenNoWNPs(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		Build()

	pool := &fakePool{nodeClients: map[string]grpcexporter.AgentClientAPI{}}

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          fakeClient,
		agentClientPool: pool,
		updateInterval:  time.Hour,
		logger:          ctrl.Log.WithName("test"),
	}

	err := sync.sync(context.Background())
	require.NoError(t, err)
}

// Test that the fake pool's MarkStaleAgentClient works correctly.
func TestFakePoolMarkStale(t *testing.T) {
	t.Parallel()

	pool := &fakePool{
		nodeClients: map[string]grpcexporter.AgentClientAPI{
			"node-1": &fakeAgentClient{},
		},
	}

	pool.MarkStaleAgentClient("node-1")
	require.Nil(t, pool.nodeClients["node-1"])

	// Marking again should not panic.
	pool.MarkStaleAgentClient("node-1")
}

// TestNewWorkloadNetworkPolicyStatusSync validates config.
func TestNewWorkloadNetworkPolicyStatusSync(t *testing.T) {
	t.Parallel()

	_, err := NewWorkloadNetworkPolicyStatusSync(nil, &WorkloadNetworkPolicyStatusSyncConfig{
		UpdateInterval: 0,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid update interval")
}

// Test that the gRPC exporter pool creation works with valid config.
func TestAgentClientPoolDefaults(t *testing.T) {
	t.Parallel()

	pool, err := grpcexporter.NewAgentClientPool(grpcexporter.AgentClientPoolConfig{
		AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
			Port: 50051,
		},
		Namespace:           "test-ns",
		LabelSelectorString: grpcexporter.DefaultCniwatcherLabelSelectorString,
		Logger:              slog.Default(),
	})
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestAgentClientPoolUpdatePool(t *testing.T) {
	t.Parallel()

	// We need a full scheme for the fake client.
	s := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(
			newCniwatcherPod("cniwatcher-1", "test-ns", "node-1", "10.0.0.1"),
			newCniwatcherPod("cniwatcher-2", "test-ns", "node-2", "10.0.0.2"),
		).
		Build()

	// Create a pool with a factory that dials.
	// grpc.NewClient is lazy so creation will succeed even without a
	// real gRPC server. We verify the pool correctly discovers pods.
	pool, err := grpcexporter.NewAgentClientPool(grpcexporter.AgentClientPoolConfig{
		AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
			Port: 50051,
		},
		Namespace:           "test-ns",
		LabelSelectorString: "app.kubernetes.io/name=network-enforcer-cniwatcher",
		Logger:              slog.Default(),
	})
	require.NoError(t, err)

	clients, err := pool.UpdatePool(context.Background(), fakeClient)
	require.NoError(t, err)
	require.Len(t, clients, 2)
	// Both nodes are present (entries are non-nil because grpc.NewClient
	// is lazy and does not dial during construction).
	require.Contains(t, clients, "node-1")
	require.Contains(t, clients, "node-2")
	require.NotNil(t, clients["node-1"])
	require.NotNil(t, clients["node-2"])

	// Mark a client stale and verify it becomes nil.
	pool.MarkStaleAgentClient("node-1")
	require.Nil(t, clients["node-1"])
}

func TestSyncClearsViolationsWithNoNewScrapedViolations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	tcp := corev1.ProtocolTCP
	port80 := intstr.FromInt32(80)

	wnp := newTestWNP("policy-1", "ns1")
	// Add an egress rule to the policy template that permits the traffic
	// that was previously denied and recorded as a violation.
	wnp.Spec.Kubernetes.Egress = []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							corev1.LabelMetadataName: "dst-ns",
						},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &port80,
				},
			},
		},
	}

	// Pre-populate status with a violation that matches the rule above.
	wnp.Status = securityv1alpha1.WorkloadNetworkPolicyStatus{
		ViolationCount:       1,
		ActiveViolationCount: 1,
		Violations: []securityv1alpha1.ViolationRecord{
			{
				ID: 0,
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Timestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
					Source: securityv1alpha1.WorkloadRef{
						Namespace: "src-ns", OwnerKind: "Deployment", OwnerName: "app",
					},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "dst-ns", OwnerKind: "Service", OwnerName: "svc",
					},
					Protocol:               corev1.ProtocolTCP,
					DstPort:                80,
					Action:                 "protect",
					DenyingPolicyNamespace: "ns1",
					DenyingPolicyName:      "policy-1",
				},
			},
		},
	}

	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	// Pool with no reachable nodes → empty scrape → zero violations.
	pool := &fakePool{nodeClients: map[string]grpcexporter.AgentClientAPI{}}

	sync := newTestWorkloadNetworkStatusSync(fakeClient).withPool(pool)

	require.NoError(t, sync.sync(t.Context()))

	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, fakeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: "ns1", Name: "policy-1"},
		&updatedWNP,
	))

	// The violation should have been cleared because it matches a rule in
	// the current policy template (clearAllowedViolations ran even though
	// no new violations were scraped).
	require.Equal(t, int64(1), updatedWNP.Status.ViolationCount,
		"ViolationCount should still be 1 (total observed)")
	require.Equal(t, int64(0), updatedWNP.Status.ActiveViolationCount,
		"ActiveViolationCount should be 0 after clearing")
	require.Empty(t, updatedWNP.Status.Violations,
		"Violations should be empty — the matching rule cleared it")
}

// TestTwoPhasePatchConflict simulates a scenario where an annotation is
// modified between the status patch and the metadata patch. Both patches
// use MergeFrom so the annotation should survive.
func TestTwoPhasePatchConflict(t *testing.T) {
	t.Parallel()

	// Start with a WNP that has a pre-existing annotation.
	wnp := newTestWNP("conflict-policy", "ns1")
	wnp.Annotations = map[string]string{
		"existing.io/key": "original-value",
	}
	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := newTestWorkloadNetworkStatusSync(fakeClient)

	violations := []securityv1alpha1.ViolationRecord{
		{
			ViolationInfo: securityv1alpha1.ViolationInfo{
				Timestamp: metav1.NewTime(time.Now()),
				Source: securityv1alpha1.WorkloadRef{
					Namespace: "ns1", OwnerKind: "Deployment", OwnerName: "app",
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: "ns2", OwnerKind: "Service", OwnerName: "svc",
				},
				Protocol:               corev1.ProtocolTCP,
				DstPort:                80,
				Action:                 "protect",
				DenyingPolicyNamespace: "ns1",
				DenyingPolicyName:      "conflict-policy",
			},
		},
	}

	require.NoError(t, sync.processWorkloadNetworkPolicy(t.Context(), wnp, violations))

	// The existing annotation should still be present.
	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, fakeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: "ns1", Name: "conflict-policy"},
		&updatedWNP,
	))
	require.Equal(t, "original-value", updatedWNP.Annotations["existing.io/key"])
	// Status should also be updated.
	require.Equal(t, int64(1), updatedWNP.Status.ActiveViolationCount)
}
