package controller

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testSlogLogger returns a slog logger that discards all output.
func testSlogLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newSyncWithObjects builds a status-sync backed by a fake client seeded with
// the given objects, for tests that resolve destination workloads from Pods.
func newSyncWithObjects(objs ...client.Object) *WorkloadNetworkPolicyStatusSync {
	return &WorkloadNetworkPolicyStatusSync{
		Client: fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(objs...).Build(),
		logger: testSlogLogger(),
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
func newViolation(
	ts time.Time,
	srcNS string,
	srcName string,
	dstNS string,
	dstName string,
	denyNS string,
	denyName string,
) securityv1alpha1.ViolationRecord {
	return securityv1alpha1.ViolationRecord{
		ViolationInfo: securityv1alpha1.ViolationInfo{
			Timestamp: metav1.NewTime(ts),
			Source: securityv1alpha1.WorkloadRef{
				Namespace: srcNS,
				OwnerKind: "Deployment",
				OwnerName: srcName,
			},
			Dest: securityv1alpha1.WorkloadRef{
				Namespace: dstNS,
				OwnerKind: "Service",
				OwnerName: dstName,
			},
			Protocol:               corev1.ProtocolTCP,
			DstPort:                80,
			Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			DenyingPolicyNamespace: denyNS,
			DenyingPolicyName:      denyName,
		},
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
		violations []securityv1alpha1.ViolationRecord
		check      func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord)
	}{
		{
			name: "attributes_egress_deny_to_WNP",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
					logger: testSlogLogger(),
				}
			}(),
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
				logger: testSlogLogger(),
			},
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
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
			violations: []securityv1alpha1.ViolationRecord{
				newViolation(
					ts,
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
				newViolation(
					ts,
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
		Client:         fakeClient,
		updateInterval: time.Hour,
		logger:         testSlogLogger(),
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

func TestSyncSkipsWhenNoWNPs(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		Build()

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:         fakeClient,
		updateInterval: time.Hour,
		logger:         testSlogLogger(),
	}

	err := sync.sync(context.Background())
	require.NoError(t, err)
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

	sync := newTestWorkloadNetworkStatusSync(fakeClient)

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
