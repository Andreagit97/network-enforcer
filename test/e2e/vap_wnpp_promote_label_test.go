package e2e_test

import (
	"context"
	"testing"

	"github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func TestValidatingAdmissionPolicyWNPPPromoteLabel(t *testing.T) {
	t.Log("test ValidatingAdmissionPolicy WNPP promote label")

	testEnv.Test(t, getValidatingAdmissionPolicyWNPPPromoteLabelTest())
}

func getValidatingAdmissionPolicyWNPPPromoteLabelTest() types.Feature {
	return features.New("Test ValidatingAdmissionPolicy for WNPP promote label").
		Setup(setupTestNamespace).
		Assess("VAP enforces the WNPP promote-label enum", assessVAPWNPPPromoteLabel).
		Teardown(teardownTestNamespace).
		Feature()
}

func assessVAPWNPPPromoteLabel(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	r := getSecurityV1Alpha1Client(ctx)
	namespace := getNamespace(ctx)
	require.NoError(t, admissionregistrationv1.AddToScheme(r.GetScheme()))

	// The chart must have installed the VAP and binding before any admission checks.
	vapName := getSuiteConfig(ctx).releaseName + "-wnpp-promote-label"
	require.NoError(t, r.Get(ctx, vapName, "", &admissionregistrationv1.ValidatingAdmissionPolicy{}),
		"ValidatingAdmissionPolicy %q should exist", vapName)
	require.NoError(t, r.Get(ctx, vapName+"-binding", "", &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}),
		"ValidatingAdmissionPolicyBinding %q should exist", vapName+"-binding")

	// CREATE with an unsupported promote value is denied.
	invalidCreate := newVAPTestProposal("test-proposal-invalid-create", namespace, map[string]string{
		v1alpha1.ProposalPromoteLabelKey: "true",
	})
	requireAdmissionDenied(t, r.Create(ctx, invalidCreate), "VAP should have rejected unsupported promote label")

	// CREATE with promote=monitor is allowed.
	monitorCreate := newVAPTestProposal("test-proposal-monitor", namespace, map[string]string{
		v1alpha1.ProposalPromoteLabelKey: string(v1alpha1.WorkloadNetworkPolicyModeMonitor),
	})
	require.NoError(t, r.Create(ctx, monitorCreate), "failed to create proposal with monitor promote label")
	deleteVAPTestProposal(ctx, t, r, monitorCreate)

	// UPDATE with an unsupported promote value is denied.
	invalidUpdate := newVAPTestProposal("test-proposal-invalid-update", namespace, nil)
	require.NoError(t, r.Create(ctx, invalidUpdate), "failed to create proposal without promote label")
	require.NoError(t, r.Get(ctx, invalidUpdate.Name, namespace, invalidUpdate), "failed to get created proposal")
	setPromoteLabel(invalidUpdate, "true")
	requireAdmissionDenied(
		t,
		r.Update(ctx, invalidUpdate),
		"VAP should have rejected updating an unsupported promote label",
	)
	require.NoError(
		t,
		r.Get(ctx, invalidUpdate.Name, namespace, invalidUpdate),
		"failed to get proposal after failed update",
	)
	_, exists := invalidUpdate.Labels[v1alpha1.ProposalPromoteLabelKey]
	require.False(t, exists, "promote label should not exist on proposal")
	deleteVAPTestProposal(ctx, t, r, invalidUpdate)

	// UPDATE with promote=protect is allowed.
	protectUpdate := newVAPTestProposal("test-proposal-protect-update", namespace, nil)
	require.NoError(t, r.Create(ctx, protectUpdate), "failed to create proposal without promote label")
	require.NoError(t, r.Get(ctx, protectUpdate.Name, namespace, protectUpdate), "failed to get created proposal")
	setPromoteLabel(protectUpdate, string(v1alpha1.WorkloadNetworkPolicyModeProtect))
	require.NoError(t, r.Update(ctx, protectUpdate), "VAP should allow updating to protect promote label")
	deleteVAPTestProposal(ctx, t, r, protectUpdate)

	return ctx
}

func setPromoteLabel(proposal *v1alpha1.WorkloadNetworkPolicyProposal, value string) {
	if proposal.Labels == nil {
		proposal.Labels = map[string]string{}
	}
	proposal.Labels[v1alpha1.ProposalPromoteLabelKey] = value
}

func requireAdmissionDenied(t *testing.T, err error, msg string) {
	t.Helper()
	require.Error(t, err, msg)
	require.True(t, apierrors.IsInvalid(err) || apierrors.IsForbidden(err),
		"expected Invalid or Forbidden error, got: %v", err)
}

func deleteVAPTestProposal(
	ctx context.Context,
	t *testing.T,
	r *resources.Resources,
	proposal *v1alpha1.WorkloadNetworkPolicyProposal,
) {
	t.Helper()
	err := r.Delete(ctx, proposal)
	if err != nil && !apierrors.IsNotFound(err) {
		assert.NoError(t, err, "failed to delete proposal")
	}
}

func newVAPTestProposal(name, namespace string, labels map[string]string) *v1alpha1.WorkloadNetworkPolicyProposal {
	return &v1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: v1alpha1.WorkloadNetworkPolicyProposalSpec{
			PolicyBackendSpec: v1alpha1.PolicyBackendSpec{
				Backend: v1alpha1.PolicyBackendIstio,
				Istio: &v1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "vap-test"},
					},
				},
			},
		},
	}
}
