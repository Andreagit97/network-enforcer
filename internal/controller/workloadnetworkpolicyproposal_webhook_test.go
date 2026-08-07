package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

func TestProposalWebhookValidatePromotionLabel(t *testing.T) {
	t.Parallel()

	webhook := &ProposalWebhook{}

	tests := []struct {
		name       string
		labels     map[string]string
		op         string
		wantErr    bool
		errContain string
	}{
		{
			name: "allows create without promote label",
			op:   "create",
		},
		{
			name: "allows create with monitor promote label",
			labels: map[string]string{
				securityv1alpha1.ProposalPromoteLabelKey: string(securityv1alpha1.WorkloadNetworkPolicyModeMonitor),
			},
			op: "create",
		},
		{
			name: "allows update with protect promote label",
			labels: map[string]string{
				securityv1alpha1.ProposalPromoteLabelKey: string(securityv1alpha1.WorkloadNetworkPolicyModeProtect),
			},
			op: "update",
		},
		{
			name: "denies create with unsupported promote label",
			labels: map[string]string{
				securityv1alpha1.ProposalPromoteLabelKey: "true",
			},
			op:         "create",
			wantErr:    true,
			errContain: `unsupported value "true"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proposal := &securityv1alpha1.WorkloadNetworkPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-proposal",
					Labels: tc.labels,
				},
			}

			var warns []string
			var err error
			switch tc.op {
			case "create":
				warns, err = webhook.ValidateCreate(t.Context(), proposal)
			case "update":
				warns, err = webhook.ValidateUpdate(t.Context(), proposal, proposal)
			default:
				t.Fatalf("unknown op %q", tc.op)
			}

			require.Empty(t, warns)
			if tc.wantErr {
				require.Error(t, err)
				require.True(t, apierrors.IsInvalid(err))
				require.Contains(t, err.Error(), tc.errContain)
				return
			}
			require.NoError(t, err)
		})
	}
}
