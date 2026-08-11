package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/ownerkind"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
	netypes "github.com/rancher-sandbox/network-enforcer/internal/types"
)

func TestProcessIstioLearningEvent(t *testing.T) {
	t.Parallel()

	rsOwner := func(name string) metav1.OwnerReference {
		return metav1.OwnerReference{
			APIVersion: "apps/v1",
			Kind:       string(ownerkind.KindReplicaSet),
			Name:       name,
			UID:        "rs-uid",
			Controller: new(true),
		}
	}

	httpServerProposal := getProposalName(topology.WorkloadKey{
		Namespace: testNamespace,
		OwnerKind: ownerkind.KindDeployment,
		OwnerName: "http-server",
	}, networkingv1.PolicyTypeIngress)
	backendProposal := getProposalName(topology.WorkloadKey{
		Namespace: testNamespace,
		OwnerKind: ownerkind.KindDeployment,
		OwnerName: "backend",
	}, networkingv1.PolicyTypeIngress)
	promotedWNP := newTestWNP(backendProposal, testNamespace)
	promotedWNP.Labels = map[string]string{
		securityv1alpha1.PolicyPromotedFromLabelKey: backendProposal,
	}

	tests := []struct {
		name             string
		objs             []client.Object
		events           []netypes.LearningEvent
		wantProposalName string
		wantSelector     map[string]string
		wantProposalLen  int
	}{
		{
			name: "stable proposal per deployment across replicas",
			objs: []client.Object{
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "http-server", Namespace: testNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "http-server"},
						},
					},
				},
				ownedPod("http-server-6cbcc86f5d-aaa", rsOwner("http-server-6cbcc86f5d"), map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "6cbcc86f5d",
				}),
				ownedPod("http-server-6cbcc86f5d-bbb", rsOwner("http-server-6cbcc86f5d"), map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "6cbcc86f5d",
				}),
			},
			events: []netypes.LearningEvent{
				{DstName: "http-server-6cbcc86f5d-aaa", DstNamespace: testNamespace},
				{DstName: "http-server-6cbcc86f5d-bbb", DstNamespace: testNamespace},
			},
			wantProposalName: httpServerProposal,
			wantSelector:     map[string]string{"app": "http-server"},
			wantProposalLen:  1,
		},
		{
			name: "skips when promoted policy exists",
			objs: []client.Object{
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: testNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "backend"},
						},
					},
				},
				ownedPod("backend-7d9f8c6b5a-pod", rsOwner("backend-7d9f8c6b5a"), map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "7d9f8c6b5a",
				}),
				promotedWNP,
			},
			events: []netypes.LearningEvent{
				{DstName: "backend-7d9f8c6b5a-pod", DstNamespace: testNamespace},
			},
			wantProposalLen: 0,
		},
		{
			name: "unsupported owner skipped",
			objs: []client.Object{
				ownedPod("oneshot-pod", metav1.OwnerReference{
					APIVersion: "batch/v1",
					Kind:       "Job",
					Name:       "oneshot",
					UID:        "job-uid",
					Controller: new(true),
				}, nil),
			},
			events: []netypes.LearningEvent{
				{DstName: "oneshot-pod", DstNamespace: testNamespace},
			},
			wantProposalLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cl := fake.NewClientBuilder().
				WithScheme(newWorkloadTestScheme(t)).
				WithObjects(tt.objs...).
				Build()
			r := NewLearningReconciler(cl)
			ctx := context.Background()

			for _, evt := range tt.events {
				_, err := r.Reconcile(ctx, evt)
				require.NoError(t, err)
			}

			var proposals securityv1alpha1.WorkloadNetworkPolicyProposalList
			require.NoError(t, cl.List(ctx, &proposals, client.InNamespace(testNamespace)))
			require.Len(t, proposals.Items, tt.wantProposalLen)

			if tt.wantProposalLen == 0 {
				return
			}

			require.Equal(t, tt.wantProposalName, proposals.Items[0].Name)
			require.Equal(t, tt.wantSelector, proposals.Items[0].Spec.PodSelector.MatchLabels)
			require.Equal(
				t,
				[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				proposals.Items[0].Spec.PolicyTypes,
			)
		})
	}
}
