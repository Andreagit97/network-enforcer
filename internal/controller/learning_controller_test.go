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
	netypes "github.com/rancher-sandbox/network-enforcer/internal/types"
)

func TestProcessIstioLearningEvent(t *testing.T) {
	t.Parallel()

	rsOwner := func(name string) *metav1.OwnerReference {
		return &metav1.OwnerReference{
			APIVersion: "apps/v1",
			Kind:       string(securityv1alpha1.WorkloadKindReplicaSet),
			Name:       name,
			UID:        "rs-uid",
			Controller: new(true),
		}
	}

	clientPrincipal := "cluster.local/ns/default/sa/http-client-sa"
	otherPrincipal := "cluster.local/ns/default/sa/other-client-sa"
	httpServerName := "http-server"
	httpServerHash := "6cbcc86f5d"
	httpServerRS := httpServerName + "-" + httpServerHash
	httpServerPodA := httpServerRS + "-aaa"
	httpServerPodB := httpServerRS + "-bbb"
	httpServerLabels := map[string]string{"app": httpServerName}

	httpServerProposal := getProposalName(securityv1alpha1.WorkloadRef{
		Namespace: testNamespace,
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		OwnerName: httpServerName,
	}, networkingv1.PolicyTypeIngress)
	backendProposal := getProposalName(securityv1alpha1.WorkloadRef{
		Namespace: testNamespace,
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
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
		wantRules        []securityv1alpha1.IstioAuthorizationPolicyRule
	}{
		{
			name: "stable proposal per deployment across replicas",
			objs: []client.Object{
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: httpServerName, Namespace: testNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: httpServerLabels,
						},
					},
				},
				ownedPod(httpServerPodA, rsOwner(httpServerRS), map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: httpServerHash,
				}),
				ownedPod(httpServerPodB, rsOwner(httpServerRS), map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: httpServerHash,
				}),
			},
			events: []netypes.LearningEvent{{
				Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: httpServerPodA},
				Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
				DstPort: "18080",
			}, {
				Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: httpServerPodB},
				Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
				DstPort: "18080",
			}},
			wantProposalName: httpServerProposal,
			wantSelector:     httpServerLabels,
			wantProposalLen:  1,
			wantRules: []securityv1alpha1.IstioAuthorizationPolicyRule{
				{
					From: []securityv1alpha1.IstioFrom{
						{Source: securityv1alpha1.IstioSource{Principals: []string{clientPrincipal}}},
					},
					To: []securityv1alpha1.IstioTo{
						{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080"}}},
					},
				},
			},
		},
		{
			name: "merges ports and principals without duplicates",
			objs: []client.Object{
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: httpServerName, Namespace: testNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: httpServerLabels,
						},
					},
				},
				ownedPod(httpServerPodA, rsOwner(httpServerRS), map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: httpServerHash,
				}),
			},
			events: []netypes.LearningEvent{
				{
					Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: httpServerPodA},
					Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
					DstPort: "18080",
				},
				{
					Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: httpServerPodA},
					Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
					DstPort: "18081",
				},
				{
					Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: httpServerPodA},
					Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
					DstPort: "18080",
				},
				{
					Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: httpServerPodA},
					Source:  &securityv1alpha1.WorkloadRef{Identity: otherPrincipal},
					DstPort: "18080",
				},
			},
			wantProposalName: httpServerProposal,
			wantSelector:     httpServerLabels,
			wantProposalLen:  1,
			wantRules: []securityv1alpha1.IstioAuthorizationPolicyRule{
				{
					From: []securityv1alpha1.IstioFrom{
						{Source: securityv1alpha1.IstioSource{Principals: []string{clientPrincipal}}},
					},
					To: []securityv1alpha1.IstioTo{
						{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080", "18081"}}},
					},
				},
				{
					From: []securityv1alpha1.IstioFrom{
						{Source: securityv1alpha1.IstioSource{Principals: []string{otherPrincipal}}},
					},
					To: []securityv1alpha1.IstioTo{
						{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080"}}},
					},
				},
			},
		},
		{
			name: "does not duplicate port present in a later To entry",
			objs: []client.Object{
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: httpServerName, Namespace: testNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: httpServerLabels,
						},
					},
				},
				ownedPod(httpServerPodA, rsOwner(httpServerRS), map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: httpServerHash,
				}),
				&securityv1alpha1.WorkloadNetworkPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      httpServerProposal,
						Namespace: testNamespace,
					},
					Spec: securityv1alpha1.WorkloadNetworkPolicyProposalSpec{
						PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
							Backend: securityv1alpha1.PolicyBackendIstio,
							Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
								Selector: metav1.LabelSelector{
									MatchLabels: httpServerLabels,
								},
								Rules: []securityv1alpha1.IstioAuthorizationPolicyRule{
									{
										From: []securityv1alpha1.IstioFrom{
											{
												Source: securityv1alpha1.IstioSource{
													Principals: []string{clientPrincipal},
												},
											},
										},
										To: []securityv1alpha1.IstioTo{
											{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080"}}},
											{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18081"}}},
										},
									},
								},
							},
						},
					},
				},
			},
			events: []netypes.LearningEvent{{
				Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: httpServerPodA},
				Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
				DstPort: "18081",
			}},
			wantProposalName: httpServerProposal,
			wantSelector:     httpServerLabels,
			wantProposalLen:  1,
			wantRules: []securityv1alpha1.IstioAuthorizationPolicyRule{
				{
					From: []securityv1alpha1.IstioFrom{
						{Source: securityv1alpha1.IstioSource{Principals: []string{clientPrincipal}}},
					},
					To: []securityv1alpha1.IstioTo{
						{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080"}}},
						{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18081"}}},
					},
				},
			},
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
			events: []netypes.LearningEvent{{
				Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: "backend-7d9f8c6b5a-pod"},
				Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
				DstPort: "8080",
			}},
			wantProposalLen: 0,
		},
		{
			name: "unsupported owner skipped",
			objs: []client.Object{
				ownedPod("oneshot-pod", &metav1.OwnerReference{
					APIVersion: "batch/v1",
					Kind:       "Job",
					Name:       "oneshot",
					UID:        "job-uid",
					Controller: new(true),
				}, nil),
			},
			events: []netypes.LearningEvent{{
				Dest:    &securityv1alpha1.WorkloadRef{Namespace: testNamespace, OwnerName: "oneshot-pod"},
				Source:  &securityv1alpha1.WorkloadRef{Identity: clientPrincipal},
				DstPort: "8080",
			}},
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
			require.Equal(t, securityv1alpha1.PolicyBackendIstio, proposals.Items[0].Spec.Backend)
			require.NotNil(t, proposals.Items[0].Spec.Istio)
			require.Equal(t, tt.wantSelector, proposals.Items[0].Spec.Istio.Selector.MatchLabels)
			require.Equal(t, tt.wantRules, proposals.Items[0].Spec.Istio.Rules)
		})
	}
}
