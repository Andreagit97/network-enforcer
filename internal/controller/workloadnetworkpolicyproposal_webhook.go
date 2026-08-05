/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

// +kubebuilder:webhook:path=/validate-security-rancher-io-v1alpha1-workloadnetworkpolicyproposal,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.rancher.io,resources=workloadnetworkpolicyproposals,verbs=create;update,versions=v1alpha1,name=validate-workloadnetworkpolicyproposals.rancher.io,admissionReviewVersions=v1

// ProposalWebhook validates WorkloadNetworkPolicyProposal resources.
type ProposalWebhook struct{}

var _ admission.Validator[*securityv1alpha1.WorkloadNetworkPolicyProposal] = &ProposalWebhook{}

func (w *ProposalWebhook) ValidateCreate(
	ctx context.Context,
	proposal *securityv1alpha1.WorkloadNetworkPolicyProposal,
) (admission.Warnings, error) {
	logger := log.FromContext(ctx)
	logger.Info("Validation for WorkloadNetworkPolicyProposal upon creation", "name", proposal.GetName())
	return nil, validatePromotionLabel(proposal)
}

func (w *ProposalWebhook) ValidateUpdate(
	ctx context.Context,
	_, newProposal *securityv1alpha1.WorkloadNetworkPolicyProposal,
) (admission.Warnings, error) {
	logger := log.FromContext(ctx)
	logger.Info("Validation for WorkloadNetworkPolicyProposal upon update", "name", newProposal.GetName())
	return nil, validatePromotionLabel(newProposal)
}

func (w *ProposalWebhook) ValidateDelete(
	_ context.Context,
	_ *securityv1alpha1.WorkloadNetworkPolicyProposal,
) (admission.Warnings, error) {
	return nil, nil
}

func validatePromotionLabel(
	proposal *securityv1alpha1.WorkloadNetworkPolicyProposal,
) error {
	val, ok := proposal.Labels[securityv1alpha1.ProposalPromoteLabelKey]
	if !ok {
		return nil
	}
	if _, valid := proposal.HasPromotionLabel(); valid {
		return nil
	}
	return apierrors.NewInvalid(
		schema.GroupKind{Group: securityv1alpha1.GroupVersion.Group, Kind: "WorkloadNetworkPolicyProposal"},
		proposal.Name,
		field.ErrorList{
			field.Invalid(
				field.NewPath("metadata", "labels").Key(securityv1alpha1.ProposalPromoteLabelKey),
				val,
				fmt.Sprintf(
					"unsupported value %q: must be %q or %q",
					val,
					securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
					securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				),
			),
		},
	)
}
