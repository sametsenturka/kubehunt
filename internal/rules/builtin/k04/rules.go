package k04

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
)

const psaEnforceLabel = "pod-security.kubernetes.io/enforce"

var category = domain.OWASPCategory{ID: "K04", Version: "2025", Title: "Lack Of Cluster Level Policy Enforcement"}

type stateRule struct {
	metadata rules.Metadata
	evaluate func(context.Context, domain.ClusterState) []domain.Finding
}

func (rule stateRule) Metadata() rules.Metadata { return rule.metadata }

func (rule stateRule) Evaluate(ctx context.Context, state domain.ClusterState) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	findings := rule.evaluate(ctx, state)
	if err := ctx.Err(); err != nil {
		return findings, err
	}
	return findings, nil
}

func Rules() []rules.Rule {
	return []rules.Rule{
		newRule(
			"KSCAN-K04-001",
			"Pod Security Admission enforcement explicitly privileged",
			"A Namespace explicitly selects the privileged Pod Security Admission enforcement level, which does not restrict workload security settings through that namespace label.",
			domain.SeverityMedium,
			"Namespace",
			domain.CapabilityNamespacesList,
			"Set pod-security.kubernetes.io/enforce to baseline or restricted after validating workload compatibility, and pin an appropriate policy version.",
			evaluatePrivilegedPSA,
		),
		newRule(
			"KSCAN-K04-002",
			"ValidatingAdmissionPolicy binding does not deny violations",
			"A ValidatingAdmissionPolicyBinding uses Audit or Warn actions without Deny, so matching validation failures are observed but not rejected by this binding.",
			domain.SeverityMedium,
			"ValidatingAdmissionPolicyBinding",
			domain.CapabilityValidatingAdmissionBindingsList,
			"After a safe audit rollout, add Deny to validationActions for controls that must be enforced and verify the binding's match scope and exclusions.",
			evaluateNonEnforcingBindings,
		),
		newRule(
			"KSCAN-K04-003",
			"ValidatingAdmissionPolicy explicitly fails open",
			"A ValidatingAdmissionPolicy explicitly ignores policy compilation, runtime, or configuration failures instead of failing the admission request.",
			domain.SeverityMedium,
			"ValidatingAdmissionPolicy",
			domain.CapabilityValidatingAdmissionPoliciesList,
			"Set failurePolicy to Fail after validating the policy and its parameters, and monitor admission failures during rollout.",
			evaluateFailOpenPolicies,
		),
		newRule(
			"KSCAN-K04-004",
			"Validating admission webhook explicitly fails open",
			"A validating admission webhook explicitly allows matching requests when the webhook call fails.",
			domain.SeverityMedium,
			"ValidatingWebhookConfiguration",
			domain.CapabilityValidatingWebhookConfigurationsList,
			"After validating webhook availability and recovery procedures, set failurePolicy to Fail for security controls that must block non-compliant resources.",
			evaluateFailOpenWebhooks,
		),
	}
}

func newRule(id, title, description string, severity domain.Severity, affected string, capability domain.CapabilityID, remediation string, evaluate func(context.Context, domain.ClusterState) []domain.Finding) rules.Rule {
	return stateRule{
		metadata: rules.Metadata{
			ID:                    id,
			Version:               "1.0.0",
			Title:                 title,
			Description:           description,
			DefaultSeverity:       severity,
			AffectedResourceTypes: []string{affected},
			RequiredCapabilities:  []domain.CapabilityID{capability},
			Remediation:           remediation,
			OWASPMappings: []rules.OWASPMapping{{
				TaxonomyID: rules.OWASPTaxonomyID,
				Category:   category,
				Type:       rules.MappingPrimary,
				Rationale:  "The rule identifies explicit policy configuration that does not reject matching security-policy failures.",
			}},
		},
		evaluate: evaluate,
	}
}

func evaluatePrivilegedPSA(ctx context.Context, state domain.ClusterState) []domain.Finding {
	var findings []domain.Finding
	for _, namespace := range state.Namespaces {
		if ctx.Err() != nil {
			return findings
		}
		if namespace.Metadata.Labels[psaEnforceLabel] != "privileged" {
			continue
		}
		findings = append(findings, domain.Finding{
			Resource: reference("v1", "Namespace", namespace.Metadata),
			Evidence: []domain.Evidence{{
				Field:   fmt.Sprintf("metadata.labels[%q]", psaEnforceLabel),
				Value:   "privileged",
				Message: fmt.Sprintf("Namespace %q explicitly sets Pod Security Admission enforce level to privileged", namespace.Metadata.Name),
			}},
		})
	}
	return findings
}

func evaluateNonEnforcingBindings(ctx context.Context, state domain.ClusterState) []domain.Finding {
	var findings []domain.Finding
	for _, binding := range state.ValidatingAdmissionPolicyBindings {
		if ctx.Err() != nil {
			return findings
		}
		if len(binding.ValidationActions) == 0 || contains(binding.ValidationActions, "Deny") {
			continue
		}
		actions := canonicalStrings(binding.ValidationActions)
		findings = append(findings, domain.Finding{
			Resource: reference("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", binding.Metadata),
			Evidence: []domain.Evidence{{
				Field:   "spec.validationActions",
				Value:   actions,
				Message: fmt.Sprintf("binding %q references policy %q with validation actions %s and no Deny action", binding.Metadata.Name, binding.PolicyName, actions),
			}},
		})
	}
	return findings
}

func evaluateFailOpenPolicies(ctx context.Context, state domain.ClusterState) []domain.Finding {
	var findings []domain.Finding
	for _, policy := range state.ValidatingAdmissionPolicies {
		if ctx.Err() != nil {
			return findings
		}
		if policy.FailurePolicy != "Ignore" {
			continue
		}
		findings = append(findings, domain.Finding{
			Resource: reference("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", policy.Metadata),
			Evidence: []domain.Evidence{{
				Field:   "spec.failurePolicy",
				Value:   "Ignore",
				Message: fmt.Sprintf("ValidatingAdmissionPolicy %q explicitly sets failurePolicy=Ignore", policy.Metadata.Name),
			}},
		})
	}
	return findings
}

func evaluateFailOpenWebhooks(ctx context.Context, state domain.ClusterState) []domain.Finding {
	var findings []domain.Finding
	for _, configuration := range state.ValidatingWebhookConfigurations {
		for index, webhook := range configuration.Webhooks {
			if ctx.Err() != nil {
				return findings
			}
			if webhook.FailurePolicy != "Ignore" {
				continue
			}
			findings = append(findings, domain.Finding{
				Resource: reference("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", configuration.Metadata),
				Evidence: []domain.Evidence{{
					Field:   fmt.Sprintf("webhooks[index=%d,name=%s].failurePolicy", index, webhook.Name),
					Value:   webhook.Name + "=Ignore",
					Message: fmt.Sprintf("validating webhook %q explicitly sets failurePolicy=Ignore", webhook.Name),
				}},
			})
		}
	}
	return findings
}

func reference(apiVersion, kind string, metadata domain.Metadata) domain.ResourceReference {
	return domain.ResourceReference{APIVersion: apiVersion, Kind: kind, Namespace: metadata.Namespace, Name: metadata.Name, UID: metadata.UID}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func canonicalStrings(values []string) string {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	unique := copy[:0]
	for _, value := range copy {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return strings.Join(unique, ",")
}
