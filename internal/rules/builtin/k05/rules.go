package k05

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
)

var category = domain.OWASPCategory{ID: "K05", Version: "2025", Title: "Missing Network Segmentation Controls"}

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
			"KSCAN-K05-001",
			"Pod lacks ingress NetworkPolicy isolation",
			"An active Pod is not selected by any native NetworkPolicy that isolates ingress traffic.",
			domain.SeverityMedium,
			[]string{"Pod"},
			[]domain.CapabilityID{domain.CapabilityPodsList, domain.CapabilityNetworkPoliciesList},
			"Add an ingress-isolating NetworkPolicy that selects the Pod, start from default deny, and allow only reviewed sources and ports required by the workload.",
			func(ctx context.Context, state domain.ClusterState) []domain.Finding {
				return evaluateMissingIsolation(ctx, state, "Ingress")
			},
		),
		newRule(
			"KSCAN-K05-002",
			"Pod lacks egress NetworkPolicy isolation",
			"An active Pod is not selected by any native NetworkPolicy that isolates egress traffic.",
			domain.SeverityMedium,
			[]string{"Pod"},
			[]domain.CapabilityID{domain.CapabilityPodsList, domain.CapabilityNetworkPoliciesList},
			"Add an egress-isolating NetworkPolicy that selects the Pod, start from default deny, and allow only reviewed destinations and ports including required DNS and control-plane access.",
			func(ctx context.Context, state domain.ClusterState) []domain.Finding {
				return evaluateMissingIsolation(ctx, state, "Egress")
			},
		),
		newRule(
			"KSCAN-K05-003",
			"NetworkPolicy ingress rule allows all sources",
			"An ingress-isolating NetworkPolicy contains a rule with no from peers, allowing that rule's ports from every source under native NetworkPolicy semantics.",
			domain.SeverityMedium,
			[]string{"NetworkPolicy"},
			[]domain.CapabilityID{domain.CapabilityNetworkPoliciesList},
			"Replace the empty from peer list with reviewed pod, namespace, or IP block selectors and restrict destination ports to those required.",
			evaluateAllSourcesIngress,
		),
		newRule(
			"KSCAN-K05-004",
			"NetworkPolicy egress rule allows all destinations",
			"An egress-isolating NetworkPolicy contains a rule with no to peers, allowing that rule's ports to every destination under native NetworkPolicy semantics.",
			domain.SeverityMedium,
			[]string{"NetworkPolicy"},
			[]domain.CapabilityID{domain.CapabilityNetworkPoliciesList},
			"Replace the empty to peer list with reviewed pod, namespace, or IP block selectors and restrict destination ports to those required.",
			evaluateAllDestinationsEgress,
		),
	}
}

func newRule(id, title, description string, severity domain.Severity, affected []string, capabilities []domain.CapabilityID, remediation string, evaluate func(context.Context, domain.ClusterState) []domain.Finding) rules.Rule {
	return stateRule{
		metadata: rules.Metadata{
			ID:                    id,
			Version:               "1.0.0",
			Title:                 title,
			Description:           description,
			DefaultSeverity:       severity,
			AffectedResourceTypes: affected,
			RequiredCapabilities:  capabilities,
			Remediation:           remediation,
			OWASPMappings: []rules.OWASPMapping{{
				TaxonomyID: rules.OWASPTaxonomyID,
				Category:   category,
				Type:       rules.MappingPrimary,
				Rationale:  "The rule identifies missing or overly broad native Kubernetes network segmentation intent.",
			}},
		},
		evaluate: evaluate,
	}
}

func evaluateMissingIsolation(ctx context.Context, state domain.ClusterState, direction string) []domain.Finding {
	var findings []domain.Finding
	for _, pod := range state.Pods {
		if ctx.Err() != nil {
			return findings
		}
		if !eligibleForNativePolicyAssessment(pod) || isolatedInDirection(pod, state.NetworkPolicies, direction) {
			continue
		}
		findings = append(findings, domain.Finding{
			Resource: reference("v1", "Pod", pod.Metadata),
			Evidence: []domain.Evidence{{
				Field:   "metadata.labels+networkpolicies.spec.podSelector+spec.policyTypes",
				Value:   "no matching " + strings.ToLower(direction) + " isolation policy",
				Message: fmt.Sprintf("Pod %q is not selected by any NetworkPolicy with effective policy type %s", pod.Metadata.Name, direction),
			}},
		})
	}
	return findings
}

func evaluateAllSourcesIngress(ctx context.Context, state domain.ClusterState) []domain.Finding {
	var findings []domain.Finding
	for _, policy := range state.NetworkPolicies {
		if !hasEffectivePolicyType(policy, "Ingress") {
			continue
		}
		for index, ingress := range policy.Ingress {
			if ctx.Err() != nil {
				return findings
			}
			if len(ingress.From) != 0 {
				continue
			}
			ports := summarizePorts(ingress.Ports)
			findings = append(findings, domain.Finding{
				Resource: reference("networking.k8s.io/v1", "NetworkPolicy", policy.Metadata),
				Evidence: []domain.Evidence{{
					Field:   fmt.Sprintf("spec.ingress[index=%d].from", index),
					Value:   "all sources; ports=" + ports,
					Message: fmt.Sprintf("NetworkPolicy %q ingress rule %d allows %s from all sources", policy.Metadata.Name, index, ports),
				}},
			})
		}
	}
	return findings
}

func evaluateAllDestinationsEgress(ctx context.Context, state domain.ClusterState) []domain.Finding {
	var findings []domain.Finding
	for _, policy := range state.NetworkPolicies {
		if !hasEffectivePolicyType(policy, "Egress") {
			continue
		}
		for index, egress := range policy.Egress {
			if ctx.Err() != nil {
				return findings
			}
			if len(egress.To) != 0 {
				continue
			}
			ports := summarizePorts(egress.Ports)
			findings = append(findings, domain.Finding{
				Resource: reference("networking.k8s.io/v1", "NetworkPolicy", policy.Metadata),
				Evidence: []domain.Evidence{{
					Field:   fmt.Sprintf("spec.egress[index=%d].to", index),
					Value:   "all destinations; ports=" + ports,
					Message: fmt.Sprintf("NetworkPolicy %q egress rule %d allows %s to all destinations", policy.Metadata.Name, index, ports),
				}},
			})
		}
	}
	return findings
}

func eligibleForNativePolicyAssessment(pod domain.Pod) bool {
	if pod.Metadata.Name == "" || pod.Metadata.Namespace == "" || pod.Spec.HostNetwork {
		return false
	}
	return !strings.EqualFold(pod.Phase, "Succeeded") && !strings.EqualFold(pod.Phase, "Failed")
}

func isolatedInDirection(pod domain.Pod, policies []domain.NetworkPolicy, direction string) bool {
	for _, policy := range policies {
		if policy.Metadata.Namespace == pod.Metadata.Namespace && hasEffectivePolicyType(policy, direction) && selectorMatches(policy.PodSelector, pod.Metadata.Labels) {
			return true
		}
	}
	return false
}

func hasEffectivePolicyType(policy domain.NetworkPolicy, wanted string) bool {
	if len(policy.PolicyTypes) == 0 {
		if wanted == "Ingress" {
			return true
		}
		return wanted == "Egress" && len(policy.Egress) > 0
	}
	for _, policyType := range policy.PolicyTypes {
		if policyType == wanted {
			return true
		}
	}
	return false
}

func selectorMatches(selector domain.LabelSelector, labels map[string]string) bool {
	for key, expected := range selector.MatchLabels {
		actual, exists := labels[key]
		if !exists || actual != expected {
			return false
		}
	}
	for _, expression := range selector.MatchExpressions {
		value, exists := labels[expression.Key]
		switch expression.Operator {
		case "In":
			if !exists || !contains(expression.Values, value) {
				return false
			}
		case "NotIn":
			if exists && contains(expression.Values, value) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func summarizePorts(ports []domain.NetworkPolicyPort) string {
	if len(ports) == 0 {
		return "all ports"
	}
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "TCP"
		}
		value := port.Port
		if value == "" {
			value = "*"
		}
		if port.EndPort != nil {
			value += fmt.Sprintf("-%d", *port.EndPort)
		}
		values = append(values, protocol+"/"+value)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
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
