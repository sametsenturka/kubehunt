package k04

import (
	"context"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
)

func TestRuleMetadata(t *testing.T) {
	t.Parallel()

	registered := Rules()
	if len(registered) != 4 {
		t.Fatalf("Rules() count = %d, want 4", len(registered))
	}
	for _, rule := range registered {
		metadata := rule.Metadata()
		if metadata.ID == "" || metadata.Version == "" || metadata.Title == "" || metadata.Description == "" || metadata.Remediation == "" || metadata.DefaultSeverity == "" {
			t.Errorf("incomplete metadata for %q: %#v", metadata.ID, metadata)
		}
		if len(metadata.AffectedResourceTypes) != 1 || len(metadata.RequiredCapabilities) != 1 {
			t.Errorf("unexpected applicability metadata for %q: %#v", metadata.ID, metadata)
		}
		if !hasMapping(metadata.OWASPMappings, "K04", rules.MappingPrimary) {
			t.Errorf("missing K04 primary mapping for %q: %#v", metadata.ID, metadata.OWASPMappings)
		}
	}
}

func TestPrivilegedPSAEnforcementPositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := domain.ClusterState{Namespaces: []domain.Namespace{{Metadata: domain.Metadata{
		Name: "development", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"},
	}}}}
	findings := evaluateRule(t, "KSCAN-K04-001", positive)
	if len(findings) != 1 || findings[0].Resource.Kind != "Namespace" || findings[0].Evidence[0].Value != "privileged" {
		t.Fatalf("positive findings = %#v, want one Namespace finding", findings)
	}

	for name, state := range map[string]domain.ClusterState{
		"restricted": {Namespaces: []domain.Namespace{{Metadata: domain.Metadata{Name: "production", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}}},
		"missing":    {Namespaces: []domain.Namespace{{Metadata: domain.Metadata{Name: "production"}}}},
	} {
		if findings := evaluateRule(t, "KSCAN-K04-001", state); len(findings) != 0 {
			t.Errorf("%s findings = %#v, want none", name, findings)
		}
	}
}

func TestNonEnforcingVAPBindingPositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := domain.ClusterState{ValidatingAdmissionPolicyBindings: []domain.ValidatingAdmissionPolicyBinding{{
		Metadata:          domain.Metadata{Name: "pod-security-audit"},
		PolicyName:        "pod-security",
		ValidationActions: []string{"Audit", "Warn"},
	}}}
	findings := evaluateRule(t, "KSCAN-K04-002", positive)
	if len(findings) != 1 || findings[0].Evidence[0].Value != "Audit,Warn" {
		t.Fatalf("positive findings = %#v, want one audit/warn finding", findings)
	}

	for name, actions := range map[string][]string{
		"deny":  {"Deny", "Audit"},
		"empty": nil,
	} {
		state := domain.ClusterState{ValidatingAdmissionPolicyBindings: []domain.ValidatingAdmissionPolicyBinding{{
			Metadata: domain.Metadata{Name: "binding"}, PolicyName: "policy", ValidationActions: actions,
		}}}
		if findings := evaluateRule(t, "KSCAN-K04-002", state); len(findings) != 0 {
			t.Errorf("%s findings = %#v, want none", name, findings)
		}
	}
}

func TestFailOpenVAPPositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := domain.ClusterState{ValidatingAdmissionPolicies: []domain.ValidatingAdmissionPolicy{{
		Metadata: domain.Metadata{Name: "required-labels"}, FailurePolicy: "Ignore",
	}}}
	findings := evaluateRule(t, "KSCAN-K04-003", positive)
	if len(findings) != 1 || findings[0].Evidence[0].Value != "Ignore" {
		t.Fatalf("positive findings = %#v, want one fail-open policy finding", findings)
	}

	for name, policy := range map[string]string{"fail": "Fail", "unset defaults to fail": ""} {
		state := domain.ClusterState{ValidatingAdmissionPolicies: []domain.ValidatingAdmissionPolicy{{Metadata: domain.Metadata{Name: "policy"}, FailurePolicy: policy}}}
		if findings := evaluateRule(t, "KSCAN-K04-003", state); len(findings) != 0 {
			t.Errorf("%s findings = %#v, want none", name, findings)
		}
	}
}

func TestFailOpenValidatingWebhookPositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := domain.ClusterState{ValidatingWebhookConfigurations: []domain.ValidatingWebhookConfiguration{{
		Metadata: domain.Metadata{Name: "security-policy"},
		Webhooks: []domain.ValidatingWebhook{{Name: "policy.example.com", FailurePolicy: "Ignore"}, {Name: "strict.example.com", FailurePolicy: "Fail"}},
	}}}
	findings := evaluateRule(t, "KSCAN-K04-004", positive)
	if len(findings) != 1 || findings[0].Evidence[0].Value != "policy.example.com=Ignore" {
		t.Fatalf("positive findings = %#v, want one fail-open webhook finding", findings)
	}

	for name, policy := range map[string]string{"fail": "Fail", "unset defaults to fail": ""} {
		state := domain.ClusterState{ValidatingWebhookConfigurations: []domain.ValidatingWebhookConfiguration{{
			Metadata: domain.Metadata{Name: "security-policy"}, Webhooks: []domain.ValidatingWebhook{{Name: "policy.example.com", FailurePolicy: policy}},
		}}}
		if findings := evaluateRule(t, "KSCAN-K04-004", state); len(findings) != 0 {
			t.Errorf("%s findings = %#v, want none", name, findings)
		}
	}
}

func evaluateRule(t *testing.T, ruleID string, state domain.ClusterState) []domain.Finding {
	t.Helper()
	for _, rule := range Rules() {
		if rule.Metadata().ID != ruleID {
			continue
		}
		findings, err := rule.Evaluate(context.Background(), state)
		if err != nil {
			t.Fatalf("Evaluate(%s) error = %v", ruleID, err)
		}
		return findings
	}
	t.Fatalf("rule %s not registered", ruleID)
	return nil
}

func hasMapping(mappings []rules.OWASPMapping, category string, mappingType rules.MappingType) bool {
	for _, mapping := range mappings {
		if mapping.Category.ID == category && mapping.Type == mappingType {
			return true
		}
	}
	return false
}
