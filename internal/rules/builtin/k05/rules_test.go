package k05

import (
	"context"
	"strings"
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
		if len(metadata.AffectedResourceTypes) == 0 || len(metadata.RequiredCapabilities) == 0 {
			t.Errorf("incomplete applicability metadata for %q: %#v", metadata.ID, metadata)
		}
		if !hasMapping(metadata.OWASPMappings, "K05", rules.MappingPrimary) {
			t.Errorf("missing K05 primary mapping for %q: %#v", metadata.ID, metadata.OWASPMappings)
		}
	}
}

func TestMissingIngressIsolationPositiveNegativeAndNearMiss(t *testing.T) {
	t.Parallel()

	pod := activePod("api", map[string]string{"app": "api"})
	positive := domain.ClusterState{Pods: []domain.Pod{pod}}
	assertOneFinding(t, "KSCAN-K05-001", positive, "Pod", "api")

	negative := domain.ClusterState{Pods: []domain.Pod{pod}, NetworkPolicies: []domain.NetworkPolicy{{
		Metadata:    domain.Metadata{Name: "api-ingress", Namespace: "production"},
		PodSelector: domain.LabelSelector{MatchExpressions: []domain.LabelSelectorRequirement{{Key: "app", Operator: "In", Values: []string{"api"}}}},
		PolicyTypes: []string{"Ingress"},
	}}}
	assertNoFindings(t, "KSCAN-K05-001", negative)

	nearMiss := negative
	nearMiss.NetworkPolicies[0].PodSelector = domain.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}
	assertOneFinding(t, "KSCAN-K05-001", nearMiss, "Pod", "api")
}

func TestSelectorDoesNotTreatMissingEmptyValuedLabelAsMatch(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		Pods: []domain.Pod{activePod("api", map[string]string{"app": "api"})},
		NetworkPolicies: []domain.NetworkPolicy{{
			Metadata:    domain.Metadata{Name: "requires-empty-label", Namespace: "production"},
			PodSelector: domain.LabelSelector{MatchLabels: map[string]string{"segmented": ""}},
			PolicyTypes: []string{"Ingress"},
		}},
	}
	assertOneFinding(t, "KSCAN-K05-001", state, "Pod", "api")
}

func TestNotInSelectorMatchesPodWithoutTheLabel(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		Pods: []domain.Pod{activePod("api", map[string]string{"app": "api"})},
		NetworkPolicies: []domain.NetworkPolicy{{
			Metadata: domain.Metadata{Name: "not-development", Namespace: "production"},
			PodSelector: domain.LabelSelector{MatchExpressions: []domain.LabelSelectorRequirement{{
				Key: "environment", Operator: "NotIn", Values: []string{"development"},
			}}},
			PolicyTypes: []string{"Ingress"},
		}},
	}
	assertNoFindings(t, "KSCAN-K05-001", state)
}

func TestMissingEgressIsolationPositiveNegativeAndDefaulting(t *testing.T) {
	t.Parallel()

	pod := activePod("api", map[string]string{"app": "api"})
	positive := domain.ClusterState{Pods: []domain.Pod{pod}, NetworkPolicies: []domain.NetworkPolicy{{
		Metadata: domain.Metadata{Name: "ingress-only", Namespace: "production"}, PodSelector: domain.LabelSelector{},
	}}}
	assertOneFinding(t, "KSCAN-K05-002", positive, "Pod", "api")

	negative := domain.ClusterState{Pods: []domain.Pod{pod}, NetworkPolicies: []domain.NetworkPolicy{{
		Metadata:    domain.Metadata{Name: "defaulted-both", Namespace: "production"},
		PodSelector: domain.LabelSelector{},
		Egress:      []domain.NetworkPolicyEgressRule{{To: []domain.NetworkPolicyPeer{{IPBlock: &domain.IPBlock{CIDR: "10.0.0.0/8"}}}}},
	}}}
	assertNoFindings(t, "KSCAN-K05-002", negative)
	assertNoFindings(t, "KSCAN-K05-001", negative)
}

func TestMissingIsolationSkipsCompletedAndHostNetworkPods(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{Pods: []domain.Pod{
		{Metadata: domain.Metadata{Name: "succeeded", Namespace: "production"}, Phase: "Succeeded"},
		{Metadata: domain.Metadata{Name: "failed", Namespace: "production"}, Phase: "Failed"},
		{Metadata: domain.Metadata{Name: "host-network", Namespace: "production"}, Phase: "Running", Spec: domain.PodSpec{HostNetwork: true}},
	}}
	for _, ruleID := range []string{"KSCAN-K05-001", "KSCAN-K05-002"} {
		assertNoFindings(t, ruleID, state)
	}
}

func TestAllSourcesIngressRulePositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := domain.ClusterState{NetworkPolicies: []domain.NetworkPolicy{{
		Metadata: domain.Metadata{Name: "public-http", Namespace: "production"},
		Ingress:  []domain.NetworkPolicyIngressRule{{Ports: []domain.NetworkPolicyPort{{Protocol: "TCP", Port: "443"}}}},
	}}}
	finding := assertOneFinding(t, "KSCAN-K05-003", positive, "NetworkPolicy", "public-http")
	if !strings.Contains(finding.Evidence[0].Message, "all sources") || !strings.Contains(finding.Evidence[0].Message, "TCP/443") {
		t.Fatalf("unexpected evidence: %#v", finding.Evidence)
	}

	negative := domain.ClusterState{NetworkPolicies: []domain.NetworkPolicy{{
		Metadata: domain.Metadata{Name: "private-http", Namespace: "production"},
		Ingress:  []domain.NetworkPolicyIngressRule{{From: []domain.NetworkPolicyPeer{{IPBlock: &domain.IPBlock{CIDR: "10.0.0.0/8"}}}}},
	}}}
	assertNoFindings(t, "KSCAN-K05-003", negative)
}

func TestAllDestinationsEgressRulePositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := domain.ClusterState{NetworkPolicies: []domain.NetworkPolicy{{
		Metadata: domain.Metadata{Name: "dns-anywhere", Namespace: "production"},
		Egress:   []domain.NetworkPolicyEgressRule{{Ports: []domain.NetworkPolicyPort{{Protocol: "UDP", Port: "53"}}}},
	}}}
	finding := assertOneFinding(t, "KSCAN-K05-004", positive, "NetworkPolicy", "dns-anywhere")
	if !strings.Contains(finding.Evidence[0].Message, "all destinations") || !strings.Contains(finding.Evidence[0].Message, "UDP/53") {
		t.Fatalf("unexpected evidence: %#v", finding.Evidence)
	}

	negative := domain.ClusterState{NetworkPolicies: []domain.NetworkPolicy{{
		Metadata: domain.Metadata{Name: "internal-egress", Namespace: "production"},
		Egress:   []domain.NetworkPolicyEgressRule{{To: []domain.NetworkPolicyPeer{{NamespaceSelector: &domain.LabelSelector{MatchLabels: map[string]string{"environment": "production"}}}}}},
	}}}
	assertNoFindings(t, "KSCAN-K05-004", negative)
}

func activePod(name string, labels map[string]string) domain.Pod {
	return domain.Pod{Metadata: domain.Metadata{Name: name, Namespace: "production", Labels: labels}, Phase: "Running"}
}

func assertOneFinding(t *testing.T, ruleID string, state domain.ClusterState, kind, name string) domain.Finding {
	t.Helper()
	findings := evaluateRule(t, ruleID, state)
	if len(findings) != 1 {
		t.Fatalf("%s findings = %#v, want one", ruleID, findings)
	}
	if findings[0].Resource.Kind != kind || findings[0].Resource.Name != name || len(findings[0].Evidence) == 0 {
		t.Fatalf("%s unexpected finding = %#v", ruleID, findings[0])
	}
	return findings[0]
}

func assertNoFindings(t *testing.T, ruleID string, state domain.ClusterState) {
	t.Helper()
	if findings := evaluateRule(t, ruleID, state); len(findings) != 0 {
		t.Fatalf("%s findings = %#v, want none", ruleID, findings)
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
