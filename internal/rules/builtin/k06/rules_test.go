package k06

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
	if len(registered) != 5 {
		t.Fatalf("Rules() count = %d, want 5", len(registered))
	}
	for _, rule := range registered {
		metadata := rule.Metadata()
		if metadata.ID == "" || metadata.Version == "" || metadata.Title == "" || metadata.Description == "" || metadata.Remediation == "" || metadata.DefaultSeverity == "" {
			t.Errorf("incomplete metadata for %q: %#v", metadata.ID, metadata)
		}
		if len(metadata.AffectedResourceTypes) != 1 || len(metadata.RequiredCapabilities) != 1 {
			t.Errorf("unexpected applicability metadata for %q: %#v", metadata.ID, metadata)
		}
		if !hasMapping(metadata.OWASPMappings, "K06", rules.MappingPrimary) {
			t.Errorf("missing K06 primary mapping for %q: %#v", metadata.ID, metadata.OWASPMappings)
		}
	}
}

func TestLoadBalancerServicePositiveAndNegative(t *testing.T) {
	t.Parallel()
	assertServiceRule(t, "KSCAN-K06-001", domain.Service{Metadata: metadata("public"), Type: "LoadBalancer"}, true)
	assertServiceRule(t, "KSCAN-K06-001", domain.Service{Metadata: metadata("internal"), Type: "ClusterIP"}, false)
	assertServiceRule(t, "KSCAN-K06-001", domain.Service{Metadata: metadata("node"), Type: "NodePort"}, false)
}

func TestNodePortServicePositiveAndNegative(t *testing.T) {
	t.Parallel()
	assertServiceRule(t, "KSCAN-K06-002", domain.Service{Metadata: metadata("node"), Type: "NodePort", Ports: []domain.ServicePort{{Port: 443, NodePort: 30443}}}, true)
	assertServiceRule(t, "KSCAN-K06-002", domain.Service{Metadata: metadata("internal"), Type: "ClusterIP"}, false)
	assertServiceRule(t, "KSCAN-K06-002", domain.Service{Metadata: metadata("load-balancer"), Type: "LoadBalancer"}, false)
}

func TestExternalIPsPositiveNegativeAndMissingValues(t *testing.T) {
	t.Parallel()
	assertServiceRule(t, "KSCAN-K06-003", domain.Service{Metadata: metadata("legacy"), Type: "ClusterIP", ExternalIPs: []string{"203.0.113.10"}}, true)
	assertServiceRule(t, "KSCAN-K06-003", domain.Service{Metadata: metadata("internal"), Type: "ClusterIP"}, false)
	assertServiceRule(t, "KSCAN-K06-003", domain.Service{Metadata: metadata("empty"), Type: "ClusterIP", ExternalIPs: []string{"", "  "}}, false)
}

func TestIngressRoutePositiveAndNearMiss(t *testing.T) {
	t.Parallel()

	positive := domain.ClusterState{Ingresses: []domain.Ingress{{
		Metadata: metadata("public-api"),
		Rules:    []domain.IngressRule{{Host: "api.example.test", Paths: []domain.IngressPath{{Path: "/", Backend: domain.IngressBackend{ServiceName: "api", ServicePort: "https"}}}}},
	}}}
	findings := evaluateRule(t, "KSCAN-K06-004", positive)
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence[0].Message, "api.example.test") {
		t.Fatalf("positive findings = %#v, want one routed Ingress", findings)
	}

	for name, ingress := range map[string]domain.Ingress{
		"no backends":      {Metadata: metadata("empty")},
		"resource backend": {Metadata: metadata("resource"), DefaultBackend: &domain.IngressBackend{Resource: "example.io/StorageBucket/assets"}},
		"empty service":    {Metadata: metadata("invalid"), DefaultBackend: &domain.IngressBackend{}},
	} {
		if findings := evaluateRule(t, "KSCAN-K06-004", domain.ClusterState{Ingresses: []domain.Ingress{ingress}}); len(findings) != 0 {
			t.Errorf("%s findings = %#v, want none", name, findings)
		}
	}
}

func TestNonPrivateLiteralAPIEndpointPositiveAndNegative(t *testing.T) {
	t.Parallel()

	for name, server := range map[string]string{
		"ipv4": "https://8.8.8.8:6443",
		"ipv6": "https://[2001:4860:4860::8888]:6443",
	} {
		findings := evaluateRule(t, "KSCAN-K06-005", domain.ClusterState{Cluster: domain.ClusterMetadata{Name: "cluster", Server: server}})
		if len(findings) != 1 || findings[0].Resource.Kind != "Cluster" {
			t.Errorf("%s findings = %#v, want one Cluster endpoint finding", name, findings)
		}
	}

	for name, server := range map[string]string{
		"private":  "https://10.0.0.10:6443",
		"loopback": "https://127.0.0.1:6443",
		"hostname": "https://api.example.test:6443",
		"invalid":  "://bad",
		"missing":  "",
	} {
		if findings := evaluateRule(t, "KSCAN-K06-005", domain.ClusterState{Cluster: domain.ClusterMetadata{Name: "cluster", Server: server}}); len(findings) != 0 {
			t.Errorf("%s findings = %#v, want none", name, findings)
		}
	}
}

func assertServiceRule(t *testing.T, ruleID string, service domain.Service, expected bool) {
	t.Helper()
	findings := evaluateRule(t, ruleID, domain.ClusterState{Services: []domain.Service{service}})
	if expected && (len(findings) != 1 || findings[0].Resource.Kind != "Service" || len(findings[0].Evidence) == 0) {
		t.Fatalf("%s findings = %#v, want one Service finding", ruleID, findings)
	}
	if !expected && len(findings) != 0 {
		t.Fatalf("%s findings = %#v, want none", ruleID, findings)
	}
}

func metadata(name string) domain.Metadata {
	return domain.Metadata{Name: name, Namespace: "production"}
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
