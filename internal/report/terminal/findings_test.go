package terminal

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

func TestScanReporterRendersFinding(t *testing.T) {
	t.Parallel()

	result := domain.ScanResult{
		State: domain.ClusterState{Cluster: domain.ClusterMetadata{Name: "test"}},
		Findings: []domain.Finding{{
			RuleID:       "KSCAN-K01-001",
			Severity:     domain.SeverityHigh,
			Resource:     domain.ResourceReference{Kind: "Deployment", Namespace: "production", Name: "payment-api"},
			Namespace:    "production",
			Evidence:     []domain.Evidence{{Message: "container \"api\": securityContext.privileged=true"}},
			Description:  "A container is privileged.",
			Remediation:  "Set privileged to false.",
			PrimaryOWASP: domain.OWASPCategory{ID: "K01", Version: "2025", Title: "Insecure Workload Configurations"},
		}},
	}
	var output bytes.Buffer
	if err := (ScanReporter{}).Render(&output, result); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	for _, expected := range []string{"Findings: 1", "HIGH KSCAN-K01-001", "OWASP K01:2025 - Insecure Workload Configurations", "Deployment/payment-api", "production", "securityContext.privileged=true", "Set privileged to false."} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestScanReporterSanitizesFindingText(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	result := domain.ScanResult{State: domain.ClusterState{}, Findings: []domain.Finding{{
		RuleID:       "RULE\x1b[31m",
		Severity:     domain.SeverityHigh,
		Resource:     domain.ResourceReference{Kind: "Pod", Name: "unsafe\x1b[31m"},
		Evidence:     []domain.Evidence{{Message: "unsafe\x1b[31m"}},
		PrimaryOWASP: domain.OWASPCategory{ID: "K01", Version: "2025"},
	}}}
	if err := (ScanReporter{}).Render(&output, result); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if strings.ContainsRune(output.String(), '\x1b') {
		t.Fatalf("output contains escape character: %q", output.String())
	}
}

func TestScanReporterRendersCorrelatedAttackPath(t *testing.T) {
	t.Parallel()

	workload := domain.ResourceReference{Kind: "Deployment", Namespace: "production", Name: "api"}
	serviceAccount := domain.ResourceReference{Kind: "ServiceAccount", Namespace: "production", Name: "api"}
	result := domain.ScanResult{State: domain.ClusterState{Cluster: domain.ClusterMetadata{Name: "test"}}, Findings: []domain.Finding{{
		RuleID: "KSCAN-PATH-002", Title: "Pod creation opportunity", Severity: domain.SeverityHigh,
		Resource: workload, Namespace: "production", PrimaryOWASP: domain.OWASPCategory{ID: "K02", Version: "2025", Title: "Overly Permissive Authorization Configurations"},
		Evidence:          []domain.Evidence{{Field: "rules", Value: "create", Message: "Role permits Pod creation"}},
		AffectedResources: []domain.ResourceReference{workload, serviceAccount},
		AttackPath: []domain.AttackPathStep{{
			From: domain.AttackPathNode{Kind: "Deployment", Resource: &workload}, Relationship: "uses", To: domain.AttackPathNode{Kind: "ServiceAccount", Resource: &serviceAccount}, Confidence: "confirmed",
		}},
		SupportingFindings: []domain.SupportingFinding{{RuleID: "KSCAN-K02-006", Resource: domain.ResourceReference{Kind: "RoleBinding", Name: "pod-creator"}}},
		Description:        "A confirmed correlation.", Remediation: "Remove Pod creation permission.",
	}}}
	var output bytes.Buffer
	if err := (ScanReporter{}).Render(&output, result); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	for _, expected := range []string{"Affected resources:", "Deployment/production/api", "Attack path:", "--uses[confirmed]-->", "Supporting findings:", "KSCAN-K02-006 RoleBinding/pod-creator"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output missing %q:\n%s", expected, output.String())
		}
	}
}
