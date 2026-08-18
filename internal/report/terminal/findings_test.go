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
