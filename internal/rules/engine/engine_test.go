package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
	"github.com/sametsenturka/kubehunt/internal/rules/engine"
)

type testRule struct {
	metadata rules.Metadata
	findings []domain.Finding
	err      error
}

func (rule testRule) Metadata() rules.Metadata { return rule.metadata }
func (rule testRule) Evaluate(context.Context, domain.ClusterState) ([]domain.Finding, error) {
	return rule.findings, rule.err
}

func TestEngineAppliesMetadataFingerprintAndDeduplicates(t *testing.T) {
	t.Parallel()

	finding := domain.Finding{
		Resource: domain.ResourceReference{APIVersion: "v1", Kind: "Pod", Namespace: "test", Name: "pod"},
		Evidence: []domain.Evidence{{Field: "spec.hostPID", Value: "true", Message: "spec.hostPID=true"}},
	}
	rule := testRule{metadata: validMetadata("TEST-001"), findings: []domain.Finding{finding, finding}}
	ruleEngine, err := engine.New(rule)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	findings, err := ruleEngine.Evaluate(context.Background(), domain.ClusterState{})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	got := findings[0]
	if got.RuleID != "TEST-001" || got.Title == "" || got.Description == "" || got.Remediation == "" || got.Severity != domain.SeverityHigh || got.PrimaryOWASP.ID != "K01" || got.Fingerprint == "" {
		t.Fatalf("finding metadata not applied: %#v", got)
	}
}

func TestEngineRejectsInvalidCatalog(t *testing.T) {
	t.Parallel()

	if _, err := engine.New(testRule{}); err == nil {
		t.Fatal("New() error = nil, want invalid metadata error")
	}
	metadata := validMetadata("TEST-001")
	if _, err := engine.New(testRule{metadata: metadata}, testRule{metadata: metadata}); err == nil {
		t.Fatal("New() error = nil, want duplicate ID error")
	}
}

func TestEngineContinuesAfterRuleError(t *testing.T) {
	t.Parallel()

	failed := testRule{metadata: validMetadata("TEST-001"), err: errors.New("broken")}
	good := testRule{metadata: validMetadata("TEST-002"), findings: []domain.Finding{{
		Resource: domain.ResourceReference{APIVersion: "v1", Kind: "Pod", Name: "pod"},
		Evidence: []domain.Evidence{{Field: "spec.hostPID", Value: "true", Message: "spec.hostPID=true"}},
	}}}
	ruleEngine, err := engine.New(failed, good)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	findings, err := ruleEngine.Evaluate(context.Background(), domain.ClusterState{})
	if err == nil || len(findings) != 1 || findings[0].RuleID != "TEST-002" {
		t.Fatalf("Evaluate() findings = %#v, error = %v", findings, err)
	}
}

func validMetadata(id string) rules.Metadata {
	return rules.Metadata{
		ID:                    id,
		Version:               "1.0.0",
		Title:                 "Test rule",
		Description:           "Test description",
		DefaultSeverity:       domain.SeverityHigh,
		AffectedResourceTypes: []string{"Pod"},
		RequiredCapabilities:  []domain.CapabilityID{domain.CapabilityPodsList},
		Remediation:           "Fix it.",
		OWASPMappings: []rules.OWASPMapping{{
			TaxonomyID: rules.OWASPTaxonomyID,
			Category:   domain.OWASPCategory{ID: "K01", Version: "2025", Title: "Insecure Workload Configurations"},
			Type:       rules.MappingPrimary,
			Rationale:  "Test rationale.",
		}},
	}
}
