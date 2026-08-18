package engine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
)

type Engine struct {
	rules []rules.Rule
}

func New(registered ...rules.Rule) (*Engine, error) {
	seen := make(map[string]struct{}, len(registered))
	for _, rule := range registered {
		if rule == nil {
			return nil, fmt.Errorf("validate rule catalog: rule is nil")
		}
		metadata := rule.Metadata()
		if err := validateMetadata(metadata); err != nil {
			return nil, fmt.Errorf("validate rule catalog: %w", err)
		}
		if _, exists := seen[metadata.ID]; exists {
			return nil, fmt.Errorf("validate rule catalog: duplicate rule ID %q", metadata.ID)
		}
		seen[metadata.ID] = struct{}{}
	}
	return &Engine{rules: append([]rules.Rule(nil), registered...)}, nil
}

func (engine *Engine) Evaluate(ctx context.Context, state domain.ClusterState) ([]domain.Finding, error) {
	if engine == nil {
		return nil, fmt.Errorf("evaluate rules: engine is nil")
	}
	var findings []domain.Finding
	var evaluationErrors []error
	for _, rule := range engine.rules {
		if err := ctx.Err(); err != nil {
			return findings, fmt.Errorf("evaluate rules: %w", err)
		}
		metadata := rule.Metadata()
		evaluated, err := evaluateSafely(ctx, rule, state)
		if err != nil {
			evaluationErrors = append(evaluationErrors, fmt.Errorf("rule %s: %w", metadata.ID, err))
			continue
		}
		for index := range evaluated {
			finding := &evaluated[index]
			applyMetadata(finding, metadata)
			if err := validateFinding(*finding); err != nil {
				evaluationErrors = append(evaluationErrors, fmt.Errorf("rule %s: %w", metadata.ID, err))
				continue
			}
			finding.Fingerprint = fingerprint(*finding)
			findings = append(findings, *finding)
		}
	}

	findings = deduplicate(findings)
	sortFindings(findings)
	if len(evaluationErrors) > 0 {
		return findings, fmt.Errorf("evaluate rules: %w", errors.Join(evaluationErrors...))
	}
	return findings, nil
}

func evaluateSafely(ctx context.Context, rule rules.Rule, state domain.ClusterState) (findings []domain.Finding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic during evaluation: %v", recovered)
		}
	}()
	return rule.Evaluate(ctx, state)
}

func validateMetadata(metadata rules.Metadata) error {
	switch {
	case metadata.ID == "":
		return fmt.Errorf("rule ID is empty")
	case metadata.Version == "":
		return fmt.Errorf("rule %s version is empty", metadata.ID)
	case metadata.Title == "":
		return fmt.Errorf("rule %s title is empty", metadata.ID)
	case metadata.Description == "":
		return fmt.Errorf("rule %s description is empty", metadata.ID)
	case metadata.DefaultSeverity.Rank() == 0:
		return fmt.Errorf("rule %s severity %q is invalid", metadata.ID, metadata.DefaultSeverity)
	case len(metadata.AffectedResourceTypes) == 0:
		return fmt.Errorf("rule %s has no affected resource types", metadata.ID)
	case len(metadata.RequiredCapabilities) == 0:
		return fmt.Errorf("rule %s has no required capabilities", metadata.ID)
	case metadata.Remediation == "":
		return fmt.Errorf("rule %s remediation is empty", metadata.ID)
	}
	primary := 0
	for _, mapping := range metadata.OWASPMappings {
		if mapping.TaxonomyID != rules.OWASPTaxonomyID || mapping.Category.ID == "" || mapping.Category.Version != "2025" || mapping.Rationale == "" {
			return fmt.Errorf("rule %s has an invalid OWASP mapping", metadata.ID)
		}
		if mapping.Type == rules.MappingPrimary {
			primary++
		} else if mapping.Type != rules.MappingRelated {
			return fmt.Errorf("rule %s has mapping with invalid type %q", metadata.ID, mapping.Type)
		}
	}
	if primary != 1 {
		return fmt.Errorf("rule %s must have exactly one primary OWASP mapping", metadata.ID)
	}
	return nil
}

func applyMetadata(finding *domain.Finding, metadata rules.Metadata) {
	finding.RuleID = metadata.ID
	finding.Title = metadata.Title
	if finding.Severity == "" {
		finding.Severity = metadata.DefaultSeverity
	}
	if finding.Description == "" {
		finding.Description = metadata.Description
	}
	if finding.Remediation == "" {
		finding.Remediation = metadata.Remediation
	}
	finding.Namespace = finding.Resource.Namespace
	for _, mapping := range metadata.OWASPMappings {
		if mapping.Type == rules.MappingPrimary {
			finding.PrimaryOWASP = mapping.Category
		} else {
			finding.RelatedOWASP = append(finding.RelatedOWASP, mapping.Category)
		}
	}
}

func validateFinding(finding domain.Finding) error {
	if finding.Resource.Kind == "" || finding.Resource.Name == "" {
		return fmt.Errorf("finding has an incomplete resource reference")
	}
	if len(finding.Evidence) == 0 {
		return fmt.Errorf("finding for %s/%s has no evidence", finding.Resource.Kind, finding.Resource.Name)
	}
	for _, evidence := range finding.Evidence {
		if evidence.Field == "" || evidence.Message == "" {
			return fmt.Errorf("finding for %s/%s has incomplete evidence", finding.Resource.Kind, finding.Resource.Name)
		}
	}
	return nil
}

func fingerprint(finding domain.Finding) string {
	parts := []string{"v1", finding.RuleID, finding.Resource.APIVersion, finding.Resource.Kind, finding.Resource.Namespace, finding.Resource.Name}
	for _, evidence := range finding.Evidence {
		parts = append(parts, evidence.Field, evidence.Value)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", sum[:16])
}

func deduplicate(findings []domain.Finding) []domain.Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if _, exists := seen[finding.Fingerprint]; exists {
			continue
		}
		seen[finding.Fingerprint] = struct{}{}
		result = append(result, finding)
	}
	return result
}

func sortFindings(findings []domain.Finding) {
	sort.SliceStable(findings, func(left, right int) bool {
		if findings[left].Severity.Rank() != findings[right].Severity.Rank() {
			return findings[left].Severity.Rank() > findings[right].Severity.Rank()
		}
		leftKey := findings[left].RuleID + "\x00" + findings[left].Resource.Kind + "\x00" + findings[left].Namespace + "\x00" + findings[left].Resource.Name + "\x00" + findings[left].Fingerprint
		rightKey := findings[right].RuleID + "\x00" + findings[right].Resource.Kind + "\x00" + findings[right].Namespace + "\x00" + findings[right].Resource.Name + "\x00" + findings[right].Fingerprint
		return leftKey < rightKey
	})
}
