package rules

import (
	"context"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

const OWASPTaxonomyID = "owasp-kubernetes-top-10:2025"

type MappingType string

const (
	MappingPrimary MappingType = "primary"
	MappingRelated MappingType = "related"
)

type OWASPMapping struct {
	TaxonomyID string
	Category   domain.OWASPCategory
	Type       MappingType
	Rationale  string
}

type Metadata struct {
	ID                    string
	Version               string
	Title                 string
	Description           string
	DefaultSeverity       domain.Severity
	OWASPMappings         []OWASPMapping
	AffectedResourceTypes []string
	RequiredCapabilities  []domain.CapabilityID
	Remediation           string
}

type Rule interface {
	Metadata() Metadata
	Evaluate(context.Context, domain.ClusterState) ([]domain.Finding, error)
}
