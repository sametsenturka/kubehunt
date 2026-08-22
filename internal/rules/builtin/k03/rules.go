package k03

import (
	"context"
	"fmt"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
	workloadtarget "github.com/sametsenturka/kubehunt/internal/rules/workload"
)

var (
	categoryK03 = domain.OWASPCategory{ID: "K03", Version: "2025", Title: "Secrets Management Failures"}
	categoryK01 = domain.OWASPCategory{ID: "K01", Version: "2025", Title: "Insecure Workload Configurations"}
)

type workloadRule struct {
	metadata rules.Metadata
	evaluate func(workloadtarget.Target) []domain.Finding
}

func (rule workloadRule) Metadata() rules.Metadata { return rule.metadata }

func (rule workloadRule) Evaluate(ctx context.Context, state domain.ClusterState) ([]domain.Finding, error) {
	var findings []domain.Finding
	for _, target := range workloadtarget.Targets(state) {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		findings = append(findings, rule.evaluate(target)...)
		if err := ctx.Err(); err != nil {
			return findings, err
		}
	}
	return findings, nil
}

func Rules() []rules.Rule {
	return []rules.Rule{
		newRule(
			"KSCAN-K03-001",
			"Secret key exposed through an environment variable",
			"A container injects a Kubernetes Secret key into process environment state, where debugging output or application logging can expose it.",
			domain.SeverityMedium,
			"Prefer a read-only Secret volume or a purpose-built external secret provider, and ensure the application reads the credential from a file without logging it.",
			evaluateSecretKeyEnvironment,
		),
		newRule(
			"KSCAN-K03-002",
			"Entire Secret exposed through environment variables",
			"A container uses envFrom.secretRef, injecting every key from a Kubernetes Secret into process environment state.",
			domain.SeverityHigh,
			"Remove envFrom.secretRef. Provide only the required keys, preferably through a read-only Secret volume or a purpose-built external secret provider, and prevent credential logging.",
			evaluateWholeSecretEnvironment,
		),
	}
}

func newRule(id, title, description string, severity domain.Severity, remediation string, evaluate func(workloadtarget.Target) []domain.Finding) rules.Rule {
	return workloadRule{
		metadata: rules.Metadata{
			ID:                    id,
			Version:               "1.0.0",
			Title:                 title,
			Description:           description,
			DefaultSeverity:       severity,
			AffectedResourceTypes: []string{"Pod", "Deployment", "StatefulSet", "DaemonSet"},
			RequiredCapabilities:  []domain.CapabilityID{domain.CapabilityPodsList, domain.CapabilityWorkloadTemplatesList},
			Remediation:           remediation,
			OWASPMappings: []rules.OWASPMapping{
				{
					TaxonomyID: rules.OWASPTaxonomyID,
					Category:   categoryK03,
					Type:       rules.MappingPrimary,
					Rationale:  "The rule identifies a Kubernetes Secret exposed through process environment state.",
				},
				{
					TaxonomyID: rules.OWASPTaxonomyID,
					Category:   categoryK01,
					Type:       rules.MappingRelated,
					Rationale:  "The Secret exposure is introduced by workload container configuration.",
				},
			},
		},
		evaluate: evaluate,
	}
}

func evaluateSecretKeyEnvironment(target workloadtarget.Target) []domain.Finding {
	var findings []domain.Finding
	for _, container := range workloadtarget.Containers(target, true) {
		for _, reference := range container.Value.SecretEnvironmentVariables {
			if reference.SecretName == "" || reference.SecretKey == "" {
				continue
			}
			field := fmt.Sprintf("%s[name=%s].env[index=%d,name=%s].valueFrom.secretKeyRef", container.Field, container.Value.Name, reference.Index, reference.Name)
			value := reference.SecretName + "/" + reference.SecretKey
			message := fmt.Sprintf("%s %q: environment variable %q reads key %q from Secret %q", container.Display, container.Value.Name, reference.Name, reference.SecretKey, reference.SecretName)
			findings = append(findings, domain.Finding{Resource: target.Ref, Evidence: []domain.Evidence{{Field: field, Value: value, Message: message}}})
		}
	}
	return findings
}

func evaluateWholeSecretEnvironment(target workloadtarget.Target) []domain.Finding {
	var findings []domain.Finding
	for _, container := range workloadtarget.Containers(target, true) {
		for _, reference := range container.Value.SecretEnvironmentSources {
			if reference.SecretName == "" {
				continue
			}
			field := fmt.Sprintf("%s[name=%s].envFrom[index=%d].secretRef", container.Field, container.Value.Name, reference.Index)
			message := fmt.Sprintf("%s %q: envFrom injects every key from Secret %q into environment variables", container.Display, container.Value.Name, reference.SecretName)
			if reference.Prefix != "" {
				message += fmt.Sprintf(" with prefix %q", reference.Prefix)
			}
			findings = append(findings, domain.Finding{Resource: target.Ref, Evidence: []domain.Evidence{{Field: field, Value: reference.SecretName, Message: message}}})
		}
	}
	return findings
}
