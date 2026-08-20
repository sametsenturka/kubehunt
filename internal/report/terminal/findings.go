package terminal

import (
	"fmt"
	"io"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

type ScanReporter struct{}

func (ScanReporter) Render(writer io.Writer, result domain.ScanResult) error {
	if writer == nil {
		return fmt.Errorf("render scan: output writer is nil")
	}
	if err := (InventoryReporter{}).Render(writer, result.State); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "\nFindings: %d\n", len(result.Findings)); err != nil {
		return fmt.Errorf("render finding count: %w", err)
	}
	for _, finding := range result.Findings {
		if err := renderFinding(writer, finding); err != nil {
			return err
		}
	}
	return nil
}

func renderFinding(writer io.Writer, finding domain.Finding) error {
	primary := finding.PrimaryOWASP
	if _, err := fmt.Fprintf(writer, "\n%s %s\nOWASP %s:%s - %s\n\n", strings.ToUpper(string(finding.Severity)), safeText(finding.RuleID), safeText(primary.ID), safeText(primary.Version), safeText(primary.Title)); err != nil {
		return fmt.Errorf("render finding heading: %w", err)
	}
	if _, err := fmt.Fprintf(writer, "Resource:\n%s/%s\n\nNamespace:\n%s\n\nEvidence:\n", safeText(finding.Resource.Kind), safeText(finding.Resource.Name), safeText(finding.Namespace)); err != nil {
		return fmt.Errorf("render finding resource: %w", err)
	}
	for index, evidence := range finding.Evidence {
		prefix := ""
		if len(finding.Evidence) > 1 {
			prefix = "- "
		}
		if _, err := fmt.Fprintf(writer, "%s%s\n", prefix, safeText(evidence.Message)); err != nil {
			return fmt.Errorf("render finding evidence %d: %w", index, err)
		}
	}
	if len(finding.AffectedResources) > 0 {
		if _, err := fmt.Fprintln(writer, "\nAffected resources:"); err != nil {
			return fmt.Errorf("render affected resources heading: %w", err)
		}
		for _, resource := range finding.AffectedResources {
			name := resource.Kind + "/" + resource.Name
			if resource.Namespace != "" {
				name = resource.Kind + "/" + resource.Namespace + "/" + resource.Name
			}
			if _, err := fmt.Fprintf(writer, "- %s\n", safeText(name)); err != nil {
				return fmt.Errorf("render affected resource: %w", err)
			}
		}
	}
	if len(finding.AttackPath) > 0 {
		if _, err := fmt.Fprintln(writer, "\nAttack path:"); err != nil {
			return fmt.Errorf("render attack path heading: %w", err)
		}
		for _, step := range finding.AttackPath {
			if _, err := fmt.Fprintf(writer, "- %s --%s[%s]--> %s\n", safeText(pathNodeName(step.From)), safeText(step.Relationship), safeText(step.Confidence), safeText(pathNodeName(step.To))); err != nil {
				return fmt.Errorf("render attack path step: %w", err)
			}
		}
	}
	if len(finding.SupportingFindings) > 0 {
		if _, err := fmt.Fprintln(writer, "\nSupporting findings:"); err != nil {
			return fmt.Errorf("render supporting findings heading: %w", err)
		}
		for _, supporting := range finding.SupportingFindings {
			if _, err := fmt.Fprintf(writer, "- %s %s/%s\n", safeText(supporting.RuleID), safeText(supporting.Resource.Kind), safeText(supporting.Resource.Name)); err != nil {
				return fmt.Errorf("render supporting finding: %w", err)
			}
		}
	}
	if _, err := fmt.Fprintf(writer, "\nDescription:\n%s\n\nRemediation:\n%s\n", safeText(finding.Description), safeText(finding.Remediation)); err != nil {
		return fmt.Errorf("render finding details: %w", err)
	}
	return nil
}

func pathNodeName(node domain.AttackPathNode) string {
	if node.Resource != nil {
		if node.Resource.Namespace != "" {
			return node.Resource.Kind + "/" + node.Resource.Namespace + "/" + node.Resource.Name
		}
		return node.Resource.Kind + "/" + node.Resource.Name
	}
	name := node.Attributes["resource"]
	if name == "" {
		name = node.Attributes["url"]
	}
	if name == "" {
		return node.Kind
	}
	return node.Kind + "/" + name
}
