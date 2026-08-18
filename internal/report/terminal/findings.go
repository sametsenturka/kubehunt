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
	if _, err := fmt.Fprintf(writer, "\nDescription:\n%s\n\nRemediation:\n%s\n", safeText(finding.Description), safeText(finding.Remediation)); err != nil {
		return fmt.Errorf("render finding details: %w", err)
	}
	return nil
}
