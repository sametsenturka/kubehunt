package k03

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
	if len(registered) != 2 {
		t.Fatalf("Rules() count = %d, want 2", len(registered))
	}
	for _, rule := range registered {
		metadata := rule.Metadata()
		if metadata.ID == "" || metadata.Version == "" || metadata.Title == "" || metadata.Description == "" || metadata.Remediation == "" || metadata.DefaultSeverity == "" {
			t.Errorf("incomplete metadata for %q: %#v", metadata.ID, metadata)
		}
		if len(metadata.AffectedResourceTypes) != 4 || len(metadata.RequiredCapabilities) == 0 {
			t.Errorf("incomplete applicability metadata for %q: %#v", metadata.ID, metadata)
		}
		if !hasMapping(metadata.OWASPMappings, "K03", rules.MappingPrimary) || !hasMapping(metadata.OWASPMappings, "K01", rules.MappingRelated) {
			t.Errorf("unexpected OWASP mappings for %q: %#v", metadata.ID, metadata.OWASPMappings)
		}
	}
}

func TestSecretKeyEnvironmentRulePositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := stateWithContainer(domain.Container{
		Name: "api",
		SecretEnvironmentVariables: []domain.SecretEnvironmentVariable{{
			Name: "DATABASE_PASSWORD", SecretName: "database", SecretKey: "password",
		}},
	})
	findings := evaluateRule(t, "KSCAN-K03-001", positive)
	if len(findings) != 1 {
		t.Fatalf("positive findings = %#v, want one", findings)
	}
	if findings[0].Resource.Kind != "Pod" || findings[0].Resource.Name != "workload" || findings[0].Evidence[0].Value != "database/password" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence[0].Message, "DATABASE_PASSWORD") || !strings.Contains(findings[0].Evidence[0].Message, "database") {
		t.Fatalf("finding evidence lacks reference details: %#v", findings[0].Evidence)
	}

	negative := stateWithContainer(domain.Container{Name: "api"})
	if findings := evaluateRule(t, "KSCAN-K03-001", negative); len(findings) != 0 {
		t.Fatalf("negative findings = %#v, want none", findings)
	}
}

func TestWholeSecretEnvironmentRulePositiveAndNegative(t *testing.T) {
	t.Parallel()

	positive := stateWithContainer(domain.Container{
		Name: "worker",
		SecretEnvironmentSources: []domain.SecretEnvironmentSource{{
			Prefix: "APP_", SecretName: "application-secrets",
		}},
	})
	findings := evaluateRule(t, "KSCAN-K03-002", positive)
	if len(findings) != 1 {
		t.Fatalf("positive findings = %#v, want one", findings)
	}
	if findings[0].Severity != domain.SeverityHigh || findings[0].Evidence[0].Value != "application-secrets" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}

	negative := stateWithContainer(domain.Container{Name: "worker"})
	if findings := evaluateRule(t, "KSCAN-K03-002", negative); len(findings) != 0 {
		t.Fatalf("negative findings = %#v, want none", findings)
	}
}

func TestRulesAnalyzeRegularInitAndEphemeralContainers(t *testing.T) {
	t.Parallel()

	container := func(name string) domain.Container {
		return domain.Container{
			Name:                       name,
			SecretEnvironmentVariables: []domain.SecretEnvironmentVariable{{Name: "TOKEN", SecretName: "credentials", SecretKey: "token"}},
			SecretEnvironmentSources:   []domain.SecretEnvironmentSource{{SecretName: "credentials"}},
		}
	}
	state := domain.ClusterState{Pods: []domain.Pod{{
		Metadata: domain.Metadata{Name: "workload", Namespace: "production"},
		Spec: domain.PodSpec{
			Containers:          []domain.Container{container("app")},
			InitContainers:      []domain.Container{container("setup")},
			EphemeralContainers: []domain.Container{container("debugger")},
		},
	}}}
	for _, ruleID := range []string{"KSCAN-K03-001", "KSCAN-K03-002"} {
		findings := evaluateRule(t, ruleID, state)
		if len(findings) != 3 {
			t.Fatalf("%s findings = %d, want 3: %#v", ruleID, len(findings), findings)
		}
		fields := findings[0].Evidence[0].Field + findings[1].Evidence[0].Field + findings[2].Evidence[0].Field
		for _, expected := range []string{"containers", "initContainers", "ephemeralContainers"} {
			if !strings.Contains(fields, expected) {
				t.Errorf("%s evidence fields do not include %s: %q", ruleID, expected, fields)
			}
		}
	}
}

func TestControllerOwnedPodDoesNotDuplicateK03Finding(t *testing.T) {
	t.Parallel()

	controller := true
	container := domain.Container{
		Name: "api",
		SecretEnvironmentVariables: []domain.SecretEnvironmentVariable{{
			Name: "TOKEN", SecretName: "credentials", SecretKey: "token",
		}},
	}
	state := domain.ClusterState{
		Deployments: []domain.Workload{{
			Metadata: domain.Metadata{Name: "api", Namespace: "production"},
			Selector: domain.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: domain.PodTemplate{Spec: domain.PodSpec{Containers: []domain.Container{container}}},
		}},
		Pods: []domain.Pod{{
			Metadata: domain.Metadata{
				Name: "api-pod", Namespace: "production", Labels: map[string]string{"app": "api"},
				Owners: []domain.OwnerReference{{Kind: "ReplicaSet", Name: "api-rs", Controller: controller}},
			},
			Spec: domain.PodSpec{Containers: []domain.Container{container}},
		}},
	}
	findings := evaluateRule(t, "KSCAN-K03-001", state)
	if len(findings) != 1 || findings[0].Resource.Kind != "Deployment" {
		t.Fatalf("findings = %#v, want only Deployment finding", findings)
	}
}

func TestEmptySecretReferencesDoNotProduceFindings(t *testing.T) {
	t.Parallel()

	state := stateWithContainer(domain.Container{
		Name:                       "api",
		SecretEnvironmentVariables: []domain.SecretEnvironmentVariable{{Name: "TOKEN"}},
		SecretEnvironmentSources:   []domain.SecretEnvironmentSource{{Prefix: "APP_"}},
	})
	for _, ruleID := range []string{"KSCAN-K03-001", "KSCAN-K03-002"} {
		if findings := evaluateRule(t, ruleID, state); len(findings) != 0 {
			t.Fatalf("%s findings = %#v, want none", ruleID, findings)
		}
	}
}

func stateWithContainer(container domain.Container) domain.ClusterState {
	return domain.ClusterState{Pods: []domain.Pod{{
		Metadata: domain.Metadata{Name: "workload", Namespace: "production"},
		Spec:     domain.PodSpec{Containers: []domain.Container{container}},
	}}}
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
		for index := range findings {
			if findings[index].Severity == "" {
				findings[index].Severity = rule.Metadata().DefaultSeverity
			}
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
