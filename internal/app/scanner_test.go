package app

import (
	"context"
	"errors"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/graph/model"
	kubeclient "github.com/sametsenturka/kubehunt/internal/kube/client"
	"github.com/sametsenturka/kubehunt/internal/kube/collectors"
)

func TestNewScannerRegistersK01AndK02Rules(t *testing.T) {
	t.Parallel()

	trueValue := true
	state := domain.ClusterState{
		Pods: []domain.Pod{{
			Metadata: domain.Metadata{Name: "privileged", Namespace: "team-a"},
			Spec: domain.PodSpec{Containers: []domain.Container{{
				Name: "app", SecurityContext: domain.ContainerSecurityContext{Privileged: &trueValue},
			}}},
		}},
		ClusterRoles: []domain.Role{{
			Metadata: domain.Metadata{Name: "secret-reader"},
			Rules:    []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		}},
		ClusterRoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "secret-reader"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "secret-reader"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}},
		}},
	}
	scanner := NewScanner()
	if scanner.InitializationError != nil {
		t.Fatalf("NewScanner() initialization error = %v", scanner.InitializationError)
	}
	findings, err := scanner.Rules.Evaluate(context.Background(), state)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	wanted := map[string]bool{"KSCAN-K01-001": false, "KSCAN-K02-003": false}
	for _, finding := range findings {
		if _, exists := wanted[finding.RuleID]; exists {
			wanted[finding.RuleID] = true
		}
	}
	for id, found := range wanted {
		if !found {
			t.Errorf("registered catalog did not produce %s", id)
		}
	}
}

func TestScannerBuildsGraphAndAppendsCorrelatedFindings(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{Cluster: domain.ClusterMetadata{Name: "test"}}
	base := domain.Finding{Fingerprint: "base", RuleID: "KSCAN-K02-006", Severity: domain.SeverityHigh}
	correlated := domain.Finding{Fingerprint: "path", RuleID: "KSCAN-PATH-002", Severity: domain.SeverityHigh}
	builder := &recordingGraphBuilder{graph: model.New()}
	correlator := &recordingCorrelator{findings: []domain.Finding{correlated}}
	scanner := &Scanner{
		Clients:      staticProvider{},
		Collector:    staticCollector{state: state},
		Rules:        staticRuleEngine{findings: []domain.Finding{base}},
		GraphBuilder: builder,
		Correlator:   correlator,
	}
	result, err := scanner.Scan(context.Background(), ScanOptions{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !builder.called || len(builder.findings) != 1 || builder.findings[0].RuleID != base.RuleID {
		t.Fatalf("graph builder did not receive rule findings: %#v", builder)
	}
	if !correlator.called || len(result.Findings) != 2 {
		t.Fatalf("correlation stage was not appended: called=%v findings=%#v", correlator.called, result.Findings)
	}
}

func TestScannerReturnsContextualGraphCorrelationError(t *testing.T) {
	t.Parallel()

	expected := errors.New("correlation failed")
	scanner := &Scanner{
		Clients:      staticProvider{},
		Collector:    staticCollector{state: domain.ClusterState{Cluster: domain.ClusterMetadata{Name: "test"}}},
		Rules:        staticRuleEngine{},
		GraphBuilder: &recordingGraphBuilder{graph: model.New()},
		Correlator:   &recordingCorrelator{err: expected},
	}
	if _, err := scanner.Scan(context.Background(), ScanOptions{}); !errors.Is(err, expected) {
		t.Fatalf("Scan() error = %v, want wrapped %v", err, expected)
	}
}

type staticProvider struct{}

func (staticProvider) Connect(context.Context, kubeclient.Options) (kubeclient.Connection, error) {
	return kubeclient.Connection{Client: fake.NewSimpleClientset(), ContextName: "test", ClusterName: "test", Server: "https://127.0.0.1:6443"}, nil
}

type staticCollector struct {
	state domain.ClusterState
	err   error
}

func (collector staticCollector) Collect(context.Context, kubernetes.Interface, domain.ClusterMetadata, collectors.Scope) (domain.ClusterState, error) {
	return collector.state, collector.err
}

type staticRuleEngine struct {
	findings []domain.Finding
	err      error
}

func (engine staticRuleEngine) Evaluate(context.Context, domain.ClusterState) ([]domain.Finding, error) {
	return engine.findings, engine.err
}

type recordingGraphBuilder struct {
	graph    *model.Graph
	err      error
	findings []domain.Finding
	called   bool
}

func (builder *recordingGraphBuilder) Build(_ domain.ClusterState, findings []domain.Finding) (*model.Graph, error) {
	builder.called = true
	builder.findings = append([]domain.Finding(nil), findings...)
	return builder.graph, builder.err
}

type recordingCorrelator struct {
	findings []domain.Finding
	err      error
	called   bool
}

func (correlator *recordingCorrelator) Evaluate(context.Context, *model.Graph) ([]domain.Finding, error) {
	correlator.called = true
	return correlator.findings, correlator.err
}
