package app

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sametsenturka/kubehunt/internal/domain"
	graphbuild "github.com/sametsenturka/kubehunt/internal/graph/build"
	"github.com/sametsenturka/kubehunt/internal/graph/correlate"
	"github.com/sametsenturka/kubehunt/internal/graph/model"
	kubeclient "github.com/sametsenturka/kubehunt/internal/kube/client"
	"github.com/sametsenturka/kubehunt/internal/kube/collectors"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k01"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k02"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k03"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k04"
	"github.com/sametsenturka/kubehunt/internal/rules/engine"
)

type ScanOptions struct {
	Kubeconfig          string
	Context             string
	Namespaces          []string
	AllowExecCredential bool
}

type ClusterScanner interface {
	Scan(context.Context, ScanOptions) (domain.ScanResult, error)
}

type RuleEngine interface {
	Evaluate(context.Context, domain.ClusterState) ([]domain.Finding, error)
}

type GraphBuilder interface {
	Build(domain.ClusterState, []domain.Finding) (*model.Graph, error)
}

type AttackPathCorrelator interface {
	Evaluate(context.Context, *model.Graph) ([]domain.Finding, error)
}

type Scanner struct {
	Clients             kubeclient.Provider
	Collector           collectors.Collector
	Rules               RuleEngine
	GraphBuilder        GraphBuilder
	Correlator          AttackPathCorrelator
	Now                 func() time.Time
	InitializationError error
}

func NewScanner() *Scanner {
	registeredRules := append(k01.Rules(), k02.Rules()...)
	registeredRules = append(registeredRules, k03.Rules()...)
	registeredRules = append(registeredRules, k04.Rules()...)
	ruleEngine, err := engine.New(registeredRules...)
	return &Scanner{
		Clients:             kubeclient.DefaultProvider{},
		Collector:           collectors.NewClusterCollector(),
		Rules:               ruleEngine,
		GraphBuilder:        graphbuild.Builder{},
		Correlator:          correlate.New(),
		Now:                 time.Now,
		InitializationError: err,
	}
}

func (scanner *Scanner) Scan(ctx context.Context, options ScanOptions) (domain.ScanResult, error) {
	if scanner.InitializationError != nil {
		return domain.ScanResult{}, fmt.Errorf("scan cluster: initialize rules: %w", scanner.InitializationError)
	}
	if scanner.Clients == nil {
		return domain.ScanResult{}, fmt.Errorf("scan cluster: Kubernetes client provider is nil")
	}
	if scanner.Collector == nil {
		return domain.ScanResult{}, fmt.Errorf("scan cluster: collector is nil")
	}
	if scanner.Rules == nil {
		return domain.ScanResult{}, fmt.Errorf("scan cluster: rule engine is nil")
	}
	if scanner.GraphBuilder == nil {
		return domain.ScanResult{}, fmt.Errorf("scan cluster: graph builder is nil")
	}
	if scanner.Correlator == nil {
		return domain.ScanResult{}, fmt.Errorf("scan cluster: attack path correlator is nil")
	}
	now := scanner.Now
	if now == nil {
		now = time.Now
	}

	connection, err := scanner.Clients.Connect(ctx, kubeclient.Options{
		Kubeconfig:          options.Kubeconfig,
		Context:             options.Context,
		AllowExecCredential: options.AllowExecCredential,
	})
	if err != nil {
		return domain.ScanResult{}, fmt.Errorf("scan cluster: %w", err)
	}

	metadata := domain.ClusterMetadata{
		Context:   connection.ContextName,
		Name:      connection.ClusterName,
		Server:    connection.Server,
		StartedAt: now().UTC(),
	}
	state, err := scanner.Collector.Collect(ctx, connection.Client, metadata, collectors.Scope{Namespaces: options.Namespaces})
	state.Cluster.EndedAt = now().UTC()
	if err != nil {
		return domain.ScanResult{State: state}, fmt.Errorf("scan cluster %q: %w", displayClusterName(metadata), err)
	}
	findings, err := scanner.Rules.Evaluate(ctx, state)
	if err != nil {
		return domain.ScanResult{State: state, Findings: findings}, fmt.Errorf("scan cluster %q: analyze security posture: %w", displayClusterName(metadata), err)
	}
	graph, err := scanner.GraphBuilder.Build(state, findings)
	if err != nil {
		return domain.ScanResult{State: state, Findings: findings}, fmt.Errorf("scan cluster %q: build attack graph: %w", displayClusterName(metadata), err)
	}
	correlated, err := scanner.Correlator.Evaluate(ctx, graph)
	if err != nil {
		return domain.ScanResult{State: state, Findings: findings}, fmt.Errorf("scan cluster %q: correlate attack paths: %w", displayClusterName(metadata), err)
	}
	findings = append(findings, correlated...)
	sort.SliceStable(findings, func(left, right int) bool {
		if findings[left].Severity.Rank() != findings[right].Severity.Rank() {
			return findings[left].Severity.Rank() > findings[right].Severity.Rank()
		}
		leftKey := findings[left].RuleID + "\x00" + findings[left].Resource.Kind + "\x00" + findings[left].Resource.Namespace + "\x00" + findings[left].Resource.Name + "\x00" + findings[left].Fingerprint
		rightKey := findings[right].RuleID + "\x00" + findings[right].Resource.Kind + "\x00" + findings[right].Resource.Namespace + "\x00" + findings[right].Resource.Name + "\x00" + findings[right].Fingerprint
		return leftKey < rightKey
	})
	return domain.ScanResult{State: state, Findings: findings}, nil
}

func displayClusterName(metadata domain.ClusterMetadata) string {
	if metadata.Name != "" {
		return metadata.Name
	}
	return metadata.Context
}
