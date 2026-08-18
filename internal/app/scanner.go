package app

import (
	"context"
	"fmt"
	"time"

	"github.com/sametsenturka/kubehunt/internal/domain"
	kubeclient "github.com/sametsenturka/kubehunt/internal/kube/client"
	"github.com/sametsenturka/kubehunt/internal/kube/collectors"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k01"
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

type Scanner struct {
	Clients             kubeclient.Provider
	Collector           collectors.Collector
	Rules               RuleEngine
	Now                 func() time.Time
	InitializationError error
}

func NewScanner() *Scanner {
	ruleEngine, err := engine.New(k01.Rules()...)
	return &Scanner{
		Clients:             kubeclient.DefaultProvider{},
		Collector:           collectors.NewClusterCollector(),
		Rules:               ruleEngine,
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
	return domain.ScanResult{State: state, Findings: findings}, nil
}

func displayClusterName(metadata domain.ClusterMetadata) string {
	if metadata.Name != "" {
		return metadata.Name
	}
	return metadata.Context
}
