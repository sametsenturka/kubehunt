package app

import (
	"context"
	"fmt"
	"time"

	"github.com/sametsenturka/kubehunt/internal/domain"
	kubeclient "github.com/sametsenturka/kubehunt/internal/kube/client"
	"github.com/sametsenturka/kubehunt/internal/kube/collectors"
)

type ScanOptions struct {
	Kubeconfig          string
	Context             string
	Namespaces          []string
	AllowExecCredential bool
}

type ClusterScanner interface {
	Scan(context.Context, ScanOptions) (domain.ClusterState, error)
}

type Scanner struct {
	Clients   kubeclient.Provider
	Collector collectors.Collector
	Now       func() time.Time
}

func NewScanner() *Scanner {
	return &Scanner{
		Clients:   kubeclient.DefaultProvider{},
		Collector: collectors.NewClusterCollector(),
		Now:       time.Now,
	}
}

func (scanner *Scanner) Scan(ctx context.Context, options ScanOptions) (domain.ClusterState, error) {
	if scanner.Clients == nil {
		return domain.ClusterState{}, fmt.Errorf("scan cluster: Kubernetes client provider is nil")
	}
	if scanner.Collector == nil {
		return domain.ClusterState{}, fmt.Errorf("scan cluster: collector is nil")
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
		return domain.ClusterState{}, fmt.Errorf("scan cluster: %w", err)
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
		return state, fmt.Errorf("scan cluster %q: %w", displayClusterName(metadata), err)
	}
	return state, nil
}

func displayClusterName(metadata domain.ClusterMetadata) string {
	if metadata.Name != "" {
		return metadata.Name
	}
	return metadata.Context
}
