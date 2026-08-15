package terminal

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

type InventoryReporter struct{}

func (InventoryReporter) Render(writer io.Writer, state domain.ClusterState) error {
	if writer == nil {
		return fmt.Errorf("render inventory: output writer is nil")
	}
	clusterName := state.Cluster.Name
	if clusterName == "" {
		clusterName = state.Cluster.Context
	}
	if _, err := fmt.Fprintf(writer, "Cluster: %s\n", safeText(clusterName)); err != nil {
		return fmt.Errorf("render cluster heading: %w", err)
	}
	if state.Cluster.Context != "" {
		if _, err := fmt.Fprintf(writer, "Context: %s\n", safeText(state.Cluster.Context)); err != nil {
			return fmt.Errorf("render context: %w", err)
		}
	}
	if host := serverHostname(state.Cluster.Server); host != "" {
		if _, err := fmt.Fprintf(writer, "Server: %s\n", safeText(host)); err != nil {
			return fmt.Errorf("render server: %w", err)
		}
	}
	namespaceScope := "all namespaces"
	if len(state.Cluster.NamespaceScope) > 0 {
		namespaceScope = strings.Join(state.Cluster.NamespaceScope, ", ")
	}
	if _, err := fmt.Fprintf(writer, "Namespace scope: %s\n\n", safeText(namespaceScope)); err != nil {
		return fmt.Errorf("render namespace scope: %w", err)
	}

	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	for _, kind := range domain.InventoryKinds {
		if _, err := fmt.Fprintf(table, "%s\t%d\n", kind, state.Count(kind)); err != nil {
			return fmt.Errorf("render %s inventory count: %w", kind, err)
		}
	}
	if err := table.Flush(); err != nil {
		return fmt.Errorf("render inventory summary: %w", err)
	}
	return nil
}

func serverHostname(server string) string {
	parsed, err := url.Parse(server)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func safeText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value)
}
