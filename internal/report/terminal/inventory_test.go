package terminal

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

func TestInventoryReporterRendersAllCounts(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		Cluster:         domain.ClusterMetadata{Name: "minikube", Context: "local", Server: "https://127.0.0.1:6443", NamespaceScope: []string{"team-a"}},
		Namespaces:      make([]domain.Namespace, 2),
		Pods:            make([]domain.Pod, 3),
		Deployments:     make([]domain.Workload, 1),
		NetworkPolicies: make([]domain.NetworkPolicy, 4),
	}
	var output bytes.Buffer
	if err := (InventoryReporter{}).Render(&output, state); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	for _, expected := range []string{"Cluster: minikube", "Context: local", "Server: 127.0.0.1", "Namespace scope: team-a", "Namespaces", "2", "Pods", "3", "Deployments", "1", "NetworkPolicies", "4", "ClusterRoleBindings"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output does not contain %q:\n%s", expected, output.String())
		}
	}
}

func TestInventoryReporterStripsTerminalControlCharacters(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	state := domain.ClusterState{Cluster: domain.ClusterMetadata{Name: "safe\x1b[31munsafe"}}
	if err := (InventoryReporter{}).Render(&output, state); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if strings.ContainsRune(output.String(), '\x1b') {
		t.Fatalf("output contains an escape character: %q", output.String())
	}
}
