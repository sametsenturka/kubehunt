package cli

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/app"
	"github.com/sametsenturka/kubehunt/internal/domain"
)

type recordingScanner struct {
	result  domain.ScanResult
	err     error
	options app.ScanOptions
	called  bool
}

func (scanner *recordingScanner) Scan(_ context.Context, options app.ScanOptions) (domain.ScanResult, error) {
	scanner.called = true
	scanner.options = options
	return scanner.result, scanner.err
}

func TestScanClusterCommandPassesScopeAndPrintsInventory(t *testing.T) {
	t.Parallel()

	scanner := &recordingScanner{result: domain.ScanResult{State: domain.ClusterState{
		Cluster:    domain.ClusterMetadata{Name: "minikube"},
		Namespaces: make([]domain.Namespace, 2),
		Pods:       make([]domain.Pod, 3),
	}}}
	var output bytes.Buffer
	command := newRootCommand(scanner, &output)
	command.SetArgs([]string{
		"scan", "cluster",
		"--kubeconfig", "test-config",
		"--context", "test-context",
		"--namespace", "team-b",
		"--namespace", "team-a",
		"--allow-exec-credential",
	})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !scanner.called {
		t.Fatal("scanner was not called")
	}
	if scanner.options.Kubeconfig != "test-config" || scanner.options.Context != "test-context" || !scanner.options.AllowExecCredential {
		t.Fatalf("scan options = %#v", scanner.options)
	}
	if !reflect.DeepEqual(scanner.options.Namespaces, []string{"team-b", "team-a"}) {
		t.Fatalf("namespaces = %#v", scanner.options.Namespaces)
	}
	if !strings.Contains(output.String(), "Cluster: minikube") || !strings.Contains(output.String(), "Pods") {
		t.Fatalf("unexpected output:\n%s", output.String())
	}
}

func TestScanClusterCommandReturnsScannerError(t *testing.T) {
	t.Parallel()

	expected := errors.New("cluster unavailable")
	command := newRootCommand(&recordingScanner{err: expected}, &bytes.Buffer{})
	command.SetArgs([]string{"scan", "cluster"})
	if err := command.Execute(); !errors.Is(err, expected) {
		t.Fatalf("Execute() error = %v, want %v", err, expected)
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	command := newRootCommand(&recordingScanner{}, &output)
	command.SetArgs([]string{"version"})
	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.HasPrefix(output.String(), "kubehunt version ") {
		t.Fatalf("unexpected version output: %q", output.String())
	}
}
