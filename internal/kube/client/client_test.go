package client

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestReadOnlyTransportAllowsSafeReads(t *testing.T) {
	t.Parallel()

	called := false
	transport := readOnlyTransport{next: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cluster.example/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatalf("safe GET rejected: %v", err)
	}
	if !called {
		t.Fatal("underlying transport was not called")
	}
}

func TestReadOnlyTransportAllowsResourceNamedLikeSubresource(t *testing.T) {
	t.Parallel()

	transport := readOnlyTransport{next: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cluster.example/api/v1/namespaces/default/pods/exec", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatalf("ordinary resource GET rejected: %v", err)
	}
}

func TestReadOnlyTransportRejectsMutationsAndDangerousReads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "post", method: http.MethodPost, path: "/api/v1/namespaces"},
		{name: "pod exec", method: http.MethodGet, path: "/api/v1/namespaces/default/pods/app/exec"},
		{name: "node proxy", method: http.MethodGet, path: "/api/v1/nodes/worker/proxy/metrics"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(context.Background(), test.method, "https://cluster.example"+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			transport := readOnlyTransport{next: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("underlying transport must not be called")
				return nil, nil
			})}

			if _, err := transport.RoundTrip(request); err == nil {
				t.Fatal("expected request to be rejected")
			}
		})
	}
}

func TestDefaultProviderUsesExplicitContext(t *testing.T) {
	t.Parallel()

	path := writeTestKubeconfig(t, &clientcmdapi.Config{
		CurrentContext: "first",
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster-one": {Server: "https://one.example"},
			"cluster-two": {Server: "https://two.example"},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"first":  {Cluster: "cluster-one", AuthInfo: "user"},
			"second": {Cluster: "cluster-two", AuthInfo: "user"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"user": {Token: "test-token"}},
	})

	connection, err := (DefaultProvider{}).Connect(context.Background(), Options{Kubeconfig: path, Context: "second"})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if connection.ContextName != "second" || connection.ClusterName != "cluster-two" || connection.Server != "https://two.example" {
		t.Fatalf("connection = %#v", connection)
	}
}

func TestDefaultProviderRejectsExecCredentialsByDefault(t *testing.T) {
	t.Parallel()

	path := writeTestKubeconfig(t, &clientcmdapi.Config{
		CurrentContext: "managed",
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://cluster.example"},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"managed": {Cluster: "cluster", AuthInfo: "exec-user"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"exec-user": {Exec: &clientcmdapi.ExecConfig{Command: "credential-helper"}},
		},
	})

	_, err := (DefaultProvider{}).Connect(context.Background(), Options{Kubeconfig: path})
	if err == nil || !strings.Contains(err.Error(), "disabled by default") {
		t.Fatalf("Connect() error = %v, want credential rejection", err)
	}
}

func TestDefaultProviderRejectsInsecureClusterTransport(t *testing.T) {
	t.Parallel()

	path := writeTestKubeconfig(t, &clientcmdapi.Config{
		CurrentContext: "insecure",
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://cluster.example", InsecureSkipTLSVerify: true},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"insecure": {Cluster: "cluster", AuthInfo: "user"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"user": {Token: "test-token"}},
	})

	_, err := (DefaultProvider{}).Connect(context.Background(), Options{Kubeconfig: path})
	if err == nil || !strings.Contains(err.Error(), "insecure-skip-tls-verify") {
		t.Fatalf("Connect() error = %v, want insecure transport rejection", err)
	}
}

func writeTestKubeconfig(t *testing.T, config *clientcmdapi.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := clientcmd.WriteToFile(*config, path); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}
