package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const defaultTimeout = 30 * time.Second

type Options struct {
	Kubeconfig          string
	Context             string
	AllowExecCredential bool
}

type Connection struct {
	Client      kubernetes.Interface
	ContextName string
	ClusterName string
	Server      string
}

type Provider interface {
	Connect(context.Context, Options) (Connection, error)
}

type DefaultProvider struct{}

func (DefaultProvider) Connect(_ context.Context, options Options) (Connection, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if options.Kubeconfig != "" {
		loadingRules.ExplicitPath = options.Kubeconfig
	}

	rawConfig, err := loadingRules.Load()
	if err != nil {
		return Connection{}, fmt.Errorf("load kubeconfig: %w", err)
	}

	contextName := options.Context
	if contextName == "" {
		contextName = rawConfig.CurrentContext
	}
	if contextName == "" {
		return Connection{}, fmt.Errorf("select kubeconfig context: no current context is configured")
	}

	selectedContext, ok := rawConfig.Contexts[contextName]
	if !ok {
		return Connection{}, fmt.Errorf("select kubeconfig context %q: context does not exist", contextName)
	}
	selectedCluster, ok := rawConfig.Clusters[selectedContext.Cluster]
	if !ok {
		return Connection{}, fmt.Errorf("select cluster %q for context %q: cluster does not exist", selectedContext.Cluster, contextName)
	}
	if err := validateClusterTransport(selectedCluster.Server, selectedCluster.InsecureSkipTLSVerify); err != nil {
		return Connection{}, fmt.Errorf("validate cluster %q for context %q: %w", selectedContext.Cluster, contextName, err)
	}

	if !options.AllowExecCredential {
		if authInfo := rawConfig.AuthInfos[selectedContext.AuthInfo]; authInfo != nil && (authInfo.Exec != nil || authInfo.AuthProvider != nil) {
			return Connection{}, fmt.Errorf("load credentials for context %q: exec and auth-provider credentials are disabled by default; use --allow-exec-credential only if you trust the kubeconfig", contextName)
		}
	}

	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return Connection{}, fmt.Errorf("build Kubernetes client configuration for context %q: %w", contextName, err)
	}
	configureREST(restConfig)

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return Connection{}, fmt.Errorf("create Kubernetes client for context %q: %w", contextName, err)
	}

	return Connection{
		Client:      clientset,
		ContextName: contextName,
		ClusterName: selectedContext.Cluster,
		Server:      selectedCluster.Server,
	}, nil
}

func validateClusterTransport(server string, insecureSkipTLSVerify bool) error {
	if insecureSkipTLSVerify {
		return fmt.Errorf("insecure-skip-tls-verify is not allowed")
	}
	serverURL, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if !strings.EqualFold(serverURL.Scheme, "https") || serverURL.Hostname() == "" {
		return fmt.Errorf("server URL must use HTTPS and include a hostname")
	}
	return nil
}

func configureREST(config *rest.Config) {
	config.Timeout = defaultTimeout
	config.UserAgent = "kubehunt/dev"
	previousWrap := config.WrapTransport
	config.WrapTransport = func(transport http.RoundTripper) http.RoundTripper {
		if previousWrap != nil {
			transport = previousWrap(transport)
		}
		return readOnlyTransport{next: transport}
	}
}

type readOnlyTransport struct {
	next http.RoundTripper
}

func (transport readOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return nil, fmt.Errorf("KubeHunt read-only policy rejected HTTP method %s", request.Method)
	}
	if dangerousReadPath(request.URL.Path) {
		return nil, fmt.Errorf("KubeHunt read-only policy rejected API subresource path %q", request.URL.Path)
	}
	return transport.next.RoundTrip(request)
}

func dangerousReadPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for index, segment := range segments {
		switch segment {
		case "pods":
			if index+2 < len(segments) {
				switch segments[index+2] {
				case "proxy", "exec", "attach", "portforward":
					return true
				}
			}
		case "nodes", "services":
			if index+2 < len(segments) && segments[index+2] == "proxy" {
				return true
			}
		case "serviceaccounts":
			if index+2 < len(segments) && segments[index+2] == "token" {
				return true
			}
		}
	}
	return false
}
