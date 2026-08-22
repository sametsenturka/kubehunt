package k06

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
)

var category = domain.OWASPCategory{ID: "K06", Version: "2025", Title: "Overly Exposed Kubernetes Components"}

type stateRule struct {
	metadata rules.Metadata
	evaluate func(context.Context, domain.ClusterState) []domain.Finding
}

func (rule stateRule) Metadata() rules.Metadata { return rule.metadata }

func (rule stateRule) Evaluate(ctx context.Context, state domain.ClusterState) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	findings := rule.evaluate(ctx, state)
	if err := ctx.Err(); err != nil {
		return findings, err
	}
	return findings, nil
}

func Rules() []rules.Rule {
	return []rules.Rule{
		newRule("KSCAN-K06-001", "LoadBalancer Service creates a potential exposure surface", "A Service explicitly requests a load balancer. The resulting route may be external or internal depending on infrastructure that is not visible to this scan.", domain.SeverityLow, "Service", domain.CapabilityServicesList, "Confirm that the load balancer is required, restrict its source networks in the authoritative infrastructure configuration, and prefer an internal load balancer for private services.", evaluateLoadBalancerServices),
		newRule("KSCAN-K06-002", "NodePort Service creates a node-level exposure surface", "A Service exposes one or more ports on cluster nodes. Node routing and firewall configuration determine whether those ports are reachable outside trusted networks.", domain.SeverityLow, "Service", domain.CapabilityServicesList, "Use ClusterIP unless node-level exposure is required, and restrict node-port access with reviewed firewalls, security groups, or equivalent network controls.", evaluateNodePortServices),
		newRule("KSCAN-K06-003", "Service declares external IP addresses", "A Service declares externalIPs that can route traffic to the Service when those addresses are routed to cluster nodes.", domain.SeverityLow, "Service", domain.CapabilityServicesList, "Remove unnecessary externalIPs and manage required external routing through a reviewed load balancer or gateway with explicit source restrictions.", evaluateExternalIPServices),
		newRule("KSCAN-K06-004", "Ingress declares a potential external route", "An Ingress declares an HTTP or HTTPS route to a Service backend. An Ingress controller and surrounding network configuration determine actual reachability.", domain.SeverityLow, "Ingress", domain.CapabilityIngressesList, "Confirm that every Ingress route is required, restrict it through the ingress controller and network perimeter, and enforce TLS and application authentication.", evaluateIngressRoutes),
		newRule("KSCAN-K06-005", "Kubernetes API endpoint uses a non-private literal IP", "The selected kubeconfig context addresses the Kubernetes API through a non-private literal IP. This is an exposure indicator, not proof that untrusted sources can reach the endpoint.", domain.SeverityMedium, "Cluster", domain.CapabilityClusterEndpointObserve, "Restrict API server access to trusted networks and administrative hosts, verify cloud firewall or authorized-network settings, and use a private endpoint where practical.", evaluateAPIEndpoint),
	}
}

func newRule(id, title, description string, severity domain.Severity, affected string, capability domain.CapabilityID, remediation string, evaluate func(context.Context, domain.ClusterState) []domain.Finding) rules.Rule {
	return stateRule{
		metadata: rules.Metadata{
			ID:                    id,
			Version:               "1.0.0",
			Title:                 title,
			Description:           description,
			DefaultSeverity:       severity,
			AffectedResourceTypes: []string{affected},
			RequiredCapabilities:  []domain.CapabilityID{capability},
			Remediation:           remediation,
			OWASPMappings: []rules.OWASPMapping{{
				TaxonomyID: rules.OWASPTaxonomyID,
				Category:   category,
				Type:       rules.MappingPrimary,
				Rationale:  "The rule identifies an explicit Kubernetes configuration that can create an externally reachable component or workload surface.",
			}},
		},
		evaluate: evaluate,
	}
}

func evaluateLoadBalancerServices(ctx context.Context, state domain.ClusterState) []domain.Finding {
	return evaluateServices(ctx, state, func(service domain.Service) []domain.Evidence {
		if service.Type != "LoadBalancer" {
			return nil
		}
		return []domain.Evidence{{Field: "spec.type", Value: "LoadBalancer", Message: fmt.Sprintf("Service %q requests a LoadBalancer; actual external reachability is not verified", service.Metadata.Name)}}
	})
}

func evaluateNodePortServices(ctx context.Context, state domain.ClusterState) []domain.Finding {
	return evaluateServices(ctx, state, func(service domain.Service) []domain.Evidence {
		if service.Type != "NodePort" {
			return nil
		}
		ports := make([]string, 0, len(service.Ports))
		for _, port := range service.Ports {
			if port.NodePort > 0 {
				ports = append(ports, fmt.Sprint(port.NodePort))
			}
		}
		sort.Strings(ports)
		value := strings.Join(ports, ",")
		if value == "" {
			value = "allocated by Kubernetes"
		}
		return []domain.Evidence{{Field: "spec.type+spec.ports[].nodePort", Value: value, Message: fmt.Sprintf("Service %q uses NodePort; node addresses and firewall reachability are not verified", service.Metadata.Name)}}
	})
}

func evaluateExternalIPServices(ctx context.Context, state domain.ClusterState) []domain.Finding {
	return evaluateServices(ctx, state, func(service domain.Service) []domain.Evidence {
		values := nonEmptySorted(service.ExternalIPs)
		if len(values) == 0 {
			return nil
		}
		joined := strings.Join(values, ",")
		return []domain.Evidence{{Field: "spec.externalIPs", Value: joined, Message: fmt.Sprintf("Service %q declares external IPs %s; routing to those addresses is not verified", service.Metadata.Name, joined)}}
	})
}

func evaluateServices(ctx context.Context, state domain.ClusterState, evidence func(domain.Service) []domain.Evidence) []domain.Finding {
	var findings []domain.Finding
	for _, service := range state.Services {
		if ctx.Err() != nil {
			return findings
		}
		observed := evidence(service)
		if len(observed) == 0 || service.Metadata.Name == "" {
			continue
		}
		findings = append(findings, domain.Finding{Resource: reference("v1", "Service", service.Metadata), Evidence: observed})
	}
	return findings
}

func evaluateIngressRoutes(ctx context.Context, state domain.ClusterState) []domain.Finding {
	var findings []domain.Finding
	for _, ingress := range state.Ingresses {
		if ctx.Err() != nil {
			return findings
		}
		if ingress.Metadata.Name == "" {
			continue
		}
		var evidence []domain.Evidence
		if ingress.DefaultBackend != nil && ingress.DefaultBackend.ServiceName != "" {
			evidence = append(evidence, routeEvidence("spec.defaultBackend.service", "", "", *ingress.DefaultBackend))
		}
		for ruleIndex, rule := range ingress.Rules {
			for pathIndex, path := range rule.Paths {
				if path.Backend.ServiceName == "" {
					continue
				}
				field := fmt.Sprintf("spec.rules[index=%d].http.paths[index=%d].backend.service", ruleIndex, pathIndex)
				evidence = append(evidence, routeEvidence(field, rule.Host, path.Path, path.Backend))
			}
		}
		if len(evidence) == 0 {
			continue
		}
		findings = append(findings, domain.Finding{Resource: reference("networking.k8s.io/v1", "Ingress", ingress.Metadata), Evidence: evidence})
	}
	return findings
}

func routeEvidence(field, host, path string, backend domain.IngressBackend) domain.Evidence {
	value := backend.ServiceName + ":" + backend.ServicePort
	return domain.Evidence{
		Field:   field,
		Value:   strings.Join([]string{host, path, value}, "|"),
		Message: fmt.Sprintf("Ingress configures host %q path %q to Service %q; controller fulfillment and external reachability are not verified", host, path, value),
	}
}

func evaluateAPIEndpoint(_ context.Context, state domain.ClusterState) []domain.Finding {
	parsed, err := url.Parse(state.Cluster.Server)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return nil
	}
	name := state.Cluster.Name
	if name == "" {
		name = state.Cluster.Context
	}
	if name == "" {
		return nil
	}
	return []domain.Finding{{
		Resource: domain.ResourceReference{APIVersion: "kubehunt.io/v1alpha1", Kind: "Cluster", Name: name},
		Evidence: []domain.Evidence{{
			Field:   "kubeconfig.clusters[].cluster.server",
			Value:   parsed.Scheme + "://" + parsed.Host,
			Message: fmt.Sprintf("Kubernetes API endpoint uses non-private literal IP %q; source restrictions and reachability are not verified", parsed.Hostname()),
		}},
	}}
}

func nonEmptySorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func reference(apiVersion, kind string, metadata domain.Metadata) domain.ResourceReference {
	return domain.ResourceReference{APIVersion: apiVersion, Kind: kind, Namespace: metadata.Namespace, Name: metadata.Name, UID: metadata.UID}
}
