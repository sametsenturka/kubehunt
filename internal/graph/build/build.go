package build

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/graph/model"
	"github.com/sametsenturka/kubehunt/internal/rbac"
)

type Builder struct{}

func (Builder) Build(state domain.ClusterState, findings []domain.Finding) (*model.Graph, error) {
	return Build(state, findings)
}

func Build(state domain.ClusterState, findings []domain.Finding) (*model.Graph, error) {
	graph := model.New()
	clusterKey := model.ClusterKey(state.Cluster)
	if err := addInventoryNodes(graph, clusterKey, state); err != nil {
		return nil, fmt.Errorf("build graph inventory: %w", err)
	}
	if err := addOwnershipEdges(graph, clusterKey, state); err != nil {
		return nil, fmt.Errorf("build graph ownership: %w", err)
	}
	if err := addServiceAccountEdges(graph, clusterKey, state); err != nil {
		return nil, fmt.Errorf("build graph service accounts: %w", err)
	}
	if err := addRBACEdges(graph, clusterKey, rbac.Build(state)); err != nil {
		return nil, fmt.Errorf("build graph RBAC: %w", err)
	}
	if err := addServiceEdges(graph, clusterKey, state); err != nil {
		return nil, fmt.Errorf("build graph services: %w", err)
	}
	if err := addIngressEdges(graph, clusterKey, state); err != nil {
		return nil, fmt.Errorf("build graph ingresses: %w", err)
	}
	if err := addNetworkPolicyEdges(graph, clusterKey, state); err != nil {
		return nil, fmt.Errorf("build graph network policies: %w", err)
	}
	if err := attachFindings(graph, clusterKey, findings); err != nil {
		return nil, fmt.Errorf("build graph findings: %w", err)
	}
	return graph, nil
}

func addInventoryNodes(graph *model.Graph, clusterKey string, state domain.ClusterState) error {
	for _, item := range state.Namespaces {
		if err := addResourceNode(graph, clusterKey, "v1", "Namespace", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.Pods {
		if err := addResourceNode(graph, clusterKey, "v1", "Pod", item.Metadata, map[string]string{"phase": item.Phase}); err != nil {
			return err
		}
	}
	for _, item := range state.Deployments {
		if err := addResourceNode(graph, clusterKey, "apps/v1", "Deployment", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.StatefulSets {
		if err := addResourceNode(graph, clusterKey, "apps/v1", "StatefulSet", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.DaemonSets {
		if err := addResourceNode(graph, clusterKey, "apps/v1", "DaemonSet", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.Services {
		if err := addResourceNode(graph, clusterKey, "v1", "Service", item.Metadata, map[string]string{"service_type": item.Type}); err != nil {
			return err
		}
	}
	for _, item := range state.Ingresses {
		if err := addResourceNode(graph, clusterKey, "networking.k8s.io/v1", "Ingress", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.ServiceAccounts {
		if err := addResourceNode(graph, clusterKey, "v1", "ServiceAccount", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.Roles {
		if err := addResourceNode(graph, clusterKey, "rbac.authorization.k8s.io/v1", "Role", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.ClusterRoles {
		if err := addResourceNode(graph, clusterKey, "rbac.authorization.k8s.io/v1", "ClusterRole", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.RoleBindings {
		if err := addResourceNode(graph, clusterKey, "rbac.authorization.k8s.io/v1", "RoleBinding", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.ClusterRoleBindings {
		if err := addResourceNode(graph, clusterKey, "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", item.Metadata, nil); err != nil {
			return err
		}
	}
	for _, item := range state.NetworkPolicies {
		if err := addResourceNode(graph, clusterKey, "networking.k8s.io/v1", "NetworkPolicy", item.Metadata, nil); err != nil {
			return err
		}
	}
	return nil
}

func addOwnershipEdges(graph *model.Graph, clusterKey string, state domain.ClusterState) error {
	for _, pod := range state.Pods {
		podRef := resourceReference("v1", "Pod", pod.Metadata)
		podID := model.ResourceNodeID(clusterKey, podRef)
		for _, owner := range pod.Metadata.Owners {
			if !owner.Controller {
				continue
			}
			switch owner.Kind {
			case "Deployment", "StatefulSet", "DaemonSet":
				ownerRef := domain.ResourceReference{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: pod.Metadata.Namespace, Name: owner.Name, UID: owner.UID}
				if _, found := graph.NodeForResource(ownerRef); !found {
					continue
				}
				discriminator := owner.Kind + "\x00" + owner.Name
				evidence := domain.Evidence{Field: "metadata.ownerReferences", Value: owner.Kind + "/" + owner.Name, Message: fmt.Sprintf("Pod %q has controller owner %s/%s", pod.Metadata.Name, owner.Kind, owner.Name)}
				if err := addEdge(graph, model.ResourceNodeID(clusterKey, ownerRef), podID, model.EdgeCreates, model.ConfidenceConfirmed, discriminator, nil, evidence); err != nil {
					return err
				}
			case "ReplicaSet":
				for _, deployment := range state.Deployments {
					if deployment.Metadata.Namespace != pod.Metadata.Namespace || !selectorMatches(deployment.Selector, pod.Metadata.Labels) {
						continue
					}
					ref := resourceReference("apps/v1", "Deployment", deployment.Metadata)
					attributes := map[string]string{"via_owner_kind": "ReplicaSet", "via_owner_name": owner.Name}
					evidence := domain.Evidence{Field: "metadata.ownerReferences+spec.selector", Value: owner.Kind + "/" + owner.Name, Message: fmt.Sprintf("Pod %q is owned by ReplicaSet %q and matches Deployment %q selector", pod.Metadata.Name, owner.Name, deployment.Metadata.Name)}
					if err := addEdge(graph, model.ResourceNodeID(clusterKey, ref), podID, model.EdgeCreates, model.ConfidenceInferred, owner.Kind+"\x00"+owner.Name, attributes, evidence); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func addServiceAccountEdges(graph *model.Graph, clusterKey string, state domain.ClusterState) error {
	for _, pod := range state.Pods {
		ref := resourceReference("v1", "Pod", pod.Metadata)
		if err := addUsesServiceAccount(graph, clusterKey, ref, pod.Spec, "pod"); err != nil {
			return err
		}
	}
	for _, workload := range state.Deployments {
		if err := addUsesServiceAccount(graph, clusterKey, resourceReference("apps/v1", "Deployment", workload.Metadata), workload.Template.Spec, "template"); err != nil {
			return err
		}
	}
	for _, workload := range state.StatefulSets {
		if err := addUsesServiceAccount(graph, clusterKey, resourceReference("apps/v1", "StatefulSet", workload.Metadata), workload.Template.Spec, "template"); err != nil {
			return err
		}
	}
	for _, workload := range state.DaemonSets {
		if err := addUsesServiceAccount(graph, clusterKey, resourceReference("apps/v1", "DaemonSet", workload.Metadata), workload.Template.Spec, "template"); err != nil {
			return err
		}
	}
	return nil
}

func addUsesServiceAccount(graph *model.Graph, clusterKey string, source domain.ResourceReference, spec domain.PodSpec, sourceType string) error {
	name := spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	target := domain.ResourceReference{APIVersion: "v1", Kind: "ServiceAccount", Namespace: source.Namespace, Name: name}
	if err := ensureResourceNode(graph, clusterKey, target); err != nil {
		return err
	}
	field := "spec.serviceAccountName"
	if sourceType == "template" {
		field = "spec.template.spec.serviceAccountName"
	}
	value := spec.ServiceAccountName
	if value == "" {
		value = "<default>"
	}
	evidence := domain.Evidence{Field: field, Value: value, Message: fmt.Sprintf("%s/%s uses ServiceAccount %q", source.Kind, source.Name, name)}
	return addEdge(graph, model.ResourceNodeID(clusterKey, source), model.ResourceNodeID(clusterKey, target), model.EdgeUses, model.ConfidenceConfirmed, sourceType, map[string]string{"source": sourceType}, evidence)
}

func addRBACEdges(graph *model.Graph, clusterKey string, effective rbac.Model) error {
	for _, assignment := range effective.Assignments {
		subjectID, err := ensureSubjectNode(graph, clusterKey, assignment)
		if err != nil {
			return err
		}
		if err := ensureResourceNode(graph, clusterKey, assignment.Binding); err != nil {
			return err
		}
		if err := ensureResourceNode(graph, clusterKey, assignment.Role); err != nil {
			return err
		}
		confidence := model.ConfidenceConfirmed
		if !assignment.SubjectValid {
			confidence = model.ConfidenceUnknown
		}
		bindingID := model.ResourceNodeID(clusterKey, assignment.Binding)
		roleID := model.ResourceNodeID(clusterKey, assignment.Role)
		subjectValue := strings.Join([]string{assignment.Subject.APIGroup, assignment.Subject.Kind, assignment.Subject.Namespace, assignment.Subject.Name}, "/")
		boundEvidence := domain.Evidence{Field: "subjects", Value: subjectValue, Message: fmt.Sprintf("%s/%s contains subject %s %q", assignment.Binding.Kind, assignment.Binding.Name, assignment.Subject.Kind, assignment.Subject.DisplayName())}
		if err := addEdge(graph, subjectID, bindingID, model.EdgeBoundVia, confidence, "", map[string]string{"subject_valid": fmt.Sprint(assignment.SubjectValid)}, boundEvidence); err != nil {
			return err
		}
		confidence = model.ConfidenceConfirmed
		if !assignment.RoleResolved {
			confidence = model.ConfidenceUnknown
		}
		referenceEvidence := domain.Evidence{Field: "roleRef", Value: assignment.Role.Kind + "/" + assignment.Role.Name, Message: fmt.Sprintf("%s/%s references %s/%s", assignment.Binding.Kind, assignment.Binding.Name, assignment.Role.Kind, assignment.Role.Name)}
		if err := addEdge(graph, bindingID, roleID, model.EdgeReferences, confidence, "", map[string]string{"role_resolved": fmt.Sprint(assignment.RoleResolved)}, referenceEvidence); err != nil {
			return err
		}
		if !assignment.SubjectValid || !assignment.RoleResolved {
			continue
		}
		for _, permission := range assignment.Permissions {
			if err := addPermissionEdges(graph, clusterKey, assignment, permission, roleID, bindingID); err != nil {
				return err
			}
		}
	}
	return nil
}

func addPermissionEdges(graph *model.Graph, clusterKey string, assignment rbac.Assignment, permission rbac.Permission, roleID, bindingID model.NodeID) error {
	scope := string(assignment.Scope)
	namespace := ""
	if assignment.Scope == rbac.ScopeNamespace {
		namespace = assignment.Namespace
	}
	for _, apiGroup := range permission.APIGroups {
		for _, resource := range permission.Resources {
			if assignment.Scope == rbac.ScopeNamespace && knownClusterScopedResource(apiGroup, resource) {
				continue
			}
			targetID := model.APIResourceNodeID(clusterKey, apiGroup, resource, scope, namespace, permission.ResourceNames)
			if err := graph.AddNode(model.Node{
				ID:   targetID,
				Type: model.NodeTypeAPIResource,
				Kind: "APIResource",
				Attributes: map[string]string{
					"api_group":      apiGroup,
					"resource":       resource,
					"scope":          scope,
					"namespace":      namespace,
					"resource_names": canonicalStrings(permission.ResourceNames),
				},
			}); err != nil {
				return err
			}
			attributes := map[string]string{
				"verbs":          canonicalStrings(permission.Verbs),
				"resource_names": canonicalStrings(permission.ResourceNames),
				"scope":          scope,
				"namespace":      namespace,
				"binding_id":     string(bindingID),
				"sources":        permissionSources(permission.Sources),
			}
			discriminator := strings.Join([]string{string(bindingID), permission.Canonical(), apiGroup, resource}, "\x00")
			evidence := domain.Evidence{Field: "rules", Value: permission.Canonical(), Message: fmt.Sprintf("%s/%s permits verbs %q on %s/%s through %s/%s", assignment.Role.Kind, assignment.Role.Name, canonicalStrings(permission.Verbs), apiGroup, resource, assignment.Binding.Kind, assignment.Binding.Name)}
			if err := addEdge(graph, roleID, targetID, model.EdgePermits, model.ConfidenceConfirmed, discriminator, attributes, evidence); err != nil {
				return err
			}
		}
	}
	if assignment.Scope != rbac.ScopeCluster {
		return nil
	}
	for _, resourceURL := range permission.NonResourceURLs {
		targetID := model.APIResourceNodeID(clusterKey, "", resourceURL, string(rbac.ScopeCluster), "", nil)
		if err := graph.AddNode(model.Node{ID: targetID, Type: model.NodeTypeAPIResource, Kind: "NonResourceURL", Attributes: map[string]string{"url": resourceURL, "scope": string(rbac.ScopeCluster)}}); err != nil {
			return err
		}
		attributes := map[string]string{"verbs": canonicalStrings(permission.Verbs), "binding_id": string(bindingID), "scope": string(rbac.ScopeCluster), "sources": permissionSources(permission.Sources)}
		discriminator := strings.Join([]string{string(bindingID), permission.Canonical(), resourceURL}, "\x00")
		evidence := domain.Evidence{Field: "rules", Value: permission.Canonical(), Message: fmt.Sprintf("%s/%s permits verbs %q on non-resource URL %q through %s/%s", assignment.Role.Kind, assignment.Role.Name, canonicalStrings(permission.Verbs), resourceURL, assignment.Binding.Kind, assignment.Binding.Name)}
		if err := addEdge(graph, roleID, targetID, model.EdgePermits, model.ConfidenceConfirmed, discriminator, attributes, evidence); err != nil {
			return err
		}
	}
	return nil
}

func addServiceEdges(graph *model.Graph, clusterKey string, state domain.ClusterState) error {
	for _, service := range state.Services {
		if len(service.Selector) == 0 {
			continue
		}
		serviceID := model.ResourceNodeID(clusterKey, resourceReference("v1", "Service", service.Metadata))
		for _, pod := range state.Pods {
			if pod.Metadata.Namespace == service.Metadata.Namespace && labelsMatch(service.Selector, pod.Metadata.Labels) {
				ref := resourceReference("v1", "Pod", pod.Metadata)
				evidence := domain.Evidence{Field: "spec.selector", Value: canonicalLabels(service.Selector), Message: fmt.Sprintf("Service %q selector matches observed Pod %q", service.Metadata.Name, pod.Metadata.Name)}
				if err := addEdge(graph, serviceID, model.ResourceNodeID(clusterKey, ref), model.EdgeExposes, model.ConfidenceConfirmed, "pod", map[string]string{"selection": "observed_pod"}, evidence); err != nil {
					return err
				}
			}
		}
		for _, target := range workloadTargets(state) {
			if target.ref.Namespace == service.Metadata.Namespace && labelsMatch(service.Selector, target.labels) {
				evidence := domain.Evidence{Field: "spec.selector+spec.template.metadata.labels", Value: canonicalLabels(service.Selector), Message: fmt.Sprintf("Service %q selector matches %s/%s template labels", service.Metadata.Name, target.ref.Kind, target.ref.Name)}
				if err := addEdge(graph, serviceID, model.ResourceNodeID(clusterKey, target.ref), model.EdgeExposes, model.ConfidenceInferred, "template", map[string]string{"selection": "workload_template"}, evidence); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func addIngressEdges(graph *model.Graph, clusterKey string, state domain.ClusterState) error {
	for _, ingress := range state.Ingresses {
		from := model.ResourceNodeID(clusterKey, resourceReference("networking.k8s.io/v1", "Ingress", ingress.Metadata))
		if ingress.DefaultBackend != nil && ingress.DefaultBackend.ServiceName != "" {
			if err := addIngressServiceEdge(graph, clusterKey, from, ingress.Metadata.Namespace, "", "", *ingress.DefaultBackend); err != nil {
				return err
			}
		}
		for _, rule := range ingress.Rules {
			for _, ingressPath := range rule.Paths {
				if ingressPath.Backend.ServiceName == "" {
					continue
				}
				if err := addIngressServiceEdge(graph, clusterKey, from, ingress.Metadata.Namespace, rule.Host, ingressPath.Path, ingressPath.Backend); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func addIngressServiceEdge(graph *model.Graph, clusterKey string, from model.NodeID, namespace, host, path string, backend domain.IngressBackend) error {
	target := domain.ResourceReference{APIVersion: "v1", Kind: "Service", Namespace: namespace, Name: backend.ServiceName}
	if err := ensureResourceNode(graph, clusterKey, target); err != nil {
		return err
	}
	attributes := map[string]string{"host": host, "path": path, "service_port": backend.ServicePort}
	discriminator := strings.Join([]string{host, path, backend.ServiceName, backend.ServicePort}, "\x00")
	field := "spec.defaultBackend.service"
	if host != "" || path != "" {
		field = "spec.rules.http.paths.backend.service"
	}
	evidence := domain.Evidence{Field: field, Value: backend.ServiceName + ":" + backend.ServicePort, Message: fmt.Sprintf("Ingress backend routes host %q path %q to Service %q", host, path, backend.ServiceName)}
	return addEdge(graph, from, model.ResourceNodeID(clusterKey, target), model.EdgeRoutesTo, model.ConfidenceConfirmed, discriminator, attributes, evidence)
}

func addNetworkPolicyEdges(graph *model.Graph, clusterKey string, state domain.ClusterState) error {
	for _, policy := range state.NetworkPolicies {
		from := model.ResourceNodeID(clusterKey, resourceReference("networking.k8s.io/v1", "NetworkPolicy", policy.Metadata))
		for _, pod := range state.Pods {
			if pod.Metadata.Namespace != policy.Metadata.Namespace || !selectorMatches(policy.PodSelector, pod.Metadata.Labels) {
				continue
			}
			to := model.ResourceNodeID(clusterKey, resourceReference("v1", "Pod", pod.Metadata))
			evidence := domain.Evidence{Field: "spec.podSelector", Value: canonicalLabelSelector(policy.PodSelector), Message: fmt.Sprintf("NetworkPolicy %q podSelector matches Pod %q", policy.Metadata.Name, pod.Metadata.Name)}
			if err := addEdge(graph, from, to, model.EdgeSelects, model.ConfidenceConfirmed, "", map[string]string{"policy_types": canonicalStrings(policy.PolicyTypes)}, evidence); err != nil {
				return err
			}
		}
	}
	return nil
}

func attachFindings(graph *model.Graph, clusterKey string, findings []domain.Finding) error {
	for _, finding := range findings {
		if err := ensureResourceNode(graph, clusterKey, finding.Resource); err != nil {
			return err
		}
		if err := graph.AttachFindingToNode(model.ResourceNodeID(clusterKey, finding.Resource), finding); err != nil {
			return err
		}
	}
	return nil
}

func addResourceNode(graph *model.Graph, clusterKey, apiVersion, kind string, metadata domain.Metadata, attributes map[string]string) error {
	ref := resourceReference(apiVersion, kind, metadata)
	values := map[string]string{"observed": "true"}
	for key, value := range attributes {
		values[key] = value
	}
	return graph.AddNode(model.Node{ID: model.ResourceNodeID(clusterKey, ref), Type: model.NodeTypeResource, Kind: kind, Ref: &ref, Attributes: values})
}

func ensureResourceNode(graph *model.Graph, clusterKey string, ref domain.ResourceReference) error {
	if _, found := graph.NodeForResource(ref); found {
		return nil
	}
	return graph.AddNode(model.Node{ID: model.ResourceNodeID(clusterKey, ref), Type: model.NodeTypeResource, Kind: ref.Kind, Ref: &ref, Attributes: map[string]string{"observed": "false"}})
}

func ensureSubjectNode(graph *model.Graph, clusterKey string, assignment rbac.Assignment) (model.NodeID, error) {
	subject := assignment.Subject
	if subject.Kind == "ServiceAccount" {
		ref := domain.ResourceReference{APIVersion: "v1", Kind: "ServiceAccount", Namespace: subject.Namespace, Name: subject.Name}
		if err := ensureResourceNode(graph, clusterKey, ref); err != nil {
			return "", err
		}
		return model.ResourceNodeID(clusterKey, ref), nil
	}
	id := model.SubjectNodeID(clusterKey, subject.APIGroup, subject.Kind, subject.Namespace, subject.Name)
	err := graph.AddNode(model.Node{ID: id, Type: model.NodeTypeIdentity, Kind: subject.Kind, Attributes: map[string]string{
		"api_group": subject.APIGroup,
		"kind":      subject.Kind,
		"namespace": subject.Namespace,
		"name":      subject.Name,
		"valid":     fmt.Sprint(assignment.SubjectValid),
	}})
	return id, err
}

func addEdge(graph *model.Graph, from, to model.NodeID, edgeType model.EdgeType, confidence model.Confidence, discriminator string, attributes map[string]string, evidence ...domain.Evidence) error {
	return graph.AddEdge(model.Edge{ID: model.StableEdgeID(from, edgeType, to, discriminator), From: from, To: to, Type: edgeType, Confidence: confidence, Attributes: attributes, Evidence: evidence})
}

func resourceReference(apiVersion, kind string, metadata domain.Metadata) domain.ResourceReference {
	return domain.ResourceReference{APIVersion: apiVersion, Kind: kind, Namespace: metadata.Namespace, Name: metadata.Name, UID: metadata.UID}
}

type workloadTarget struct {
	ref    domain.ResourceReference
	labels map[string]string
}

func workloadTargets(state domain.ClusterState) []workloadTarget {
	result := make([]workloadTarget, 0, len(state.Deployments)+len(state.StatefulSets)+len(state.DaemonSets))
	for _, workload := range state.Deployments {
		result = append(result, workloadTarget{ref: resourceReference("apps/v1", "Deployment", workload.Metadata), labels: workload.Template.Labels})
	}
	for _, workload := range state.StatefulSets {
		result = append(result, workloadTarget{ref: resourceReference("apps/v1", "StatefulSet", workload.Metadata), labels: workload.Template.Labels})
	}
	for _, workload := range state.DaemonSets {
		result = append(result, workloadTarget{ref: resourceReference("apps/v1", "DaemonSet", workload.Metadata), labels: workload.Template.Labels})
	}
	return result
}

func selectorMatches(selector domain.LabelSelector, labels map[string]string) bool {
	if !labelsMatch(selector.MatchLabels, labels) {
		return false
	}
	for _, expression := range selector.MatchExpressions {
		value, exists := labels[expression.Key]
		switch expression.Operator {
		case "In":
			if !exists || !contains(expression.Values, value) {
				return false
			}
		case "NotIn":
			if !exists || contains(expression.Values, value) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func labelsMatch(selector, labels map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func canonicalStrings(values []string) string {
	copied := append([]string(nil), values...)
	sort.Strings(copied)
	unique := copied[:0]
	for _, value := range copied {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return strings.Join(unique, ",")
}

func canonicalLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+labels[key])
	}
	return strings.Join(values, ",")
}

func canonicalLabelSelector(selector domain.LabelSelector) string {
	values := []string{canonicalLabels(selector.MatchLabels)}
	for _, expression := range selector.MatchExpressions {
		values = append(values, expression.Key+":"+expression.Operator+":"+canonicalStrings(expression.Values))
	}
	sort.Strings(values)
	return strings.Join(values, ";")
}

func permissionSources(sources []rbac.PermissionSource) string {
	values := make([]string, 0, len(sources))
	for _, source := range sources {
		values = append(values, fmt.Sprintf("%s/%s/%s#%d", source.Role.Kind, source.Role.Namespace, source.Role.Name, source.RuleIndex))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func knownClusterScopedResource(apiGroup, resource string) bool {
	if resource == "*" || strings.Contains(resource, "/") {
		return false
	}
	key := apiGroup + "/" + resource
	_, found := clusterScopedResources[key]
	return found
}

var clusterScopedResources = map[string]struct{}{
	"/namespaces": {}, "/nodes": {}, "/persistentvolumes": {},
	"rbac.authorization.k8s.io/clusterroles": {}, "rbac.authorization.k8s.io/clusterrolebindings": {},
	"apiextensions.k8s.io/customresourcedefinitions": {},
	"storage.k8s.io/storageclasses":                  {}, "storage.k8s.io/csidrivers": {}, "storage.k8s.io/csinodes": {}, "storage.k8s.io/volumeattachments": {},
	"admissionregistration.k8s.io/mutatingwebhookconfigurations": {}, "admissionregistration.k8s.io/validatingwebhookconfigurations": {},
}
