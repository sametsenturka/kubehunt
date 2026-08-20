package correlate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/graph/model"
	"github.com/sametsenturka/kubehunt/internal/graph/query"
)

var (
	categoryK01 = domain.OWASPCategory{ID: "K01", Version: "2025", Title: "Insecure Workload Configurations"}
	categoryK02 = domain.OWASPCategory{ID: "K02", Version: "2025", Title: "Overly Permissive Authorization Configurations"}
	categoryK03 = domain.OWASPCategory{ID: "K03", Version: "2025", Title: "Secrets Management Failures"}
	categoryK06 = domain.OWASPCategory{ID: "K06", Version: "2025", Title: "Overly Exposed Kubernetes Components"}
)

type Correlator struct{}

func New() *Correlator { return &Correlator{} }

func (correlator *Correlator) Evaluate(ctx context.Context, graph *model.Graph) ([]domain.Finding, error) {
	if correlator == nil {
		return nil, fmt.Errorf("correlate attack paths: correlator is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("correlate attack paths: context is nil")
	}
	if graph == nil {
		return nil, fmt.Errorf("correlate attack paths: graph is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("correlate attack paths: %w", err)
	}

	var findings []domain.Finding
	exposed, err := correlateExposedPrivilegedSecret(ctx, graph)
	if err != nil {
		return findings, err
	}
	findings = append(findings, exposed...)
	podCreate, err := correlatePodCreation(ctx, graph)
	if err != nil {
		return findings, err
	}
	findings = append(findings, podCreate...)
	rbacModify, err := correlateRBACModification(ctx, graph)
	if err != nil {
		return findings, err
	}
	findings = append(findings, rbacModify...)
	return deduplicateAndSort(findings), nil
}

type exposedWorkload struct {
	workload model.Node
	edges    []model.Edge
	support  []domain.Finding
}

func correlateExposedPrivilegedSecret(ctx context.Context, graph *model.Graph) ([]domain.Finding, error) {
	exposed, err := findExposedWorkloads(ctx, graph)
	if err != nil {
		return nil, err
	}
	var result []domain.Finding
	for _, candidate := range exposed {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("correlate exposed privileged Secret path: %w", err)
		}
		privileged := matchingFindings(candidate.workload, []string{"KSCAN-K01-001"}, "K01")
		if len(privileged) == 0 {
			continue
		}
		for _, uses := range edgesOfType(graph.Outgoing(candidate.workload.ID), model.EdgeUses) {
			if !edgeSupported(uses) {
				continue
			}
			serviceAccount, found := graph.Node(uses.To)
			if !found || serviceAccount.Kind != "ServiceAccount" || !observed(serviceAccount) {
				continue
			}
			relationships, err := query.ResourcesForIdentity(graph, serviceAccount.ID)
			if err != nil {
				return result, fmt.Errorf("correlate exposed privileged Secret path for %q: %w", serviceAccount.ID, err)
			}
			for _, relationship := range relationships {
				if !authorizationSupported(relationship) || !allowsSecretRead(relationship, candidate.workload) {
					continue
				}
				rbacFindings := matchingFindings(relationship.Binding, []string{"KSCAN-K02-001", "KSCAN-K02-002", "KSCAN-K02-003"}, "K02")
				if len(rbacFindings) == 0 {
					continue
				}
				edges := appendEdges(candidate.edges, uses, relationship.BoundVia, relationship.References, relationship.Permits)
				support := appendFindings(candidate.support, privileged, rbacFindings)
				result = append(result, correlatedFinding(correlationDefinition{
					id:          "KSCAN-PATH-001",
					title:       "Potentially exposed privileged workload identity can read Secrets",
					description: "An exposure finding and confirmed graph relationships connect a privileged workload to a ServiceAccount with effective Secret read access. This is a configuration attack path, not evidence of workload compromise or Secret use.",
					remediation: "Remove privileged mode, eliminate unnecessary external exposure, and revoke Secret read permissions from the workload ServiceAccount.",
					severity:    domain.SeverityHigh,
					primary:     categoryK02,
					related:     []domain.OWASPCategory{categoryK01, categoryK03, categoryK06},
				}, candidate.workload, graph, edges, support))
			}
		}
	}
	return result, nil
}

func findExposedWorkloads(ctx context.Context, graph *model.Graph) ([]exposedWorkload, error) {
	var result []exposedWorkload
	for _, ingress := range graph.NodesByKind("Ingress") {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("find exposed workloads: %w", err)
		}
		exposure := exposureFindings(ingress)
		if len(exposure) == 0 || !observed(ingress) {
			continue
		}
		for _, route := range edgesOfType(graph.Outgoing(ingress.ID), model.EdgeRoutesTo) {
			if !edgeSupported(route) {
				continue
			}
			service, found := graph.Node(route.To)
			if !found || service.Kind != "Service" || !observed(service) {
				continue
			}
			result = append(result, exposedFromService(graph, service, []model.Edge{route}, exposure)...)
		}
	}
	for _, service := range graph.NodesByKind("Service") {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("find exposed workloads: %w", err)
		}
		exposure := exposureFindings(service)
		if len(exposure) == 0 || !observed(service) {
			continue
		}
		result = append(result, exposedFromService(graph, service, nil, exposure)...)
	}
	sort.SliceStable(result, func(left, right int) bool {
		return exposedWorkloadKey(result[left]) < exposedWorkloadKey(result[right])
	})
	return result, nil
}

func exposedFromService(graph *model.Graph, service model.Node, prefix []model.Edge, support []domain.Finding) []exposedWorkload {
	var result []exposedWorkload
	for _, exposes := range edgesOfType(graph.Outgoing(service.ID), model.EdgeExposes) {
		if !edgeSupported(exposes) {
			continue
		}
		workload, found := graph.Node(exposes.To)
		if !found || !isWorkload(workload) || !observed(workload) {
			continue
		}
		result = append(result, exposedWorkload{workload: workload, edges: appendEdges(prefix, exposes), support: appendFindings(nil, support)})
	}
	return result
}

func correlatePodCreation(ctx context.Context, graph *model.Graph) ([]domain.Finding, error) {
	var result []domain.Finding
	for _, kind := range []string{"Pod", "Deployment", "StatefulSet", "DaemonSet"} {
		for _, workload := range graph.NodesByKind(kind) {
			if err := ctx.Err(); err != nil {
				return result, fmt.Errorf("correlate Pod creation path: %w", err)
			}
			if !observed(workload) || (workload.Kind == "Pod" && representedByController(graph, workload)) {
				continue
			}
			for _, uses := range edgesOfType(graph.Outgoing(workload.ID), model.EdgeUses) {
				if !edgeSupported(uses) {
					continue
				}
				serviceAccount, found := graph.Node(uses.To)
				if !found || serviceAccount.Kind != "ServiceAccount" || !observed(serviceAccount) {
					continue
				}
				relationships, err := query.ResourcesForIdentity(graph, serviceAccount.ID)
				if err != nil {
					return result, fmt.Errorf("correlate Pod creation path for %q: %w", serviceAccount.ID, err)
				}
				for _, relationship := range relationships {
					if !authorizationSupported(relationship) || !allowsPodCreate(relationship, workload) {
						continue
					}
					rbacFindings := matchingFindings(relationship.Binding, []string{"KSCAN-K02-001", "KSCAN-K02-002", "KSCAN-K02-006"}, "K02")
					if len(rbacFindings) == 0 {
						continue
					}
					edges := []model.Edge{uses, relationship.BoundVia, relationship.References, relationship.Permits}
					result = append(result, correlatedFinding(correlationDefinition{
						id:          "KSCAN-PATH-002",
						title:       "Workload identity has a privileged workload creation opportunity",
						description: "A workload uses a ServiceAccount with effective, unconstrained Pod creation permission. The identity could request a privileged Pod, but this result does not assert that admission policy would allow it or that the permission has been used.",
						remediation: "Remove Pod creation permission from the workload ServiceAccount or constrain the namespace with reviewed admission policies and a narrowly scoped workload role.",
						severity:    domain.SeverityHigh,
						primary:     categoryK02,
						related:     []domain.OWASPCategory{categoryK01},
					}, workload, graph, edges, rbacFindings))
				}
			}
		}
	}
	return result, nil
}

func correlateRBACModification(ctx context.Context, graph *model.Graph) ([]domain.Finding, error) {
	var result []domain.Finding
	for _, serviceAccount := range graph.NodesByKind("ServiceAccount") {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("correlate RBAC modification path: %w", err)
		}
		if !observed(serviceAccount) {
			continue
		}
		relationships, err := query.ResourcesForIdentity(graph, serviceAccount.ID)
		if err != nil {
			return result, fmt.Errorf("correlate RBAC modification path for %q: %w", serviceAccount.ID, err)
		}
		for _, relationship := range relationships {
			if !authorizationSupported(relationship) || !allowsRBACBindingModification(relationship, serviceAccount) {
				continue
			}
			rbacFindings := matchingFindings(relationship.Binding, []string{"KSCAN-K02-001", "KSCAN-K02-002", "KSCAN-K02-011"}, "K02")
			if len(rbacFindings) == 0 {
				continue
			}
			edges := []model.Edge{relationship.BoundVia, relationship.References, relationship.Permits}
			result = append(result, correlatedFinding(correlationDefinition{
				id:          "KSCAN-PATH-003",
				title:       "ServiceAccount can modify RBAC bindings",
				description: "A ServiceAccount has effective update or patch permission on RoleBindings or ClusterRoleBindings. This creates a privilege-escalation opportunity, but Kubernetes bind/escalation enforcement and the privilege of any target binding are not assumed.",
				remediation: "Remove RBAC binding update and patch permissions from workload ServiceAccounts and reserve binding administration for a tightly controlled identity.",
				severity:    domain.SeverityHigh,
				primary:     categoryK02,
			}, serviceAccount, graph, edges, rbacFindings))
		}
	}
	return result, nil
}

func authorizationSupported(relationship query.AuthorizationRelationship) bool {
	return edgeSupported(relationship.BoundVia) && edgeSupported(relationship.References) && edgeSupported(relationship.Permits)
}

func allowsSecretRead(relationship query.AuthorizationRelationship, workload model.Node) bool {
	return matchesAPIGroup(relationship.Resource.Attributes["api_group"], "") &&
		matchesResource(relationship.Resource.Attributes["resource"], "secrets") &&
		hasAnyVerb(relationship.Permits.Attributes["verbs"], "get", "list", "watch") &&
		scopeCovers(relationship.Permits, namespaceOf(workload))
}

func allowsPodCreate(relationship query.AuthorizationRelationship, workload model.Node) bool {
	return matchesAPIGroup(relationship.Resource.Attributes["api_group"], "") &&
		matchesResource(relationship.Resource.Attributes["resource"], "pods") &&
		hasAnyVerb(relationship.Permits.Attributes["verbs"], "create") &&
		relationship.Permits.Attributes["resource_names"] == "" &&
		scopeCovers(relationship.Permits, namespaceOf(workload))
}

func allowsRBACBindingModification(relationship query.AuthorizationRelationship, serviceAccount model.Node) bool {
	if !matchesAPIGroup(relationship.Resource.Attributes["api_group"], "rbac.authorization.k8s.io") ||
		!hasAnyVerb(relationship.Permits.Attributes["verbs"], "update", "patch") {
		return false
	}
	resource := relationship.Resource.Attributes["resource"]
	if resource != "*" && resource != "rolebindings" && resource != "clusterrolebindings" {
		return false
	}
	if resource == "clusterrolebindings" && relationship.Permits.Attributes["scope"] != "cluster" {
		return false
	}
	return scopeCovers(relationship.Permits, namespaceOf(serviceAccount))
}

func edgeSupported(edge model.Edge) bool {
	if edge.Confidence != model.ConfidenceConfirmed || len(edge.Evidence) == 0 {
		return false
	}
	for _, evidence := range edge.Evidence {
		if evidence.Field == "" || evidence.Message == "" {
			return false
		}
	}
	return true
}

func scopeCovers(permit model.Edge, namespace string) bool {
	switch permit.Attributes["scope"] {
	case "cluster":
		return true
	case "namespace":
		return namespace != "" && permit.Attributes["namespace"] == namespace
	default:
		return false
	}
}

func matchesAPIGroup(configured, wanted string) bool {
	return configured == "*" || configured == wanted
}

func matchesResource(configured, wanted string) bool {
	return configured == "*" || configured == wanted
}

func hasAnyVerb(configured string, wanted ...string) bool {
	verbs := splitCSV(configured)
	if _, found := verbs["*"]; found {
		return true
	}
	for _, verb := range wanted {
		if _, found := verbs[verb]; found {
			return true
		}
	}
	return false
}

func splitCSV(value string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result[item] = struct{}{}
		}
	}
	return result
}

func exposureFindings(node model.Node) []domain.Finding {
	var result []domain.Finding
	for _, finding := range node.Findings {
		if strings.HasPrefix(finding.RuleID, "KSCAN-K06-") && finding.PrimaryOWASP.ID == "K06" && validSupportingFinding(finding) {
			result = append(result, finding)
		}
	}
	sortRawFindings(result)
	return result
}

func matchingFindings(node model.Node, ruleIDs []string, category string) []domain.Finding {
	allowed := make(map[string]struct{}, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		allowed[ruleID] = struct{}{}
	}
	var result []domain.Finding
	for _, finding := range node.Findings {
		if _, found := allowed[finding.RuleID]; !found || finding.PrimaryOWASP.ID != category || !validSupportingFinding(finding) {
			continue
		}
		result = append(result, finding)
	}
	sortRawFindings(result)
	return result
}

func validSupportingFinding(finding domain.Finding) bool {
	if finding.RuleID == "" || finding.Resource.Kind == "" || finding.Resource.Name == "" || len(finding.Evidence) == 0 {
		return false
	}
	for _, evidence := range finding.Evidence {
		if evidence.Field == "" || evidence.Message == "" {
			return false
		}
	}
	return true
}

type correlationDefinition struct {
	id          string
	title       string
	description string
	remediation string
	severity    domain.Severity
	primary     domain.OWASPCategory
	related     []domain.OWASPCategory
}

func correlatedFinding(definition correlationDefinition, subject model.Node, graph *model.Graph, edges []model.Edge, support []domain.Finding) domain.Finding {
	path := make([]domain.AttackPathStep, 0, len(edges))
	var evidence []domain.Evidence
	for _, edge := range edges {
		from, _ := graph.Node(edge.From)
		to, _ := graph.Node(edge.To)
		stepEvidence := append([]domain.Evidence(nil), edge.Evidence...)
		path = append(path, domain.AttackPathStep{
			EdgeID: string(edge.ID), From: attackPathNode(from), Relationship: string(edge.Type), To: attackPathNode(to), Confidence: string(edge.Confidence), Evidence: stepEvidence,
		})
		evidence = append(evidence, stepEvidence...)
	}
	supporting := make([]domain.SupportingFinding, 0, len(support))
	for _, finding := range support {
		supporting = append(supporting, domain.SupportingFinding{
			Fingerprint: finding.Fingerprint, RuleID: finding.RuleID, Title: finding.Title, Severity: finding.Severity,
			Resource: finding.Resource, Evidence: append([]domain.Evidence(nil), finding.Evidence...), PrimaryOWASP: finding.PrimaryOWASP,
		})
		evidence = append(evidence, finding.Evidence...)
	}
	sort.SliceStable(supporting, func(left, right int) bool {
		return supportingFindingKey(supporting[left]) < supportingFindingKey(supporting[right])
	})
	resource := domain.ResourceReference{}
	if subject.Ref != nil {
		resource = *subject.Ref
	}
	finding := domain.Finding{
		RuleID: definition.id, Title: definition.title, Severity: definition.severity, Resource: resource, Namespace: resource.Namespace,
		Evidence: evidence, Description: definition.description, Remediation: definition.remediation,
		PrimaryOWASP: definition.primary, RelatedOWASP: append([]domain.OWASPCategory(nil), definition.related...),
		AttackPath: path, AffectedResources: affectedResources(path), SupportingFindings: supporting,
	}
	finding.Fingerprint = correlationFingerprint(finding)
	return finding
}

func attackPathNode(node model.Node) domain.AttackPathNode {
	result := domain.AttackPathNode{ID: string(node.ID), Type: string(node.Type), Kind: node.Kind, Attributes: cloneAttributes(node.Attributes)}
	if node.Ref != nil {
		resource := *node.Ref
		result.Resource = &resource
	}
	return result
}

func affectedResources(path []domain.AttackPathStep) []domain.ResourceReference {
	var result []domain.ResourceReference
	seen := make(map[string]struct{})
	appendNode := func(node domain.AttackPathNode) {
		if node.Resource == nil {
			return
		}
		key := resourceKey(*node.Resource)
		if _, found := seen[key]; found {
			return
		}
		seen[key] = struct{}{}
		result = append(result, *node.Resource)
	}
	for _, step := range path {
		appendNode(step.From)
		appendNode(step.To)
	}
	return result
}

func correlationFingerprint(finding domain.Finding) string {
	parts := []string{"attack-path-v1", finding.RuleID, resourceKey(finding.Resource)}
	for _, step := range finding.AttackPath {
		parts = append(parts, step.EdgeID)
	}
	for _, supporting := range finding.SupportingFindings {
		key := supporting.Fingerprint
		if key == "" {
			key = supporting.RuleID + "\x00" + resourceKey(supporting.Resource)
		}
		parts = append(parts, key)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", sum[:16])
}

func deduplicateAndSort(findings []domain.Finding) []domain.Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if _, found := seen[finding.Fingerprint]; found {
			continue
		}
		seen[finding.Fingerprint] = struct{}{}
		result = append(result, finding)
	}
	sort.SliceStable(result, func(left, right int) bool {
		if result[left].Severity.Rank() != result[right].Severity.Rank() {
			return result[left].Severity.Rank() > result[right].Severity.Rank()
		}
		return result[left].RuleID+"\x00"+resourceKey(result[left].Resource)+"\x00"+result[left].Fingerprint < result[right].RuleID+"\x00"+resourceKey(result[right].Resource)+"\x00"+result[right].Fingerprint
	})
	return result
}

func edgesOfType(edges []model.Edge, edgeType model.EdgeType) []model.Edge {
	var result []model.Edge
	for _, edge := range edges {
		if edge.Type == edgeType {
			result = append(result, edge)
		}
	}
	return result
}

func appendEdges(existing []model.Edge, candidates ...model.Edge) []model.Edge {
	result := append([]model.Edge(nil), existing...)
	return append(result, candidates...)
}

func appendFindings(existing []domain.Finding, groups ...[]domain.Finding) []domain.Finding {
	result := append([]domain.Finding(nil), existing...)
	seen := make(map[string]struct{}, len(result))
	for _, finding := range result {
		seen[rawFindingKey(finding)] = struct{}{}
	}
	for _, group := range groups {
		for _, finding := range group {
			key := rawFindingKey(finding)
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, finding)
		}
	}
	sortRawFindings(result)
	return result
}

func sortRawFindings(findings []domain.Finding) {
	sort.SliceStable(findings, func(left, right int) bool { return rawFindingKey(findings[left]) < rawFindingKey(findings[right]) })
}

func rawFindingKey(finding domain.Finding) string {
	if finding.Fingerprint != "" {
		return finding.Fingerprint
	}
	return finding.RuleID + "\x00" + resourceKey(finding.Resource)
}

func supportingFindingKey(finding domain.SupportingFinding) string {
	if finding.Fingerprint != "" {
		return finding.Fingerprint
	}
	return finding.RuleID + "\x00" + resourceKey(finding.Resource)
}

func namespaceOf(node model.Node) string {
	if node.Ref == nil {
		return ""
	}
	return node.Ref.Namespace
}

func observed(node model.Node) bool { return node.Attributes["observed"] == "true" }

func isWorkload(node model.Node) bool {
	switch node.Kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet":
		return true
	default:
		return false
	}
}

func representedByController(graph *model.Graph, pod model.Node) bool {
	for _, edge := range edgesOfType(graph.Incoming(pod.ID), model.EdgeCreates) {
		controller, found := graph.Node(edge.From)
		if found && observed(controller) && controller.Kind != "Pod" {
			return true
		}
	}
	return false
}

func resourceKey(resource domain.ResourceReference) string {
	return strings.Join([]string{resource.APIVersion, resource.Kind, resource.Namespace, resource.Name}, "\x00")
}

func cloneAttributes(attributes map[string]string) map[string]string {
	if attributes == nil {
		return nil
	}
	result := make(map[string]string, len(attributes))
	for key, value := range attributes {
		result[key] = value
	}
	return result
}

func exposedWorkloadKey(workload exposedWorkload) string {
	parts := []string{string(workload.workload.ID)}
	for _, edge := range workload.edges {
		parts = append(parts, string(edge.ID))
	}
	return strings.Join(parts, "\x00")
}
