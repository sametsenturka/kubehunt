package correlate

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/sametsenturka/kubehunt/internal/domain"
	graphbuild "github.com/sametsenturka/kubehunt/internal/graph/build"
	"github.com/sametsenturka/kubehunt/internal/graph/model"
	"github.com/sametsenturka/kubehunt/internal/kube/collectors"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k02"
	rulesengine "github.com/sametsenturka/kubehunt/internal/rules/engine"
)

func TestCorrelatorConsumesCollectorAndRuleEngineEvidence(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "production"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "production"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}},
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "worker"}}, Spec: corev1.PodSpec{
					ServiceAccountName: "worker", Containers: []corev1.Container{{Name: "worker", Image: "example.invalid/worker:test"}},
				}},
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "workload-admin", Namespace: "production"},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
				{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"rolebindings"}, Verbs: []string{"patch"}},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "workload-admin", Namespace: "production"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "workload-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "production", Name: "worker"}},
		},
	)
	state, err := collectors.NewClusterCollector().Collect(context.Background(), client, domain.ClusterMetadata{Name: "test", Context: "test", Server: "https://127.0.0.1:6443"}, collectors.Scope{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	ruleEngine, err := rulesengine.New(k02.Rules()...)
	if err != nil {
		t.Fatalf("initialize K02 rules: %v", err)
	}
	ruleFindings, err := ruleEngine.Evaluate(context.Background(), state)
	if err != nil {
		t.Fatalf("evaluate K02 rules: %v", err)
	}
	graph, err := graphbuild.Build(state, ruleFindings)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	correlated, err := New().Evaluate(context.Background(), graph)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	for _, ruleID := range []string{"KSCAN-PATH-002", "KSCAN-PATH-003"} {
		if findingByRule(correlated, ruleID) == nil {
			t.Errorf("real collector/rule graph did not produce %s: %#v", ruleID, correlated)
		}
	}
}

func TestCorrelateExposedPrivilegedWorkloadWithSecretAccess(t *testing.T) {
	graph := exposedSecretGraph(t, exposedSecretOptions{})
	findings, err := New().Evaluate(context.Background(), graph)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	finding := findingByRule(findings, "KSCAN-PATH-001")
	if finding == nil {
		t.Fatalf("KSCAN-PATH-001 not produced: %#v", findings)
	}
	if finding.Severity != domain.SeverityHigh || finding.PrimaryOWASP.ID != "K02" {
		t.Fatalf("unexpected classification: severity=%q primary=%#v", finding.Severity, finding.PrimaryOWASP)
	}
	for _, category := range []string{"K01", "K03", "K06"} {
		if !hasCategory(finding.RelatedOWASP, category) {
			t.Errorf("related OWASP mappings missing %s: %#v", category, finding.RelatedOWASP)
		}
	}
	if len(finding.AttackPath) != 6 {
		t.Fatalf("attack path steps=%d, want 6: %#v", len(finding.AttackPath), finding.AttackPath)
	}
	if len(finding.AffectedResources) != 6 {
		t.Fatalf("affected resources=%d, want 6: %#v", len(finding.AffectedResources), finding.AffectedResources)
	}
	if len(finding.SupportingFindings) != 3 {
		t.Fatalf("supporting findings=%d, want 3: %#v", len(finding.SupportingFindings), finding.SupportingFindings)
	}
	if len(finding.Evidence) < len(finding.AttackPath) {
		t.Fatalf("correlated evidence does not support every edge: %#v", finding.Evidence)
	}
	for _, step := range finding.AttackPath {
		if step.Confidence != string(model.ConfidenceConfirmed) || len(step.Evidence) == 0 {
			t.Fatalf("unsupported step included in path: %#v", step)
		}
	}
}

func TestExposedPrivilegedSecretNearMissesDoNotCorrelate(t *testing.T) {
	tests := []struct {
		name    string
		options exposedSecretOptions
	}{
		{name: "no authoritative exposure finding", options: exposedSecretOptions{omitExposureFinding: true}},
		{name: "privileged finding missing", options: exposedSecretOptions{omitPrivilegedFinding: true}},
		{name: "RBAC supporting finding missing", options: exposedSecretOptions{omitRBACFinding: true}},
		{name: "route inferred", options: exposedSecretOptions{routeConfidence: model.ConfidenceInferred}},
		{name: "route has no evidence", options: exposedSecretOptions{omitRouteEvidence: true}},
		{name: "permission is not Secret read", options: exposedSecretOptions{permissionResource: "configmaps"}},
		{name: "permission cannot read", options: exposedSecretOptions{permissionVerbs: "create"}},
		{name: "permission applies to another namespace", options: exposedSecretOptions{permissionNamespace: "staging"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := New().Evaluate(context.Background(), exposedSecretGraph(t, test.options))
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if finding := findingByRule(findings, "KSCAN-PATH-001"); finding != nil {
				t.Fatalf("near miss produced correlation: %#v", *finding)
			}
		})
	}
}

func TestCorrelateWorkloadPodCreationOpportunity(t *testing.T) {
	findings, err := New().Evaluate(context.Background(), podCreateGraph(t, podCreateOptions{}))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	finding := findingByRule(findings, "KSCAN-PATH-002")
	if finding == nil {
		t.Fatalf("KSCAN-PATH-002 not produced: %#v", findings)
	}
	if finding.PrimaryOWASP.ID != "K02" || !hasCategory(finding.RelatedOWASP, "K01") {
		t.Fatalf("unexpected OWASP mapping: primary=%#v related=%#v", finding.PrimaryOWASP, finding.RelatedOWASP)
	}
	if len(finding.AttackPath) != 4 || len(finding.SupportingFindings) != 1 {
		t.Fatalf("unexpected correlation structure: %#v", *finding)
	}
}

func TestPodCreationNearMissesDoNotCorrelate(t *testing.T) {
	tests := []struct {
		name    string
		options podCreateOptions
	}{
		{name: "Pod read only", options: podCreateOptions{verbs: "get"}},
		{name: "named resources cannot constrain create", options: podCreateOptions{resourceNames: "existing-pod"}},
		{name: "grant applies to another namespace", options: podCreateOptions{namespace: "staging"}},
		{name: "uses edge inferred", options: podCreateOptions{usesConfidence: model.ConfidenceInferred}},
		{name: "permit edge lacks evidence", options: podCreateOptions{omitPermitEvidence: true}},
		{name: "supporting K02 finding missing", options: podCreateOptions{omitRBACFinding: true}},
		{name: "ServiceAccount was only referenced", options: podCreateOptions{serviceAccountObserved: boolPointer(false)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := New().Evaluate(context.Background(), podCreateGraph(t, test.options))
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if finding := findingByRule(findings, "KSCAN-PATH-002"); finding != nil {
				t.Fatalf("near miss produced correlation: %#v", *finding)
			}
		})
	}
}

func TestPodCreationCorrelationPrefersControllerWorkload(t *testing.T) {
	graph := podCreateGraph(t, podCreateOptions{})
	podRef := ref("v1", "Pod", "production", "worker-abc")
	addResource(t, graph, "child-pod", podRef, true)
	addRelationship(t, graph, "creates", "workload", "child-pod", model.EdgeCreates, model.ConfidenceInferred, true, nil)
	addRelationship(t, graph, "pod-uses", "child-pod", "service-account", model.EdgeUses, model.ConfidenceConfirmed, true, nil)

	findings, err := New().Evaluate(context.Background(), graph)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	var podCreate []domain.Finding
	for _, finding := range findings {
		if finding.RuleID == "KSCAN-PATH-002" {
			podCreate = append(podCreate, finding)
		}
	}
	if len(podCreate) != 1 || podCreate[0].Resource.Kind != "Deployment" {
		t.Fatalf("controller and Pod produced duplicate correlations: %#v", podCreate)
	}
}

func TestCorrelateServiceAccountRBACModificationOpportunity(t *testing.T) {
	findings, err := New().Evaluate(context.Background(), rbacModifyGraph(t, rbacModifyOptions{}))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	finding := findingByRule(findings, "KSCAN-PATH-003")
	if finding == nil {
		t.Fatalf("KSCAN-PATH-003 not produced: %#v", findings)
	}
	if finding.Resource.Kind != "ServiceAccount" || finding.PrimaryOWASP.ID != "K02" {
		t.Fatalf("unexpected correlation subject or mapping: %#v", *finding)
	}
	if len(finding.AttackPath) != 3 || len(finding.SupportingFindings) != 1 {
		t.Fatalf("unexpected correlation structure: %#v", *finding)
	}
}

func TestRBACModificationNearMissesDoNotCorrelate(t *testing.T) {
	tests := []struct {
		name    string
		options rbacModifyOptions
	}{
		{name: "delete does not create escalation path", options: rbacModifyOptions{verbs: "delete"}},
		{name: "Role modification is not binding modification", options: rbacModifyOptions{resource: "roles"}},
		{name: "wrong API group", options: rbacModifyOptions{apiGroup: "apps"}},
		{name: "permit edge unknown", options: rbacModifyOptions{permitConfidence: model.ConfidenceUnknown}},
		{name: "references edge has no evidence", options: rbacModifyOptions{omitReferenceEvidence: true}},
		{name: "supporting K02 finding missing", options: rbacModifyOptions{omitRBACFinding: true}},
		{name: "ServiceAccount was only referenced", options: rbacModifyOptions{serviceAccountObserved: boolPointer(false)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := New().Evaluate(context.Background(), rbacModifyGraph(t, test.options))
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if finding := findingByRule(findings, "KSCAN-PATH-003"); finding != nil {
				t.Fatalf("near miss produced correlation: %#v", *finding)
			}
		})
	}
}

func TestCorrelatorReturnsContextAndInputErrors(t *testing.T) {
	if _, err := New().Evaluate(context.Background(), nil); err == nil {
		t.Fatal("expected nil graph error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Evaluate(ctx, model.New()); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

type exposedSecretOptions struct {
	omitExposureFinding   bool
	omitPrivilegedFinding bool
	omitRBACFinding       bool
	routeConfidence       model.Confidence
	omitRouteEvidence     bool
	permissionResource    string
	permissionVerbs       string
	permissionNamespace   string
}

func exposedSecretGraph(t *testing.T, options exposedSecretOptions) *model.Graph {
	t.Helper()
	graph := model.New()
	ingressRef := ref("networking.k8s.io/v1", "Ingress", "production", "public-api")
	serviceRef := ref("v1", "Service", "production", "api")
	podRef := ref("v1", "Pod", "production", "api-abc")
	serviceAccountRef := ref("v1", "ServiceAccount", "production", "api")
	bindingRef := ref("rbac.authorization.k8s.io/v1", "RoleBinding", "production", "secret-reader")
	roleRef := ref("rbac.authorization.k8s.io/v1", "Role", "production", "secret-reader")
	ingressFindings := []domain.Finding{supportingFinding("KSCAN-K06-001", "K06", ingressRef)}
	if options.omitExposureFinding {
		ingressFindings = nil
	}
	podFindings := []domain.Finding{supportingFinding("KSCAN-K01-001", "K01", podRef)}
	if options.omitPrivilegedFinding {
		podFindings = nil
	}
	bindingFindings := []domain.Finding{supportingFinding("KSCAN-K02-003", "K02", bindingRef)}
	if options.omitRBACFinding {
		bindingFindings = nil
	}
	addResource(t, graph, "ingress", ingressRef, true, ingressFindings...)
	addResource(t, graph, "service", serviceRef, true)
	addResource(t, graph, "workload", podRef, true, podFindings...)
	addResource(t, graph, "service-account", serviceAccountRef, true)
	addResource(t, graph, "binding", bindingRef, true, bindingFindings...)
	addResource(t, graph, "role", roleRef, true)
	resource := options.permissionResource
	if resource == "" {
		resource = "secrets"
	}
	verbs := options.permissionVerbs
	if verbs == "" {
		verbs = "get,list"
	}
	namespace := options.permissionNamespace
	if namespace == "" {
		namespace = "production"
	}
	addAPIResource(t, graph, "permission", "", resource, "namespace", namespace)
	routeConfidence := options.routeConfidence
	if routeConfidence == "" {
		routeConfidence = model.ConfidenceConfirmed
	}
	addRelationship(t, graph, "route", "ingress", "service", model.EdgeRoutesTo, routeConfidence, !options.omitRouteEvidence, nil)
	addRelationship(t, graph, "expose", "service", "workload", model.EdgeExposes, model.ConfidenceConfirmed, true, nil)
	addRelationship(t, graph, "uses", "workload", "service-account", model.EdgeUses, model.ConfidenceConfirmed, true, nil)
	addRelationship(t, graph, "bound", "service-account", "binding", model.EdgeBoundVia, model.ConfidenceConfirmed, true, nil)
	addRelationship(t, graph, "reference", "binding", "role", model.EdgeReferences, model.ConfidenceConfirmed, true, nil)
	addRelationship(t, graph, "permit", "role", "permission", model.EdgePermits, model.ConfidenceConfirmed, true, map[string]string{
		"binding_id": "binding", "verbs": verbs, "scope": "namespace", "namespace": namespace,
	})
	return graph
}

type podCreateOptions struct {
	verbs                  string
	resourceNames          string
	namespace              string
	usesConfidence         model.Confidence
	omitPermitEvidence     bool
	omitRBACFinding        bool
	serviceAccountObserved *bool
}

func podCreateGraph(t *testing.T, options podCreateOptions) *model.Graph {
	t.Helper()
	graph := model.New()
	workloadRef := ref("apps/v1", "Deployment", "production", "worker")
	serviceAccountRef := ref("v1", "ServiceAccount", "production", "worker")
	bindingRef := ref("rbac.authorization.k8s.io/v1", "RoleBinding", "production", "pod-creator")
	roleRef := ref("rbac.authorization.k8s.io/v1", "Role", "production", "pod-creator")
	bindingFindings := []domain.Finding{supportingFinding("KSCAN-K02-006", "K02", bindingRef)}
	if options.omitRBACFinding {
		bindingFindings = nil
	}
	observed := true
	if options.serviceAccountObserved != nil {
		observed = *options.serviceAccountObserved
	}
	addResource(t, graph, "workload", workloadRef, true)
	addResource(t, graph, "service-account", serviceAccountRef, observed)
	addResource(t, graph, "binding", bindingRef, true, bindingFindings...)
	addResource(t, graph, "role", roleRef, true)
	namespace := options.namespace
	if namespace == "" {
		namespace = "production"
	}
	addAPIResource(t, graph, "permission", "", "pods", "namespace", namespace)
	usesConfidence := options.usesConfidence
	if usesConfidence == "" {
		usesConfidence = model.ConfidenceConfirmed
	}
	verbs := options.verbs
	if verbs == "" {
		verbs = "create"
	}
	addRelationship(t, graph, "uses", "workload", "service-account", model.EdgeUses, usesConfidence, true, nil)
	addRelationship(t, graph, "bound", "service-account", "binding", model.EdgeBoundVia, model.ConfidenceConfirmed, true, nil)
	addRelationship(t, graph, "reference", "binding", "role", model.EdgeReferences, model.ConfidenceConfirmed, true, nil)
	addRelationship(t, graph, "permit", "role", "permission", model.EdgePermits, model.ConfidenceConfirmed, !options.omitPermitEvidence, map[string]string{
		"binding_id": "binding", "verbs": verbs, "scope": "namespace", "namespace": namespace, "resource_names": options.resourceNames,
	})
	return graph
}

type rbacModifyOptions struct {
	verbs                  string
	resource               string
	apiGroup               string
	permitConfidence       model.Confidence
	omitReferenceEvidence  bool
	omitRBACFinding        bool
	serviceAccountObserved *bool
}

func rbacModifyGraph(t *testing.T, options rbacModifyOptions) *model.Graph {
	t.Helper()
	graph := model.New()
	serviceAccountRef := ref("v1", "ServiceAccount", "production", "operator")
	bindingRef := ref("rbac.authorization.k8s.io/v1", "RoleBinding", "production", "rbac-editor")
	roleRef := ref("rbac.authorization.k8s.io/v1", "Role", "production", "rbac-editor")
	bindingFindings := []domain.Finding{supportingFinding("KSCAN-K02-011", "K02", bindingRef)}
	if options.omitRBACFinding {
		bindingFindings = nil
	}
	observed := true
	if options.serviceAccountObserved != nil {
		observed = *options.serviceAccountObserved
	}
	addResource(t, graph, "service-account", serviceAccountRef, observed)
	addResource(t, graph, "binding", bindingRef, true, bindingFindings...)
	addResource(t, graph, "role", roleRef, true)
	resource := options.resource
	if resource == "" {
		resource = "rolebindings"
	}
	apiGroup := options.apiGroup
	if apiGroup == "" {
		apiGroup = "rbac.authorization.k8s.io"
	}
	addAPIResource(t, graph, "permission", apiGroup, resource, "namespace", "production")
	verbs := options.verbs
	if verbs == "" {
		verbs = "patch,update"
	}
	confidence := options.permitConfidence
	if confidence == "" {
		confidence = model.ConfidenceConfirmed
	}
	addRelationship(t, graph, "bound", "service-account", "binding", model.EdgeBoundVia, model.ConfidenceConfirmed, true, nil)
	addRelationship(t, graph, "reference", "binding", "role", model.EdgeReferences, model.ConfidenceConfirmed, !options.omitReferenceEvidence, nil)
	addRelationship(t, graph, "permit", "role", "permission", model.EdgePermits, confidence, true, map[string]string{
		"binding_id": "binding", "verbs": verbs, "scope": "namespace", "namespace": "production",
	})
	return graph
}

func addResource(t *testing.T, graph *model.Graph, id model.NodeID, resource domain.ResourceReference, observed bool, findings ...domain.Finding) {
	t.Helper()
	if err := graph.AddNode(model.Node{
		ID: id, Type: model.NodeTypeResource, Kind: resource.Kind, Ref: &resource,
		Attributes: map[string]string{"observed": boolString(observed)}, Findings: findings,
	}); err != nil {
		t.Fatalf("add resource %s: %v", id, err)
	}
}

func addAPIResource(t *testing.T, graph *model.Graph, id model.NodeID, apiGroup, resource, scope, namespace string) {
	t.Helper()
	if err := graph.AddNode(model.Node{ID: id, Type: model.NodeTypeAPIResource, Kind: "APIResource", Attributes: map[string]string{
		"api_group": apiGroup, "resource": resource, "scope": scope, "namespace": namespace,
	}}); err != nil {
		t.Fatalf("add API resource %s: %v", id, err)
	}
}

func addRelationship(t *testing.T, graph *model.Graph, id model.EdgeID, from, to model.NodeID, edgeType model.EdgeType, confidence model.Confidence, withEvidence bool, attributes map[string]string) {
	t.Helper()
	var evidence []domain.Evidence
	if withEvidence {
		evidence = []domain.Evidence{{Field: "fixture." + string(edgeType), Value: string(edgeType), Message: "confirmed fixture relationship"}}
	}
	if err := graph.AddEdge(model.Edge{ID: id, From: from, To: to, Type: edgeType, Confidence: confidence, Attributes: attributes, Evidence: evidence}); err != nil {
		t.Fatalf("add relationship %s: %v", id, err)
	}
}

func supportingFinding(ruleID, category string, resource domain.ResourceReference) domain.Finding {
	return domain.Finding{
		Fingerprint: ruleID + "-fingerprint", RuleID: ruleID, Title: ruleID, Severity: domain.SeverityHigh, Resource: resource,
		PrimaryOWASP: domain.OWASPCategory{ID: category, Version: "2025"},
		Evidence:     []domain.Evidence{{Field: "fixture.finding", Value: "true", Message: "confirmed supporting finding"}},
	}
}

func ref(apiVersion, kind, namespace, name string) domain.ResourceReference {
	return domain.ResourceReference{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name}
}

func findingByRule(findings []domain.Finding, ruleID string) *domain.Finding {
	for index := range findings {
		if findings[index].RuleID == ruleID {
			return &findings[index]
		}
	}
	return nil
}

func hasCategory(categories []domain.OWASPCategory, wanted string) bool {
	for _, category := range categories {
		if category.ID == wanted {
			return true
		}
	}
	return false
}

func boolPointer(value bool) *bool { return &value }

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
