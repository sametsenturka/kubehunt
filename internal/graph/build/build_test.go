package build_test

import (
	"reflect"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
	graphbuild "github.com/sametsenturka/kubehunt/internal/graph/build"
	"github.com/sametsenturka/kubehunt/internal/graph/model"
	"github.com/sametsenturka/kubehunt/internal/graph/query"
)

func TestBuildCreatesKubernetesSecurityRelationships(t *testing.T) {
	state := graphFixture()
	finding := domain.Finding{
		Fingerprint: "privileged-deployment",
		RuleID:      "KSCAN-K01-001",
		Resource:    domain.ResourceReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "production", Name: "api"},
	}
	graph, err := graphbuild.Build(state, []domain.Finding{finding})
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	for _, edge := range graph.Edges() {
		if len(edge.Evidence) == 0 {
			t.Errorf("edge %s (%s) has no derivation evidence", edge.ID, edge.Type)
		}
	}

	clusterKey := model.ClusterKey(state.Cluster)
	deployment := resourceID(clusterKey, "apps/v1", "Deployment", "production", "api")
	pod := resourceID(clusterKey, "v1", "Pod", "production", "api-abc")
	serviceAccount := resourceID(clusterKey, "v1", "ServiceAccount", "production", "runner")
	roleBinding := resourceID(clusterKey, "rbac.authorization.k8s.io/v1", "RoleBinding", "production", "read-secrets")
	role := resourceID(clusterKey, "rbac.authorization.k8s.io/v1", "Role", "production", "secret-reader")
	service := resourceID(clusterKey, "v1", "Service", "production", "api")
	ingress := resourceID(clusterKey, "networking.k8s.io/v1", "Ingress", "production", "api")
	policy := resourceID(clusterKey, "networking.k8s.io/v1", "NetworkPolicy", "production", "api")
	secretResource := model.APIResourceNodeID(clusterKey, "", "secrets", "namespace", "production", nil)

	assertEdge(t, graph, deployment, pod, model.EdgeCreates, model.ConfidenceInferred)
	assertEdge(t, graph, pod, serviceAccount, model.EdgeUses, model.ConfidenceConfirmed)
	assertEdge(t, graph, serviceAccount, roleBinding, model.EdgeBoundVia, model.ConfidenceConfirmed)
	assertEdge(t, graph, roleBinding, role, model.EdgeReferences, model.ConfidenceConfirmed)
	assertEdge(t, graph, role, secretResource, model.EdgePermits, model.ConfidenceConfirmed)
	assertEdge(t, graph, service, pod, model.EdgeExposes, model.ConfidenceConfirmed)
	assertEdge(t, graph, ingress, service, model.EdgeRoutesTo, model.ConfidenceConfirmed)
	assertEdge(t, graph, policy, pod, model.EdgeSelects, model.ConfidenceConfirmed)

	deploymentNode, found := graph.Node(deployment)
	if !found || len(deploymentNode.Findings) != 1 || deploymentNode.Findings[0].RuleID != finding.RuleID {
		t.Fatalf("finding was not attached to Deployment: %#v, found=%v", deploymentNode, found)
	}
	relationships, err := query.ResourcesForIdentity(graph, serviceAccount)
	if err != nil {
		t.Fatalf("query ServiceAccount permissions: %v", err)
	}
	if len(relationships) != 1 || relationships[0].Resource.ID != secretResource {
		t.Fatalf("unexpected ServiceAccount permissions: %#v", relationships)
	}
	if got := graph.NodesByKind("NonResourceURL"); len(got) != 0 {
		t.Fatalf("RoleBinding must not grant non-resource URL permissions: %#v", got)
	}

	group := model.SubjectNodeID(clusterKey, "rbac.authorization.k8s.io", "Group", "", "developers")
	clusterBinding := resourceID(clusterKey, "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "view-pods")
	clusterRole := resourceID(clusterKey, "rbac.authorization.k8s.io/v1", "ClusterRole", "", "pod-viewer")
	assertEdge(t, graph, group, clusterBinding, model.EdgeBoundVia, model.ConfidenceConfirmed)
	assertEdge(t, graph, clusterBinding, clusterRole, model.EdgeReferences, model.ConfidenceConfirmed)
}

func TestBuildProducesDeterministicNodeAndEdgeOrder(t *testing.T) {
	state := graphFixture()
	first, err := graphbuild.Build(state, nil)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	second, err := graphbuild.Build(state, nil)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if !reflect.DeepEqual(first.Nodes(), second.Nodes()) {
		t.Fatal("node output is not deterministic")
	}
	if !reflect.DeepEqual(first.Edges(), second.Edges()) {
		t.Fatal("edge output is not deterministic")
	}
}

func TestBuildKeepsIdentifiersStableWhenKubernetesUIDsChange(t *testing.T) {
	firstState := graphFixture()
	secondState := graphFixture()
	secondState.Deployments[0].Metadata.UID = "replacement-deployment-uid"
	secondState.Pods[0].Metadata.UID = "replacement-pod-uid"
	secondState.Pods[0].Metadata.Owners[0].UID = "replacement-replicaset-uid"

	first, err := graphbuild.Build(firstState, nil)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	second, err := graphbuild.Build(secondState, nil)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if !reflect.DeepEqual(nodeIDs(first), nodeIDs(second)) {
		t.Fatal("node identifiers changed with Kubernetes UIDs")
	}
	if !reflect.DeepEqual(edgeIDs(first), edgeIDs(second)) {
		t.Fatal("edge identifiers changed with Kubernetes UIDs")
	}
}

func graphFixture() domain.ClusterState {
	return domain.ClusterState{
		Cluster:    domain.ClusterMetadata{Context: "kind-kubehunt", Name: "kind-kubehunt", Server: "https://127.0.0.1:6443"},
		Namespaces: []domain.Namespace{{Metadata: domain.Metadata{Name: "production"}}},
		Deployments: []domain.Workload{{
			Metadata: domain.Metadata{Name: "api", Namespace: "production", UID: "deployment-uid"},
			Selector: domain.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: domain.PodTemplate{Labels: map[string]string{"app": "api"}, Spec: domain.PodSpec{ServiceAccountName: "runner"}},
		}},
		Pods: []domain.Pod{{
			Metadata: domain.Metadata{
				Name: "api-abc", Namespace: "production", UID: "pod-uid", Labels: map[string]string{"app": "api"},
				Owners: []domain.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "api-7c8d", UID: "replicaset-uid", Controller: true}},
			},
			Spec: domain.PodSpec{ServiceAccountName: "runner"},
		}},
		ServiceAccounts: []domain.ServiceAccount{{Metadata: domain.Metadata{Name: "runner", Namespace: "production"}}},
		Services:        []domain.Service{{Metadata: domain.Metadata{Name: "api", Namespace: "production"}, Selector: map[string]string{"app": "api"}}},
		Ingresses: []domain.Ingress{{
			Metadata: domain.Metadata{Name: "api", Namespace: "production"},
			Rules:    []domain.IngressRule{{Host: "api.example.test", Paths: []domain.IngressPath{{Path: "/", Backend: domain.IngressBackend{ServiceName: "api", ServicePort: "http"}}}}},
		}},
		NetworkPolicies: []domain.NetworkPolicy{{
			Metadata:    domain.Metadata{Name: "api", Namespace: "production"},
			PodSelector: domain.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []string{"Ingress"},
		}},
		Roles: []domain.Role{{
			Metadata: domain.Metadata{Name: "secret-reader", Namespace: "production"},
			Rules:    []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}, NonResourceURLs: []string{"/healthz"}}},
		}},
		RoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "read-secrets", Namespace: "production"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader"},
			Subjects: []domain.Subject{{Kind: "ServiceAccount", Namespace: "production", Name: "runner"}},
		}},
		ClusterRoles: []domain.Role{{
			Metadata: domain.Metadata{Name: "pod-viewer"},
			Rules:    []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		}},
		ClusterRoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "view-pods"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-viewer"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "developers"}},
		}},
	}
}

func resourceID(clusterKey, apiVersion, kind, namespace, name string) model.NodeID {
	return model.ResourceNodeID(clusterKey, domain.ResourceReference{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name})
}

func assertEdge(t *testing.T, graph *model.Graph, from, to model.NodeID, edgeType model.EdgeType, confidence model.Confidence) {
	t.Helper()
	for _, edge := range graph.Outgoing(from) {
		if edge.To == to && edge.Type == edgeType {
			if edge.Confidence != confidence {
				t.Fatalf("edge %s -> %s (%s) confidence=%q, want %q", from, to, edgeType, edge.Confidence, confidence)
			}
			return
		}
	}
	t.Fatalf("edge %s -> %s (%s) not found", from, to, edgeType)
}

func nodeIDs(graph *model.Graph) []model.NodeID {
	nodes := graph.Nodes()
	result := make([]model.NodeID, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, node.ID)
	}
	return result
}

func edgeIDs(graph *model.Graph) []model.EdgeID {
	edges := graph.Edges()
	result := make([]model.EdgeID, 0, len(edges))
	for _, edge := range edges {
		result = append(result, edge.ID)
	}
	return result
}
