package query

import (
	"testing"

	"github.com/sametsenturka/kubehunt/internal/graph/model"
)

func TestTraverseIsDirectedBoundedFilteredAndCycleSafe(t *testing.T) {
	graph := model.New()
	for _, node := range []model.Node{
		{ID: "deployment", Type: model.NodeTypeResource, Kind: "Deployment"},
		{ID: "pod", Type: model.NodeTypeResource, Kind: "Pod"},
		{ID: "service-account", Type: model.NodeTypeResource, Kind: "ServiceAccount"},
		{ID: "service", Type: model.NodeTypeResource, Kind: "Service"},
	} {
		mustAddNode(t, graph, node)
	}
	mustAddEdge(t, graph, model.Edge{ID: "creates", From: "deployment", To: "pod", Type: model.EdgeCreates})
	mustAddEdge(t, graph, model.Edge{ID: "uses", From: "pod", To: "service-account", Type: model.EdgeUses})
	mustAddEdge(t, graph, model.Edge{ID: "cycle", From: "service-account", To: "deployment", Type: model.EdgeReferences})
	mustAddEdge(t, graph, model.Edge{ID: "exposes", From: "service", To: "pod", Type: model.EdgeExposes})

	visits, err := Traverse(graph, "deployment", TraversalOptions{Direction: DirectionOutgoing, MaxDepth: 4})
	if err != nil {
		t.Fatalf("outgoing traversal: %v", err)
	}
	if len(visits) != 3 || visits[0].Node.ID != "deployment" || visits[1].Node.ID != "pod" || visits[2].Node.ID != "service-account" {
		t.Fatalf("unexpected cycle-safe traversal: %#v", visits)
	}
	if visits[2].Depth != 2 || visits[2].Via == nil || visits[2].Via.Type != model.EdgeUses {
		t.Fatalf("unexpected visit metadata: %#v", visits[2])
	}

	incoming, err := Traverse(graph, "pod", TraversalOptions{Direction: DirectionIncoming, MaxDepth: 1})
	if err != nil {
		t.Fatalf("incoming traversal: %v", err)
	}
	if len(incoming) != 3 {
		t.Fatalf("expected pod plus its two predecessors, got %#v", incoming)
	}

	filtered, err := Traverse(graph, "deployment", TraversalOptions{MaxDepth: 3, EdgeTypes: []model.EdgeType{model.EdgeCreates}})
	if err != nil {
		t.Fatalf("filtered traversal: %v", err)
	}
	if len(filtered) != 2 || filtered[1].Node.ID != "pod" {
		t.Fatalf("unexpected filtered traversal: %#v", filtered)
	}
}

func TestAuthorizationRelationshipQueriesPreserveBindingScope(t *testing.T) {
	graph := authorizationGraph(t)
	relationships, err := ResourcesForIdentity(graph, "identity-a")
	if err != nil {
		t.Fatalf("resources for identity: %v", err)
	}
	if len(relationships) != 1 {
		t.Fatalf("expected one binding-scoped permission, got %#v", relationships)
	}
	if relationships[0].Binding.ID != "binding-a" || relationships[0].Resource.ID != "secrets" {
		t.Fatalf("unexpected relationship: %#v", relationships[0])
	}

	identities, err := IdentitiesForResource(graph, "secrets")
	if err != nil {
		t.Fatalf("identities for resource: %v", err)
	}
	if len(identities) != 1 || identities[0].Identity.ID != "identity-a" {
		t.Fatalf("unexpected inverse relationship: %#v", identities)
	}
	podIdentities, err := IdentitiesForResource(graph, "pods")
	if err != nil {
		t.Fatalf("identities for pods: %v", err)
	}
	if len(podIdentities) != 1 || podIdentities[0].Identity.ID != "identity-b" {
		t.Fatalf("permissions leaked across bindings of the same role: %#v", podIdentities)
	}
}

func authorizationGraph(t *testing.T) *model.Graph {
	t.Helper()
	graph := model.New()
	for _, node := range []model.Node{
		{ID: "identity-a", Type: model.NodeTypeIdentity, Kind: "User"},
		{ID: "identity-b", Type: model.NodeTypeIdentity, Kind: "Group"},
		{ID: "binding-a", Type: model.NodeTypeResource, Kind: "RoleBinding"},
		{ID: "binding-b", Type: model.NodeTypeResource, Kind: "ClusterRoleBinding"},
		{ID: "role", Type: model.NodeTypeResource, Kind: "ClusterRole"},
		{ID: "secrets", Type: model.NodeTypeAPIResource, Kind: "APIResource"},
		{ID: "pods", Type: model.NodeTypeAPIResource, Kind: "APIResource"},
	} {
		mustAddNode(t, graph, node)
	}
	mustAddEdge(t, graph, model.Edge{ID: "bound-a", From: "identity-a", To: "binding-a", Type: model.EdgeBoundVia})
	mustAddEdge(t, graph, model.Edge{ID: "bound-b", From: "identity-b", To: "binding-b", Type: model.EdgeBoundVia})
	mustAddEdge(t, graph, model.Edge{ID: "ref-a", From: "binding-a", To: "role", Type: model.EdgeReferences})
	mustAddEdge(t, graph, model.Edge{ID: "ref-b", From: "binding-b", To: "role", Type: model.EdgeReferences})
	mustAddEdge(t, graph, model.Edge{ID: "permit-a", From: "role", To: "secrets", Type: model.EdgePermits, Attributes: map[string]string{"binding_id": "binding-a"}})
	mustAddEdge(t, graph, model.Edge{ID: "permit-b", From: "role", To: "pods", Type: model.EdgePermits, Attributes: map[string]string{"binding_id": "binding-b"}})
	return graph
}

func mustAddNode(t *testing.T, graph *model.Graph, node model.Node) {
	t.Helper()
	if err := graph.AddNode(node); err != nil {
		t.Fatalf("add node %q: %v", node.ID, err)
	}
}

func mustAddEdge(t *testing.T, graph *model.Graph, edge model.Edge) {
	t.Helper()
	if err := graph.AddEdge(edge); err != nil {
		t.Fatalf("add edge %q: %v", edge.ID, err)
	}
}
