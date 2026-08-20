package model

import (
	"reflect"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

func TestStableIdentifiers(t *testing.T) {
	cluster := ClusterKey(domain.ClusterMetadata{Context: "kind-kubehunt", Name: "kind-kubehunt", Server: "https://127.0.0.1:6443"})
	ref := domain.ResourceReference{APIVersion: "v1", Kind: "Pod", Namespace: "production", Name: "api", UID: "uid-one"}

	first := ResourceNodeID(cluster, ref)
	ref.UID = "uid-two"
	second := ResourceNodeID(cluster, ref)
	if first != second {
		t.Fatalf("resource ID must not depend on ephemeral UID: %q != %q", first, second)
	}
	ref.Namespace = "staging"
	if first == ResourceNodeID(cluster, ref) {
		t.Fatal("resource IDs must distinguish namespaces")
	}
	if APIResourceNodeID(cluster, "", "secrets", "namespace", "production", []string{"a", "a", "b"}) != APIResourceNodeID(cluster, "", "secrets", "namespace", "production", []string{"b", "a"}) {
		t.Fatal("API resource IDs must canonicalize resource names")
	}

	edgeOne := StableEdgeID(first, EdgeUses, second, "pod")
	edgeTwo := StableEdgeID(first, EdgeUses, second, "pod")
	if edgeOne != edgeTwo {
		t.Fatalf("edge IDs are not deterministic: %q != %q", edgeOne, edgeTwo)
	}
	if edgeOne == StableEdgeID(first, EdgeUses, second, "template") {
		t.Fatal("edge discriminator must distinguish parallel semantic edges")
	}
}

func TestGraphIndexesDirectionAndFindingAttachments(t *testing.T) {
	graph := New()
	podRef := domain.ResourceReference{APIVersion: "v1", Kind: "Pod", Namespace: "production", Name: "api"}
	pod := Node{ID: "pod", Type: NodeTypeResource, Kind: "Pod", Ref: &podRef, Attributes: map[string]string{"observed": "true"}}
	serviceAccount := Node{ID: "service-account", Type: NodeTypeResource, Kind: "ServiceAccount"}
	if err := graph.AddNode(pod); err != nil {
		t.Fatalf("add pod: %v", err)
	}
	if err := graph.AddNode(serviceAccount); err != nil {
		t.Fatalf("add service account: %v", err)
	}
	edge := Edge{
		ID: "uses", From: pod.ID, To: serviceAccount.ID, Type: EdgeUses, Confidence: ConfidenceConfirmed,
		Evidence: []domain.Evidence{{Field: "spec.serviceAccountName", Value: "runner", Message: "Pod uses ServiceAccount runner"}},
	}
	if err := graph.AddEdge(edge); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	if got := graph.Outgoing(pod.ID); len(got) != 1 || got[0].To != serviceAccount.ID {
		t.Fatalf("unexpected outgoing edges: %#v", got)
	}
	if got := graph.Incoming(serviceAccount.ID); len(got) != 1 || got[0].From != pod.ID {
		t.Fatalf("unexpected incoming edges: %#v", got)
	}
	if got := graph.Outgoing(serviceAccount.ID); len(got) != 0 {
		t.Fatalf("directed edge appeared in reverse traversal: %#v", got)
	}
	if got := graph.NodesByKind("Pod"); len(got) != 1 || got[0].ID != pod.ID {
		t.Fatalf("unexpected Pod index: %#v", got)
	}
	if got, found := graph.NodeForResource(podRef); !found || got.ID != pod.ID {
		t.Fatalf("resource index lookup failed: %#v, found=%v", got, found)
	}

	finding := domain.Finding{Fingerprint: "finding-1", RuleID: "KSCAN-K01-001", Resource: podRef}
	if err := graph.AttachFindingToNode(pod.ID, finding); err != nil {
		t.Fatalf("attach node finding: %v", err)
	}
	if err := graph.AttachFindingToNode(pod.ID, finding); err != nil {
		t.Fatalf("attach duplicate node finding: %v", err)
	}
	if err := graph.AttachFindingToEdge(edge.ID, finding); err != nil {
		t.Fatalf("attach edge finding: %v", err)
	}
	gotPod, _ := graph.Node(pod.ID)
	gotEdge, _ := graph.Edge(edge.ID)
	if len(gotPod.Findings) != 1 || len(gotEdge.Findings) != 1 {
		t.Fatalf("findings were not attached or deduplicated: node=%d edge=%d", len(gotPod.Findings), len(gotEdge.Findings))
	}

	gotPod.Attributes["observed"] = "mutated"
	gotEdge.Evidence[0].Message = "mutated"
	unchanged, _ := graph.Node(pod.ID)
	if !reflect.DeepEqual(unchanged.Attributes, map[string]string{"observed": "true"}) {
		t.Fatalf("node lookup exposed graph storage: %#v", unchanged.Attributes)
	}
	unchangedEdge, _ := graph.Edge(edge.ID)
	if unchangedEdge.Evidence[0].Message != "Pod uses ServiceAccount runner" {
		t.Fatalf("edge lookup exposed graph evidence storage: %#v", unchangedEdge.Evidence)
	}
}

func TestGraphRejectsInvalidAndConflictingEdges(t *testing.T) {
	graph := New()
	if err := graph.AddNode(Node{ID: "from", Type: NodeTypeResource, Kind: "Pod"}); err != nil {
		t.Fatalf("add source: %v", err)
	}
	if err := graph.AddEdge(Edge{ID: "missing", From: "from", To: "absent", Type: EdgeUses}); err == nil {
		t.Fatal("expected missing endpoint error")
	}
	if err := graph.AddNode(Node{ID: "to", Type: NodeTypeResource, Kind: "ServiceAccount"}); err != nil {
		t.Fatalf("add target: %v", err)
	}
	edge := Edge{ID: "same-id", From: "from", To: "to", Type: EdgeUses, Confidence: ConfidenceConfirmed}
	if err := graph.AddEdge(edge); err != nil {
		t.Fatalf("add edge: %v", err)
	}
	edge.Confidence = ConfidenceInferred
	if err := graph.AddEdge(edge); err == nil {
		t.Fatal("expected conflicting stable edge ID error")
	}
}
