package model

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

type NodeType string

const (
	NodeTypeResource    NodeType = "resource"
	NodeTypeIdentity    NodeType = "identity"
	NodeTypeAPIResource NodeType = "api_resource"
)

type EdgeType string

const (
	EdgeCreates    EdgeType = "creates"
	EdgeUses       EdgeType = "uses"
	EdgeBoundVia   EdgeType = "bound_via"
	EdgeReferences EdgeType = "references"
	EdgePermits    EdgeType = "permits"
	EdgeExposes    EdgeType = "exposes"
	EdgeRoutesTo   EdgeType = "routes_to"
	EdgeSelects    EdgeType = "selects"
)

type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceInferred  Confidence = "inferred"
	ConfidenceUnknown   Confidence = "unknown"
)

type Node struct {
	ID         NodeID
	Type       NodeType
	Kind       string
	Ref        *domain.ResourceReference
	Attributes map[string]string
	Findings   []domain.Finding
}

type Edge struct {
	ID         EdgeID
	From       NodeID
	To         NodeID
	Type       EdgeType
	Confidence Confidence
	Attributes map[string]string
	Evidence   []domain.Evidence
	Findings   []domain.Finding
}

type Graph struct {
	nodes         map[NodeID]Node
	edges         map[EdgeID]Edge
	outgoing      map[NodeID][]EdgeID
	incoming      map[NodeID][]EdgeID
	kindIndex     map[string][]NodeID
	resourceIndex map[string]NodeID
}

func New() *Graph {
	return &Graph{
		nodes:         make(map[NodeID]Node),
		edges:         make(map[EdgeID]Edge),
		outgoing:      make(map[NodeID][]EdgeID),
		incoming:      make(map[NodeID][]EdgeID),
		kindIndex:     make(map[string][]NodeID),
		resourceIndex: make(map[string]NodeID),
	}
}

func (graph *Graph) AddNode(node Node) error {
	if graph == nil {
		return fmt.Errorf("add graph node: graph is nil")
	}
	if node.ID == "" || node.Type == "" || node.Kind == "" {
		return fmt.Errorf("add graph node: ID, type, and kind are required")
	}
	node = cloneNode(node)
	if existing, found := graph.nodes[node.ID]; found {
		if sameNodeIdentity(existing, node) {
			return nil
		}
		return fmt.Errorf("add graph node %q: stable ID conflicts with an existing node", node.ID)
	}
	if node.Ref != nil {
		key := resourceKey(*node.Ref)
		if existing, found := graph.resourceIndex[key]; found && existing != node.ID {
			return fmt.Errorf("add graph node %q: resource identity conflicts with node %q", node.ID, existing)
		}
	}
	graph.nodes[node.ID] = node
	graph.kindIndex[node.Kind] = appendSortedNodeID(graph.kindIndex[node.Kind], node.ID)
	if node.Ref != nil {
		key := resourceKey(*node.Ref)
		graph.resourceIndex[key] = node.ID
	}
	return nil
}

func (graph *Graph) AddEdge(edge Edge) error {
	if graph == nil {
		return fmt.Errorf("add graph edge: graph is nil")
	}
	if edge.ID == "" || edge.From == "" || edge.To == "" || edge.Type == "" {
		return fmt.Errorf("add graph edge: ID, endpoints, and type are required")
	}
	if _, found := graph.nodes[edge.From]; !found {
		return fmt.Errorf("add graph edge %q: source node %q does not exist", edge.ID, edge.From)
	}
	if _, found := graph.nodes[edge.To]; !found {
		return fmt.Errorf("add graph edge %q: target node %q does not exist", edge.ID, edge.To)
	}
	edge = cloneEdge(edge)
	if existing, found := graph.edges[edge.ID]; found {
		if sameEdgeIdentity(existing, edge) {
			return nil
		}
		return fmt.Errorf("add graph edge %q: stable ID conflicts with an existing edge", edge.ID)
	}
	graph.edges[edge.ID] = edge
	graph.outgoing[edge.From] = appendSortedEdgeID(graph.outgoing[edge.From], edge.ID)
	graph.incoming[edge.To] = appendSortedEdgeID(graph.incoming[edge.To], edge.ID)
	return nil
}

func (graph *Graph) Node(id NodeID) (Node, bool) {
	if graph == nil {
		return Node{}, false
	}
	node, found := graph.nodes[id]
	return cloneNode(node), found
}

func (graph *Graph) Edge(id EdgeID) (Edge, bool) {
	if graph == nil {
		return Edge{}, false
	}
	edge, found := graph.edges[id]
	return cloneEdge(edge), found
}

func (graph *Graph) NodeForResource(ref domain.ResourceReference) (Node, bool) {
	if graph == nil {
		return Node{}, false
	}
	id, found := graph.resourceIndex[resourceKey(ref)]
	if !found {
		return Node{}, false
	}
	return graph.Node(id)
}

func (graph *Graph) Nodes() []Node {
	if graph == nil {
		return nil
	}
	ids := make([]NodeID, 0, len(graph.nodes))
	for id := range graph.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	result := make([]Node, 0, len(ids))
	for _, id := range ids {
		result = append(result, cloneNode(graph.nodes[id]))
	}
	return result
}

func (graph *Graph) Edges() []Edge {
	if graph == nil {
		return nil
	}
	ids := make([]EdgeID, 0, len(graph.edges))
	for id := range graph.edges {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return graph.edgesForIDs(ids)
}

func (graph *Graph) NodesByKind(kind string) []Node {
	if graph == nil {
		return nil
	}
	ids := graph.kindIndex[kind]
	result := make([]Node, 0, len(ids))
	for _, id := range ids {
		result = append(result, cloneNode(graph.nodes[id]))
	}
	return result
}

func (graph *Graph) Outgoing(id NodeID) []Edge {
	if graph == nil {
		return nil
	}
	return graph.edgesForIDs(graph.outgoing[id])
}

func (graph *Graph) Incoming(id NodeID) []Edge {
	if graph == nil {
		return nil
	}
	return graph.edgesForIDs(graph.incoming[id])
}

func (graph *Graph) AttachFindingToNode(id NodeID, finding domain.Finding) error {
	if graph == nil {
		return fmt.Errorf("attach finding to node: graph is nil")
	}
	node, found := graph.nodes[id]
	if !found {
		return fmt.Errorf("attach finding to node: node %q does not exist", id)
	}
	node.Findings = appendFinding(node.Findings, finding)
	graph.nodes[id] = node
	return nil
}

func (graph *Graph) AttachFindingToEdge(id EdgeID, finding domain.Finding) error {
	if graph == nil {
		return fmt.Errorf("attach finding to edge: graph is nil")
	}
	edge, found := graph.edges[id]
	if !found {
		return fmt.Errorf("attach finding to edge: edge %q does not exist", id)
	}
	edge.Findings = appendFinding(edge.Findings, finding)
	graph.edges[id] = edge
	return nil
}

func (graph *Graph) edgesForIDs(ids []EdgeID) []Edge {
	result := make([]Edge, 0, len(ids))
	for _, id := range ids {
		result = append(result, cloneEdge(graph.edges[id]))
	}
	return result
}

func sameNodeIdentity(left, right Node) bool {
	return left.ID == right.ID && left.Type == right.Type && left.Kind == right.Kind && reflect.DeepEqual(left.Ref, right.Ref) && reflect.DeepEqual(left.Attributes, right.Attributes)
}

func sameEdgeIdentity(left, right Edge) bool {
	return left.ID == right.ID && left.From == right.From && left.To == right.To && left.Type == right.Type && left.Confidence == right.Confidence && reflect.DeepEqual(left.Attributes, right.Attributes) && reflect.DeepEqual(left.Evidence, right.Evidence)
}

func appendFinding(findings []domain.Finding, finding domain.Finding) []domain.Finding {
	key := findingKey(finding)
	for _, existing := range findings {
		if findingKey(existing) == key {
			return findings
		}
	}
	findings = append(findings, finding)
	sort.SliceStable(findings, func(left, right int) bool { return findingKey(findings[left]) < findingKey(findings[right]) })
	return findings
}

func findingKey(finding domain.Finding) string {
	if finding.Fingerprint != "" {
		return finding.Fingerprint
	}
	return strings.Join([]string{finding.RuleID, finding.Resource.APIVersion, finding.Resource.Kind, finding.Resource.Namespace, finding.Resource.Name}, "\x00")
}

func resourceKey(ref domain.ResourceReference) string {
	return strings.Join([]string{ref.APIVersion, ref.Kind, ref.Namespace, ref.Name}, "\x00")
}

func cloneNode(node Node) Node {
	if node.Ref != nil {
		ref := *node.Ref
		node.Ref = &ref
	}
	node.Attributes = cloneMap(node.Attributes)
	node.Findings = cloneFindings(node.Findings)
	return node
}

func cloneEdge(edge Edge) Edge {
	edge.Attributes = cloneMap(edge.Attributes)
	edge.Evidence = append([]domain.Evidence(nil), edge.Evidence...)
	edge.Findings = cloneFindings(edge.Findings)
	return edge
}

func cloneFindings(findings []domain.Finding) []domain.Finding {
	if findings == nil {
		return nil
	}
	result := make([]domain.Finding, len(findings))
	for index, finding := range findings {
		result[index] = finding
		result[index].Evidence = append([]domain.Evidence(nil), finding.Evidence...)
		result[index].RelatedOWASP = append([]domain.OWASPCategory(nil), finding.RelatedOWASP...)
		result[index].AffectedResources = append([]domain.ResourceReference(nil), finding.AffectedResources...)
		result[index].AttackPath = cloneAttackPath(finding.AttackPath)
		result[index].SupportingFindings = cloneSupportingFindings(finding.SupportingFindings)
		if finding.RiskScore != nil {
			riskScore := *finding.RiskScore
			riskScore.Factors = make(map[string]int, len(finding.RiskScore.Factors))
			for key, value := range finding.RiskScore.Factors {
				riskScore.Factors[key] = value
			}
			result[index].RiskScore = &riskScore
		}
	}
	return result
}

func cloneAttackPath(path []domain.AttackPathStep) []domain.AttackPathStep {
	if path == nil {
		return nil
	}
	result := make([]domain.AttackPathStep, len(path))
	for index, step := range path {
		result[index] = step
		result[index].From = cloneAttackPathNode(step.From)
		result[index].To = cloneAttackPathNode(step.To)
		result[index].Evidence = append([]domain.Evidence(nil), step.Evidence...)
	}
	return result
}

func cloneAttackPathNode(node domain.AttackPathNode) domain.AttackPathNode {
	if node.Resource != nil {
		resource := *node.Resource
		node.Resource = &resource
	}
	node.Attributes = cloneMap(node.Attributes)
	return node
}

func cloneSupportingFindings(findings []domain.SupportingFinding) []domain.SupportingFinding {
	if findings == nil {
		return nil
	}
	result := make([]domain.SupportingFinding, len(findings))
	for index, finding := range findings {
		result[index] = finding
		result[index].Evidence = append([]domain.Evidence(nil), finding.Evidence...)
	}
	return result
}

func cloneMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func appendSortedNodeID(ids []NodeID, id NodeID) []NodeID {
	ids = append(ids, id)
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return ids
}

func appendSortedEdgeID(ids []EdgeID, id EdgeID) []EdgeID {
	ids = append(ids, id)
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return ids
}
