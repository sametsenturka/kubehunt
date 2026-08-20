package query

import (
	"fmt"
	"sort"

	"github.com/sametsenturka/kubehunt/internal/graph/model"
)

type Direction string

const (
	DirectionOutgoing Direction = "outgoing"
	DirectionIncoming Direction = "incoming"
)

type TraversalOptions struct {
	Direction Direction
	MaxDepth  int
	EdgeTypes []model.EdgeType
}

type Visit struct {
	Node  model.Node
	Depth int
	Via   *model.Edge
}

// Traverse performs a bounded, cycle-safe breadth-first traversal. The start
// node is always the first result at depth zero.
func Traverse(graph *model.Graph, start model.NodeID, options TraversalOptions) ([]Visit, error) {
	if graph == nil {
		return nil, fmt.Errorf("traverse graph: graph is nil")
	}
	if _, found := graph.Node(start); !found {
		return nil, fmt.Errorf("traverse graph: start node %q does not exist", start)
	}
	if options.MaxDepth < 0 {
		return nil, fmt.Errorf("traverse graph: max depth cannot be negative")
	}
	direction := options.Direction
	if direction == "" {
		direction = DirectionOutgoing
	}
	if direction != DirectionOutgoing && direction != DirectionIncoming {
		return nil, fmt.Errorf("traverse graph: unsupported direction %q", direction)
	}

	allowed := make(map[model.EdgeType]struct{}, len(options.EdgeTypes))
	for _, edgeType := range options.EdgeTypes {
		allowed[edgeType] = struct{}{}
	}
	type pendingVisit struct {
		id    model.NodeID
		depth int
		via   *model.Edge
	}
	queue := []pendingVisit{{id: start}}
	seen := map[model.NodeID]struct{}{start: {}}
	result := make([]Visit, 0)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		node, _ := graph.Node(current.id)
		result = append(result, Visit{Node: node, Depth: current.depth, Via: current.via})
		if current.depth == options.MaxDepth {
			continue
		}
		edges := graph.Outgoing(current.id)
		if direction == DirectionIncoming {
			edges = graph.Incoming(current.id)
		}
		for index := range edges {
			edge := edges[index]
			if len(allowed) > 0 {
				if _, permitted := allowed[edge.Type]; !permitted {
					continue
				}
			}
			next := edge.To
			if direction == DirectionIncoming {
				next = edge.From
			}
			if _, visited := seen[next]; visited {
				continue
			}
			seen[next] = struct{}{}
			edgeCopy := edge
			queue = append(queue, pendingVisit{id: next, depth: current.depth + 1, via: &edgeCopy})
		}
	}
	return result, nil
}

type AuthorizationRelationship struct {
	Identity   model.Node
	Binding    model.Node
	Role       model.Node
	Resource   model.Node
	BoundVia   model.Edge
	References model.Edge
	Permits    model.Edge
}

// ResourcesForIdentity returns concrete RBAC relationship chains. Permit
// edges are scoped to the binding that produced them so permissions from two
// bindings of the same ClusterRole cannot be mixed.
func ResourcesForIdentity(graph *model.Graph, identityID model.NodeID) ([]AuthorizationRelationship, error) {
	if graph == nil {
		return nil, fmt.Errorf("query resources for identity: graph is nil")
	}
	identity, found := graph.Node(identityID)
	if !found {
		return nil, fmt.Errorf("query resources for identity: node %q does not exist", identityID)
	}
	var result []AuthorizationRelationship
	for _, boundVia := range edgesOfType(graph.Outgoing(identityID), model.EdgeBoundVia) {
		binding, found := graph.Node(boundVia.To)
		if !found {
			continue
		}
		for _, references := range edgesOfType(graph.Outgoing(binding.ID), model.EdgeReferences) {
			role, found := graph.Node(references.To)
			if !found {
				continue
			}
			for _, permits := range edgesOfType(graph.Outgoing(role.ID), model.EdgePermits) {
				if permits.Attributes["binding_id"] != string(binding.ID) {
					continue
				}
				resource, found := graph.Node(permits.To)
				if !found {
					continue
				}
				result = append(result, AuthorizationRelationship{
					Identity: identity, Binding: binding, Role: role, Resource: resource,
					BoundVia: boundVia, References: references, Permits: permits,
				})
			}
		}
	}
	sortRelationships(result)
	return result, nil
}

// IdentitiesForResource returns the inverse RBAC relationship chains for one
// API resource target.
func IdentitiesForResource(graph *model.Graph, resourceID model.NodeID) ([]AuthorizationRelationship, error) {
	if graph == nil {
		return nil, fmt.Errorf("query identities for resource: graph is nil")
	}
	resource, found := graph.Node(resourceID)
	if !found {
		return nil, fmt.Errorf("query identities for resource: node %q does not exist", resourceID)
	}
	var result []AuthorizationRelationship
	for _, permits := range edgesOfType(graph.Incoming(resourceID), model.EdgePermits) {
		bindingID := model.NodeID(permits.Attributes["binding_id"])
		if bindingID == "" {
			continue
		}
		binding, found := graph.Node(bindingID)
		if !found {
			continue
		}
		var references *model.Edge
		for _, candidate := range edgesOfType(graph.Outgoing(bindingID), model.EdgeReferences) {
			if candidate.To == permits.From {
				copy := candidate
				references = &copy
				break
			}
		}
		if references == nil {
			continue
		}
		role, found := graph.Node(permits.From)
		if !found {
			continue
		}
		for _, boundVia := range edgesOfType(graph.Incoming(bindingID), model.EdgeBoundVia) {
			identity, found := graph.Node(boundVia.From)
			if !found {
				continue
			}
			result = append(result, AuthorizationRelationship{
				Identity: identity, Binding: binding, Role: role, Resource: resource,
				BoundVia: boundVia, References: *references, Permits: permits,
			})
		}
	}
	sortRelationships(result)
	return result, nil
}

func edgesOfType(edges []model.Edge, edgeType model.EdgeType) []model.Edge {
	result := make([]model.Edge, 0, len(edges))
	for _, edge := range edges {
		if edge.Type == edgeType {
			result = append(result, edge)
		}
	}
	return result
}

func sortRelationships(relationships []AuthorizationRelationship) {
	sort.SliceStable(relationships, func(left, right int) bool {
		return relationshipKey(relationships[left]) < relationshipKey(relationships[right])
	})
}

func relationshipKey(relationship AuthorizationRelationship) string {
	return string(relationship.Identity.ID) + "\x00" + string(relationship.Binding.ID) + "\x00" + string(relationship.Role.ID) + "\x00" + string(relationship.Resource.ID) + "\x00" + string(relationship.Permits.ID)
}
