package model

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

const identityVersion = "graph-id-v1"

type NodeID string
type EdgeID string

func ClusterKey(cluster domain.ClusterMetadata) string {
	return stableID("cluster", cluster.Server, cluster.Name, cluster.Context)
}

func ResourceNodeID(clusterKey string, ref domain.ResourceReference) NodeID {
	return NodeID(stableID("resource", clusterKey, ref.APIVersion, ref.Kind, ref.Namespace, ref.Name))
}

func SubjectNodeID(clusterKey, apiGroup, kind, namespace, name string) NodeID {
	return NodeID(stableID("subject", clusterKey, apiGroup, kind, namespace, name))
}

func APIResourceNodeID(clusterKey, apiGroup, resource, scope, namespace string, resourceNames []string) NodeID {
	names := append([]string(nil), resourceNames...)
	sort.Strings(names)
	unique := names[:0]
	for _, name := range names {
		if len(unique) == 0 || unique[len(unique)-1] != name {
			unique = append(unique, name)
		}
	}
	return NodeID(stableID("api-resource", clusterKey, apiGroup, resource, scope, namespace, strings.Join(unique, "\x00")))
}

func StableEdgeID(from NodeID, edgeType EdgeType, to NodeID, discriminator string) EdgeID {
	return EdgeID(stableID("edge", string(from), string(edgeType), string(to), discriminator))
}

func stableID(prefix string, parts ...string) string {
	values := append([]string{identityVersion, prefix}, parts...)
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return fmt.Sprintf("%s:%x", prefix, sum[:16])
}
