package rbac

import (
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

type Scope string

const (
	ScopeNamespace Scope = "namespace"
	ScopeCluster   Scope = "cluster"
)

type SubjectRef struct {
	APIGroup  string
	Kind      string
	Namespace string
	Name      string
}

func (subject SubjectRef) Key() string {
	return strings.Join([]string{subject.APIGroup, subject.Kind, subject.Namespace, subject.Name}, "\x00")
}

func (subject SubjectRef) DisplayName() string {
	if subject.Kind == "ServiceAccount" && subject.Namespace != "" {
		return subject.Namespace + "/" + subject.Name
	}
	return subject.Name
}

type Permission struct {
	APIGroups       []string
	Resources       []string
	Verbs           []string
	ResourceNames   []string
	NonResourceURLs []string
	Sources         []PermissionSource
}

type PermissionSource struct {
	Role      domain.ResourceReference
	RuleIndex int
}

func (permission Permission) Allows(apiGroup, resource, verb string) bool {
	return matches(permission.APIGroups, apiGroup) && resourceMatches(permission.Resources, resource) && matches(permission.Verbs, verb)
}

func (permission Permission) AllowsVerb(verb string) bool {
	return matches(permission.Verbs, verb)
}

func (permission Permission) HasWildcardVerb() bool {
	return contains(permission.Verbs, "*")
}

func (permission Permission) HasWildcardResource() bool {
	return contains(permission.Resources, "*")
}

func (permission Permission) HasWildcardAPIGroup() bool {
	return contains(permission.APIGroups, "*")
}

func (permission Permission) IsFullyWildcard() bool {
	return permission.HasWildcardVerb() && permission.HasWildcardResource() && permission.HasWildcardAPIGroup()
}

func (permission Permission) Canonical() string {
	parts := []string{
		"apiGroups=" + canonicalList(permission.APIGroups),
		"resources=" + canonicalList(permission.Resources),
		"verbs=" + canonicalList(permission.Verbs),
	}
	if len(permission.ResourceNames) > 0 {
		parts = append(parts, "resourceNames="+canonicalList(permission.ResourceNames))
	}
	if len(permission.NonResourceURLs) > 0 {
		parts = append(parts, "nonResourceURLs="+canonicalList(permission.NonResourceURLs))
	}
	return strings.Join(parts, ";")
}

type Assignment struct {
	Subject      SubjectRef
	SubjectValid bool
	Binding      domain.ResourceReference
	Role         domain.ResourceReference
	Scope        Scope
	Namespace    string
	RoleResolved bool
	Permissions  []Permission
}

type Model struct {
	Assignments []Assignment
}

func matches(values []string, wanted string) bool {
	return contains(values, "*") || contains(values, wanted)
}

func resourceMatches(resources []string, wanted string) bool {
	for _, resource := range resources {
		if resource == "*" || resource == wanted {
			return true
		}
		if strings.HasSuffix(resource, "/*") && strings.HasPrefix(wanted, strings.TrimSuffix(resource, "*")) {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func canonicalList(values []string) string {
	copied := append([]string(nil), values...)
	sort.Strings(copied)
	unique := copied[:0]
	for _, value := range copied {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return "[" + strings.Join(unique, ",") + "]"
}
