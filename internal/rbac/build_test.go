package rbac_test

import (
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rbac"
)

func TestBuildCreatesEffectiveSubjectBindingRolePermissionChain(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		Roles: []domain.Role{{
			Metadata: domain.Metadata{Name: "secret-reader", Namespace: "team-a", UID: "role-uid"},
			Rules:    []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		}},
		RoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "read-secrets", Namespace: "team-a", UID: "binding-uid"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader"},
			Subjects: []domain.Subject{{Kind: "ServiceAccount", Namespace: "team-a", Name: "app"}},
		}},
	}
	model := rbac.Build(state)
	if len(model.Assignments) != 1 {
		t.Fatalf("assignments = %d, want 1", len(model.Assignments))
	}
	assignment := model.Assignments[0]
	if !assignment.SubjectValid || assignment.Subject.Namespace != "team-a" || assignment.Subject.DisplayName() != "team-a/app" {
		t.Errorf("subject = %#v", assignment.Subject)
	}
	if assignment.Scope != rbac.ScopeNamespace || assignment.Namespace != "team-a" {
		t.Errorf("scope = %q namespace = %q", assignment.Scope, assignment.Namespace)
	}
	if !assignment.RoleResolved || assignment.Role.Kind != "Role" || assignment.Role.Namespace != "team-a" {
		t.Errorf("role relationship = %#v, resolved = %t", assignment.Role, assignment.RoleResolved)
	}
	if len(assignment.Permissions) != 1 || !assignment.Permissions[0].Allows("", "secrets", "get") {
		t.Errorf("permissions = %#v", assignment.Permissions)
	}
}

func TestBuildDoesNotDefaultMalformedServiceAccountNamespace(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		Roles: []domain.Role{{Metadata: domain.Metadata{Name: "reader", Namespace: "team-a"}}},
		RoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "reader", Namespace: "team-a"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "reader"},
			Subjects: []domain.Subject{{Kind: "ServiceAccount", Name: "app"}},
		}},
	}
	if assignment := rbac.Build(state).Assignments[0]; assignment.Subject.Namespace != "" || assignment.SubjectValid {
		t.Fatalf("malformed ServiceAccount was treated as valid: %#v", assignment)
	}
}

func TestBuildDoesNotResolveInvalidRoleRefAPIGroup(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		Roles: []domain.Role{{Metadata: domain.Metadata{Name: "reader", Namespace: "team-a"}}},
		RoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "reader", Namespace: "team-a"},
			RoleRef:  domain.RoleReference{APIGroup: "example.com", Kind: "Role", Name: "reader"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}},
		}},
	}
	if assignment := rbac.Build(state).Assignments[0]; assignment.RoleResolved {
		t.Fatalf("invalid roleRef resolved: %#v", assignment)
	}
}

func TestRoleBindingToClusterRoleRemainsNamespaceScoped(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		ClusterRoles: []domain.Role{{Metadata: domain.Metadata{Name: "pod-admin"}, Rules: []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}}}},
		RoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "pod-admin", Namespace: "team-a"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-admin"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}},
		}},
	}
	assignment := rbac.Build(state).Assignments[0]
	if assignment.Scope != rbac.ScopeNamespace || assignment.Role.Namespace != "" || assignment.Binding.Kind != "RoleBinding" {
		t.Fatalf("assignment = %#v", assignment)
	}
}

func TestClusterRoleBindingCreatesClusterScopedAssignmentsForEverySubject(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		ClusterRoles: []domain.Role{{Metadata: domain.Metadata{Name: "view"}, Rules: []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}},
		ClusterRoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "view"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "zara"}, {APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "developers"}},
		}},
	}
	assignments := rbac.Build(state).Assignments
	if len(assignments) != 2 {
		t.Fatalf("assignments = %d, want 2", len(assignments))
	}
	for _, assignment := range assignments {
		if assignment.Scope != rbac.ScopeCluster || assignment.Binding.Kind != "ClusterRoleBinding" || !assignment.RoleResolved {
			t.Errorf("assignment = %#v", assignment)
		}
	}
	if assignments[0].Subject.Kind != "Group" || assignments[1].Subject.Kind != "User" {
		t.Errorf("assignments are not deterministic: %#v", assignments)
	}
}

func TestBuildRetainsDanglingRoleRelationshipWithoutInventingPermissions(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{RoleBindings: []domain.RoleBinding{{
		Metadata: domain.Metadata{Name: "missing", Namespace: "team-a"},
		RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "missing"},
		Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}},
	}}}
	assignment := rbac.Build(state).Assignments[0]
	if assignment.RoleResolved || len(assignment.Permissions) != 0 {
		t.Fatalf("dangling assignment = %#v", assignment)
	}
}

func TestBuildExpandsAggregatedClusterRolesAndStopsCycles(t *testing.T) {
	t.Parallel()

	state := domain.ClusterState{
		ClusterRoles: []domain.Role{
			{
				Metadata:        domain.Metadata{Name: "aggregate", Labels: map[string]string{"cycle": "a"}},
				AggregationRule: []domain.LabelSelector{{MatchLabels: map[string]string{"aggregate": "true"}}},
			},
			{
				Metadata:        domain.Metadata{Name: "secret-reader", Labels: map[string]string{"aggregate": "true", "cycle": "b"}},
				Rules:           []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
				AggregationRule: []domain.LabelSelector{{MatchExpressions: []domain.LabelSelectorRequirement{{Key: "cycle", Operator: "In", Values: []string{"a"}}}}},
			},
		},
		ClusterRoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "aggregate"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "aggregate"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}},
		}},
	}
	assignment := rbac.Build(state).Assignments[0]
	if len(assignment.Permissions) != 1 || !assignment.Permissions[0].Allows("", "secrets", "get") || assignment.Permissions[0].Sources[0].Role.Name != "secret-reader" {
		t.Fatalf("aggregated permissions = %#v", assignment.Permissions)
	}
}

func TestBuildPreservesEverySourceOfDuplicateAggregatedPermission(t *testing.T) {
	t.Parallel()

	sharedRule := domain.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}
	state := domain.ClusterState{
		ClusterRoles: []domain.Role{
			{Metadata: domain.Metadata{Name: "aggregate"}, AggregationRule: []domain.LabelSelector{{MatchLabels: map[string]string{"aggregate": "true"}}}},
			{Metadata: domain.Metadata{Name: "reader-a", Labels: map[string]string{"aggregate": "true"}}, Rules: []domain.PolicyRule{sharedRule}},
			{Metadata: domain.Metadata{Name: "reader-b", Labels: map[string]string{"aggregate": "true"}}, Rules: []domain.PolicyRule{sharedRule}},
		},
		ClusterRoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "aggregate"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "aggregate"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}},
		}},
	}
	permission := rbac.Build(state).Assignments[0].Permissions[0]
	if len(permission.Sources) != 2 || permission.Sources[0].Role.Name != "reader-a" || permission.Sources[1].Role.Name != "reader-b" {
		t.Fatalf("permission sources = %#v", permission.Sources)
	}
}

func TestPermissionSubresourceAndWildcardSemantics(t *testing.T) {
	t.Parallel()

	permission := rbac.Permission{APIGroups: []string{"*"}, Resources: []string{"pods/*"}, Verbs: []string{"create"}}
	if !permission.Allows("", "pods/exec", "create") || !permission.Allows("apps", "pods/attach", "create") {
		t.Fatalf("permission did not match wildcard subresources")
	}
	if permission.Allows("", "pods", "create") {
		t.Fatal("pods/* incorrectly matched the parent pods resource")
	}
	uppercase := rbac.Permission{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"CREATE"}}
	if uppercase.Allows("", "pods", "create") {
		t.Fatal("RBAC verbs must use Kubernetes case-sensitive matching")
	}
}
