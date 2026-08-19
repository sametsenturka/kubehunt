package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

func Build(state domain.ClusterState) Model {
	roles := make(map[string]domain.Role, len(state.Roles))
	for _, role := range state.Roles {
		roles[namespacedKey(role.Metadata.Namespace, role.Metadata.Name)] = role
	}
	clusterRoles := make(map[string]domain.Role, len(state.ClusterRoles))
	for _, role := range state.ClusterRoles {
		clusterRoles[role.Metadata.Name] = role
	}

	model := Model{}
	for _, binding := range state.RoleBindings {
		model.Assignments = append(model.Assignments, assignmentsForBinding(binding, "RoleBinding", ScopeNamespace, roles, clusterRoles)...)
	}
	for _, binding := range state.ClusterRoleBindings {
		model.Assignments = append(model.Assignments, assignmentsForBinding(binding, "ClusterRoleBinding", ScopeCluster, roles, clusterRoles)...)
	}
	sort.SliceStable(model.Assignments, func(left, right int) bool {
		return assignmentKey(model.Assignments[left]) < assignmentKey(model.Assignments[right])
	})
	return model
}

func assignmentsForBinding(binding domain.RoleBinding, bindingKind string, scope Scope, roles, clusterRoles map[string]domain.Role) []Assignment {
	bindingRef := domain.ResourceReference{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       bindingKind,
		Namespace:  binding.Metadata.Namespace,
		Name:       binding.Metadata.Name,
		UID:        binding.Metadata.UID,
	}
	roleRef := domain.ResourceReference{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       binding.RoleRef.Kind,
		Name:       binding.RoleRef.Name,
	}
	var role domain.Role
	resolved := false
	switch {
	case binding.RoleRef.APIGroup != "rbac.authorization.k8s.io":
		// Invalid role references do not create effective permissions.
	case bindingKind == "RoleBinding" && binding.RoleRef.Kind == "Role":
		roleRef.Namespace = binding.Metadata.Namespace
		role, resolved = roles[namespacedKey(binding.Metadata.Namespace, binding.RoleRef.Name)]
	case binding.RoleRef.Kind == "ClusterRole":
		role, resolved = clusterRoles[binding.RoleRef.Name]
	}

	var permissions []Permission
	if resolved {
		permissions = permissionsForRole(role, roleRef, clusterRoles)
	}
	result := make([]Assignment, 0, len(binding.Subjects))
	for _, subject := range binding.Subjects {
		namespace := ""
		if subject.Kind == "ServiceAccount" {
			namespace = subject.Namespace
		}
		subjectRef := SubjectRef{
			APIGroup:  subject.APIGroup,
			Kind:      subject.Kind,
			Namespace: namespace,
			Name:      subject.Name,
		}
		result = append(result, Assignment{
			Subject:      subjectRef,
			SubjectValid: validSubject(subjectRef),
			Binding:      bindingRef,
			Role:         roleRef,
			Scope:        scope,
			Namespace:    binding.Metadata.Namespace,
			RoleResolved: resolved,
			Permissions:  append([]Permission(nil), permissions...),
		})
	}
	return result
}

func validSubject(subject SubjectRef) bool {
	if subject.Name == "" {
		return false
	}
	switch subject.Kind {
	case "ServiceAccount":
		return subject.APIGroup == "" && subject.Namespace != ""
	case "User", "Group":
		return subject.APIGroup == "rbac.authorization.k8s.io" && subject.Namespace == ""
	default:
		return false
	}
}

func permissionsForRole(role domain.Role, boundRef domain.ResourceReference, clusterRoles map[string]domain.Role) []Permission {
	var result []Permission
	seenPermissions := make(map[string]int)
	visiting := make(map[string]bool)
	var expand func(domain.Role, domain.ResourceReference)
	expand = func(current domain.Role, sourceRef domain.ResourceReference) {
		visitKey := sourceRef.Kind + "/" + sourceRef.Namespace + "/" + sourceRef.Name
		if visiting[visitKey] {
			return
		}
		visiting[visitKey] = true
		defer delete(visiting, visitKey)

		for index, policyRule := range current.Rules {
			permission := permissionFromRule(policyRule, sourceRef, index)
			key := permission.Canonical()
			if existing, exists := seenPermissions[key]; exists {
				result[existing].Sources = appendPermissionSources(result[existing].Sources, permission.Sources...)
				continue
			}
			seenPermissions[key] = len(result)
			result = append(result, permission)
		}
		if sourceRef.Kind != "ClusterRole" {
			return
		}
		for _, selector := range current.AggregationRule {
			names := make([]string, 0, len(clusterRoles))
			for name, candidate := range clusterRoles {
				if name != current.Metadata.Name && labelSelectorMatches(selector, candidate.Metadata.Labels) {
					names = append(names, name)
				}
			}
			sort.Strings(names)
			for _, name := range names {
				candidate := clusterRoles[name]
				expand(candidate, domain.ResourceReference{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: name, UID: candidate.Metadata.UID})
			}
		}
	}
	expand(role, boundRef)
	for index := range result {
		sort.SliceStable(result[index].Sources, func(left, right int) bool {
			return permissionSourceKey(result[index].Sources[left]) < permissionSourceKey(result[index].Sources[right])
		})
	}
	return result
}

func permissionFromRule(rule domain.PolicyRule, sourceRole domain.ResourceReference, index int) Permission {
	return Permission{
		APIGroups:       append([]string(nil), rule.APIGroups...),
		Resources:       append([]string(nil), rule.Resources...),
		Verbs:           append([]string(nil), rule.Verbs...),
		ResourceNames:   append([]string(nil), rule.ResourceNames...),
		NonResourceURLs: append([]string(nil), rule.NonResourceURLs...),
		Sources:         []PermissionSource{{Role: sourceRole, RuleIndex: index}},
	}
}

func labelSelectorMatches(selector domain.LabelSelector, labels map[string]string) bool {
	for key, expected := range selector.MatchLabels {
		if labels[key] != expected {
			return false
		}
	}
	for _, expression := range selector.MatchExpressions {
		value, exists := labels[expression.Key]
		switch expression.Operator {
		case "In":
			if !exists || !stringSliceContains(expression.Values, value) {
				return false
			}
		case "NotIn":
			if !exists || stringSliceContains(expression.Values, value) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func stringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func namespacedKey(namespace, name string) string {
	return namespace + "\x00" + name
}

func assignmentKey(assignment Assignment) string {
	return strings.Join([]string{
		assignment.Subject.Key(),
		assignment.Binding.Kind,
		assignment.Binding.Namespace,
		assignment.Binding.Name,
		assignment.Role.Kind,
		assignment.Role.Namespace,
		assignment.Role.Name,
	}, "\x00")
}

func permissionSourceKey(source PermissionSource) string {
	return strings.Join([]string{source.Role.Kind, source.Role.Namespace, source.Role.Name, fmt.Sprint(source.RuleIndex)}, "\x00")
}

func appendPermissionSources(existing []PermissionSource, candidates ...PermissionSource) []PermissionSource {
	seen := make(map[string]struct{}, len(existing)+len(candidates))
	for _, source := range existing {
		seen[permissionSourceKey(source)] = struct{}{}
	}
	for _, source := range candidates {
		key := permissionSourceKey(source)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		existing = append(existing, source)
	}
	return existing
}
