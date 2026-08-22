package k02

import (
	"context"
	"fmt"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rbac"
	"github.com/sametsenturka/kubehunt/internal/rules"
)

var (
	category    = domain.OWASPCategory{ID: "K02", Version: "2025", Title: "Overly Permissive Authorization Configurations"}
	categoryK03 = domain.OWASPCategory{ID: "K03", Version: "2025", Title: "Secrets Management Failures"}
)

type assignmentRule struct {
	metadata rules.Metadata
	evaluate func(context.Context, rbac.Model) []domain.Finding
}

func (rule assignmentRule) Metadata() rules.Metadata { return rule.metadata }

func (rule assignmentRule) Evaluate(ctx context.Context, state domain.ClusterState) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rule.evaluate(ctx, rbac.Build(state)), nil
}

func Rules() []rules.Rule {
	return []rules.Rule{
		newRule("KSCAN-K02-001", "Cluster-admin binding", "A subject receives effective cluster-admin permissions through an RBAC binding.", domain.SeverityCritical, "Remove the cluster-admin binding and replace it with a narrowly scoped Role or ClusterRole containing only required permissions.", evaluateClusterAdmin),
		newRule("KSCAN-K02-002", "Broad wildcard permission", "An effective RBAC permission uses wildcard verbs, resources, or API groups.", domain.SeverityMedium, "Replace wildcard entries with explicit API groups, resources, and verbs required by the subject.", evaluateWildcards),
		withRelatedK03(newPermissionRule("KSCAN-K02-003", "Secret read permission", "A subject can read Secret objects through get, list, watch, or wildcard verbs.", domain.SeverityMedium, "Remove Secret read access or restrict it to the smallest namespace and named Secrets required.", 45, false, matchesSecretRead)),
		newPermissionRule("KSCAN-K02-004", "Pod exec permission", "A subject can execute commands in Pods through the pods/exec subresource.", domain.SeverityHigh, "Remove pods/exec access or restrict it to a dedicated operational identity and namespace.", 55, true, matchesPodExec),
		newPermissionRule("KSCAN-K02-005", "Pod attach permission", "A subject can attach to running container processes through the pods/attach subresource.", domain.SeverityHigh, "Remove pods/attach access or restrict it to a dedicated operational identity and namespace.", 55, true, matchesPodAttach),
		newPermissionRule("KSCAN-K02-006", "Pod creation permission", "A subject can create Pods, which can enable workload-based privilege escalation depending on other controls.", domain.SeverityHigh, "Remove Pod creation access or constrain it to a namespace protected by reviewed admission policies and a narrow workload role.", 55, true, matchesPodCreate),
		newPermissionRule("KSCAN-K02-007", "ServiceAccount token creation permission", "A subject can create ServiceAccount token requests.", domain.SeverityHigh, "Remove create access to serviceaccounts/token and use a narrowly scoped, audited token issuance workflow.", 60, true, matchesServiceAccountTokenCreate),
		newPermissionRule("KSCAN-K02-008", "RBAC bind permission", "A subject can use the RBAC bind verb on Roles or ClusterRoles.", domain.SeverityHigh, "Remove the bind verb unless the subject is a tightly controlled RBAC administrator.", 65, true, matchesBind),
		newPermissionRule("KSCAN-K02-009", "RBAC escalate permission", "A subject can use the RBAC escalate verb on Roles or ClusterRoles.", domain.SeverityHigh, "Remove the escalate verb unless the subject is a tightly controlled RBAC administrator.", 65, true, matchesEscalate),
		newPermissionRule("KSCAN-K02-010", "Identity impersonation permission", "A subject can impersonate Kubernetes users, groups, ServiceAccounts, UIDs, or user extras.", domain.SeverityHigh, "Remove impersonate access or restrict it to explicitly named identities and a tightly controlled administrative workflow.", 65, true, matchesImpersonate),
		newPermissionRule("KSCAN-K02-011", "RBAC object modification permission", "A subject can create, update, patch, or delete RBAC Roles or bindings.", domain.SeverityHigh, "Remove RBAC mutation permissions or isolate them to a tightly controlled administrative identity with least privilege.", 55, true, matchesRBACModification),
	}
}

func newRule(id, title, description string, severity domain.Severity, remediation string, evaluate func(context.Context, rbac.Model) []domain.Finding) assignmentRule {
	return assignmentRule{
		metadata: rules.Metadata{
			ID:                    id,
			Version:               "1.0.0",
			Title:                 title,
			Description:           description,
			DefaultSeverity:       severity,
			AffectedResourceTypes: []string{"RoleBinding", "ClusterRoleBinding", "Role", "ClusterRole"},
			RequiredCapabilities: []domain.CapabilityID{
				domain.CapabilityRolesList,
				domain.CapabilityClusterRolesList,
				domain.CapabilityRoleBindingsList,
				domain.CapabilityClusterRoleBindingsList,
			},
			Remediation: remediation,
			OWASPMappings: []rules.OWASPMapping{{
				TaxonomyID: rules.OWASPTaxonomyID,
				Category:   category,
				Type:       rules.MappingPrimary,
				Rationale:  "The rule identifies an effective native Kubernetes RBAC grant with excessive authorization impact.",
			}},
		},
		evaluate: evaluate,
	}
}

type permissionMatcher func(rbac.Assignment, rbac.Permission) bool

func newPermissionRule(id, title, description string, defaultSeverity domain.Severity, remediation string, baseRisk int, escalationPotential bool, match permissionMatcher) assignmentRule {
	return newRule(id, title, description, defaultSeverity, remediation, func(ctx context.Context, model rbac.Model) []domain.Finding {
		var findings []domain.Finding
		for _, assignment := range model.Assignments {
			if err := ctx.Err(); err != nil {
				return findings
			}
			if !assignment.SubjectValid || !assignment.RoleResolved || isEffectiveClusterAdmin(assignment) {
				continue
			}
			for _, permission := range assignment.Permissions {
				if permission.IsFullyWildcard() || !match(assignment, permission) {
					continue
				}
				findings = append(findings, findingForPermission(assignment, permission, severityFor(baseRisk, escalationPotential, assignment, &permission)))
			}
		}
		return findings
	})
}

func withRelatedK03(rule assignmentRule) assignmentRule {
	rule.metadata.OWASPMappings = append(rule.metadata.OWASPMappings, rules.OWASPMapping{
		TaxonomyID: rules.OWASPTaxonomyID,
		Category:   categoryK03,
		Type:       rules.MappingRelated,
		Rationale:  "The authorization grant can expose Kubernetes Secret contents to the bound subject.",
	})
	return rule
}

func evaluateClusterAdmin(ctx context.Context, model rbac.Model) []domain.Finding {
	var findings []domain.Finding
	for _, assignment := range model.Assignments {
		if ctx.Err() != nil {
			return findings
		}
		if !assignment.SubjectValid || !assignment.RoleResolved || !isEffectiveClusterAdmin(assignment) {
			continue
		}
		permission := fullyWildcardPermission(assignment)
		findings = append(findings, findingForPermission(assignment, permission, severityFor(70, true, assignment, &permission)))
	}
	return findings
}

func evaluateWildcards(ctx context.Context, model rbac.Model) []domain.Finding {
	var findings []domain.Finding
	for _, assignment := range model.Assignments {
		if ctx.Err() != nil {
			return findings
		}
		if !assignment.SubjectValid || !assignment.RoleResolved || isEffectiveClusterAdmin(assignment) {
			continue
		}
		for _, permission := range assignment.Permissions {
			wildcardCount := 0
			if permission.HasWildcardVerb() {
				wildcardCount++
			}
			if permission.HasWildcardResource() {
				wildcardCount++
			}
			if permission.HasWildcardAPIGroup() {
				wildcardCount++
			}
			if wildcardCount == 0 {
				continue
			}
			baseRisk := 25 + ((wildcardCount - 1) * 10)
			if wildcardTouchesSensitiveResource(permission) {
				baseRisk += 10
			}
			findings = append(findings, findingForPermission(assignment, permission, severityFor(baseRisk, wildcardCanEscalate(permission), assignment, &permission)))
		}
	}
	return findings
}

func findingForPermission(assignment rbac.Assignment, permission rbac.Permission, severity domain.Severity) domain.Finding {
	scope := "cluster-wide"
	if assignment.Scope == rbac.ScopeNamespace {
		scope = fmt.Sprintf("namespace %q", assignment.Namespace)
	}
	subjectValue := strings.Join([]string{assignment.Subject.APIGroup, assignment.Subject.Kind, assignment.Subject.Namespace, assignment.Subject.Name}, "/")
	roleValue := assignment.Role.Kind + "/" + assignment.Role.Name
	if assignment.Role.Namespace != "" {
		roleValue = assignment.Role.Kind + "/" + assignment.Role.Namespace + "/" + assignment.Role.Name
	}
	permissionSources := formatPermissionSources(permission.Sources)
	return domain.Finding{
		Severity: severity,
		Resource: assignment.Binding,
		Evidence: []domain.Evidence{
			{
				Field:   fmt.Sprintf("subjects[kind=%s,name=%s]", assignment.Subject.Kind, assignment.Subject.Name),
				Value:   subjectValue,
				Message: fmt.Sprintf("subject %s %q receives %s access", assignment.Subject.Kind, assignment.Subject.DisplayName(), scope),
			},
			{
				Field:   "roleRef",
				Value:   roleValue,
				Message: fmt.Sprintf("binding references %s %q", assignment.Role.Kind, assignment.Role.Name),
			},
			{
				Field:   "effectivePermissions",
				Value:   permission.Canonical(),
				Message: fmt.Sprintf("effective permission from %s: %s", permissionSources, permission.Canonical()),
			},
		},
	}
}

func formatPermissionSources(sources []rbac.PermissionSource) string {
	formatted := make([]string, 0, len(sources))
	for _, source := range sources {
		roleName := source.Role.Name
		if source.Role.Namespace != "" {
			roleName = source.Role.Namespace + "/" + roleName
		}
		formatted = append(formatted, fmt.Sprintf("%s %q rule %d", source.Role.Kind, roleName, source.RuleIndex))
	}
	if len(formatted) == 0 {
		return "unknown source"
	}
	return strings.Join(formatted, ", ")
}

func severityFor(base int, escalationPotential bool, assignment rbac.Assignment, permission *rbac.Permission) domain.Severity {
	score := base
	if assignment.Scope == rbac.ScopeCluster {
		score += 10
	}
	switch assignment.Subject.Kind {
	case "ServiceAccount":
		score += 5
	case "Group":
		if isBroadGroup(assignment.Subject.Name) {
			score += 10
		} else {
			score += 5
		}
	}
	if escalationPotential {
		score += 10
	}
	if permission != nil && len(permission.ResourceNames) > 0 {
		score -= 5
	}
	switch {
	case score >= 85:
		return domain.SeverityCritical
	case score >= 65:
		return domain.SeverityHigh
	case score >= 40:
		return domain.SeverityMedium
	case score >= 20:
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}

func isBroadGroup(name string) bool {
	return name == "system:authenticated" || name == "system:unauthenticated" || name == "system:serviceaccounts" || strings.HasPrefix(name, "system:serviceaccounts:")
}

func isEffectiveClusterAdmin(assignment rbac.Assignment) bool {
	return assignment.Role.Kind == "ClusterRole" && assignment.Role.Name == "cluster-admin" && hasFullyWildcardPermission(assignment)
}

func hasFullyWildcardPermission(assignment rbac.Assignment) bool {
	for _, permission := range assignment.Permissions {
		if permission.IsFullyWildcard() {
			return true
		}
	}
	return false
}

func fullyWildcardPermission(assignment rbac.Assignment) rbac.Permission {
	for _, permission := range assignment.Permissions {
		if permission.IsFullyWildcard() {
			return permission
		}
	}
	return rbac.Permission{}
}

func wildcardTouchesSensitiveResource(permission rbac.Permission) bool {
	if permission.HasWildcardResource() {
		return true
	}
	for _, resource := range []string{"secrets", "pods", "pods/exec", "pods/attach", "serviceaccounts/token", "roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
		for _, configured := range permission.Resources {
			if configured == resource || (strings.HasSuffix(configured, "/*") && strings.HasPrefix(resource, strings.TrimSuffix(configured, "*"))) {
				return true
			}
		}
	}
	return false
}

func wildcardCanEscalate(permission rbac.Permission) bool {
	if !permission.HasWildcardVerb() {
		return false
	}
	return wildcardTouchesSensitiveResource(permission)
}

func matchesSecretRead(_ rbac.Assignment, permission rbac.Permission) bool {
	return allowsAny(permission, "", "secrets", "get", "list", "watch")
}

func matchesPodExec(_ rbac.Assignment, permission rbac.Permission) bool {
	return allowsAny(permission, "", "pods/exec", "create", "get")
}

func matchesPodAttach(_ rbac.Assignment, permission rbac.Permission) bool {
	return allowsAny(permission, "", "pods/attach", "create", "get")
}

func matchesPodCreate(_ rbac.Assignment, permission rbac.Permission) bool {
	return len(permission.ResourceNames) == 0 && permission.Allows("", "pods", "create")
}

func matchesServiceAccountTokenCreate(_ rbac.Assignment, permission rbac.Permission) bool {
	return permission.Allows("", "serviceaccounts/token", "create")
}

func matchesBind(assignment rbac.Assignment, permission rbac.Permission) bool {
	if permission.Allows("rbac.authorization.k8s.io", "roles", "bind") {
		return true
	}
	return assignment.Scope == rbac.ScopeCluster && permission.Allows("rbac.authorization.k8s.io", "clusterroles", "bind")
}

func matchesEscalate(assignment rbac.Assignment, permission rbac.Permission) bool {
	if permission.Allows("rbac.authorization.k8s.io", "roles", "escalate") {
		return true
	}
	return assignment.Scope == rbac.ScopeCluster && permission.Allows("rbac.authorization.k8s.io", "clusterroles", "escalate")
}

func matchesImpersonate(assignment rbac.Assignment, permission rbac.Permission) bool {
	if assignment.Scope != rbac.ScopeCluster {
		return false
	}
	for _, target := range []struct{ apiGroup, resource string }{
		{"", "users"},
		{"", "groups"},
		{"", "serviceaccounts"},
		{"authentication.k8s.io", "uids"},
		{"authentication.k8s.io", "userextras/scopes"},
	} {
		if permission.Allows(target.apiGroup, target.resource, "impersonate") {
			return true
		}
	}
	if !permission.AllowsVerb("impersonate") {
		return false
	}
	apiGroupMatches := false
	for _, apiGroup := range permission.APIGroups {
		if apiGroup == "*" || apiGroup == "authentication.k8s.io" {
			apiGroupMatches = true
			break
		}
	}
	if apiGroupMatches {
		for _, resource := range permission.Resources {
			if strings.HasPrefix(resource, "userextras/") {
				return true
			}
		}
	}
	return false
}

func matchesRBACModification(assignment rbac.Assignment, permission rbac.Permission) bool {
	resources := []string{"roles", "rolebindings"}
	if assignment.Scope == rbac.ScopeCluster {
		resources = append(resources, "clusterroles", "clusterrolebindings")
	}
	for _, resource := range resources {
		if allowsAny(permission, "rbac.authorization.k8s.io", resource, "update", "patch", "delete") {
			return true
		}
		if len(permission.ResourceNames) == 0 && allowsAny(permission, "rbac.authorization.k8s.io", resource, "create", "deletecollection") {
			return true
		}
	}
	return false
}

func allowsAny(permission rbac.Permission, apiGroup, resource string, verbs ...string) bool {
	for _, verb := range verbs {
		if permission.Allows(apiGroup, resource, verb) {
			return true
		}
	}
	return false
}
