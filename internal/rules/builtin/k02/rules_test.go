package k02_test

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/kube/collectors"
	"github.com/sametsenturka/kubehunt/internal/rules"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k02"
	"github.com/sametsenturka/kubehunt/internal/rules/engine"
)

func TestEveryK02RuleHasCompleteMetadata(t *testing.T) {
	t.Parallel()

	registered := k02.Rules()
	if len(registered) != 11 {
		t.Fatalf("Rules() count = %d, want 11", len(registered))
	}
	for _, rule := range registered {
		metadata := rule.Metadata()
		if metadata.ID == "" || metadata.Version == "" || metadata.Title == "" || metadata.Description == "" || metadata.Remediation == "" || metadata.DefaultSeverity == "" {
			t.Errorf("rule has incomplete metadata: %#v", metadata)
		}
		if len(metadata.AffectedResourceTypes) != 4 || len(metadata.RequiredCapabilities) != 4 {
			t.Errorf("rule %s has incomplete RBAC applicability metadata", metadata.ID)
		}
		if len(metadata.OWASPMappings) != 1 || metadata.OWASPMappings[0].Type != rules.MappingPrimary || metadata.OWASPMappings[0].Category.ID != "K02" {
			t.Errorf("rule %s mappings = %#v", metadata.ID, metadata.OWASPMappings)
		}
	}
	if _, err := engine.New(registered...); err != nil {
		t.Fatalf("rule catalog validation failed: %v", err)
	}
}

func TestK02RulesPositiveAndNegative(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id       string
		roleName string
		positive rbacv1.PolicyRule
		negative rbacv1.PolicyRule
	}{
		{"KSCAN-K02-001", "cluster-admin", policy([]string{"*"}, []string{"*"}, []string{"*"}), policy([]string{""}, []string{"pods"}, []string{"get"})},
		{"KSCAN-K02-002", "custom", policy([]string{""}, []string{"configmaps"}, []string{"*"}), policy([]string{""}, []string{"configmaps"}, []string{"get"})},
		{"KSCAN-K02-003", "custom", policy([]string{""}, []string{"secrets"}, []string{"get"}), policy([]string{""}, []string{"configmaps"}, []string{"get"})},
		{"KSCAN-K02-004", "custom", policy([]string{""}, []string{"pods/exec"}, []string{"create"}), policy([]string{""}, []string{"pods"}, []string{"create"})},
		{"KSCAN-K02-005", "custom", policy([]string{""}, []string{"pods/attach"}, []string{"create"}), policy([]string{""}, []string{"pods/log"}, []string{"get"})},
		{"KSCAN-K02-006", "custom", policy([]string{""}, []string{"pods"}, []string{"create"}), policy([]string{""}, []string{"pods"}, []string{"get"})},
		{"KSCAN-K02-007", "custom", policy([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}), policy([]string{""}, []string{"serviceaccounts"}, []string{"get"})},
		{"KSCAN-K02-008", "custom", policy([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}), policy([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"get"})},
		{"KSCAN-K02-009", "custom", policy([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}), policy([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"get"})},
		{"KSCAN-K02-010", "custom", policy([]string{""}, []string{"users"}, []string{"impersonate"}), policy([]string{""}, []string{"users"}, []string{"get"})},
		{"KSCAN-K02-011", "custom", policy([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"patch"}), policy([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"get"})},
	}

	for _, test := range tests {
		test := test
		t.Run(test.id, func(t *testing.T) {
			t.Parallel()
			positive := clusterState(t, clusterGrant(test.roleName, user("alice"), test.positive)...)
			if findings := evaluateRule(t, test.id, positive); len(findings) != 1 {
				t.Errorf("positive findings = %#v, want one", findings)
			}
			negative := clusterState(t, clusterGrant(test.roleName, user("alice"), test.negative)...)
			if findings := evaluateRule(t, test.id, negative); len(findings) != 0 {
				t.Errorf("negative findings = %#v, want none", findings)
			}
		})
	}
}

func TestWildcardRuleAnalyzesEachWildcardDimension(t *testing.T) {
	t.Parallel()

	tests := []rbacv1.PolicyRule{
		policy([]string{""}, []string{"configmaps"}, []string{"*"}),
		policy([]string{""}, []string{"*"}, []string{"get"}),
		policy([]string{"*"}, []string{"configmaps"}, []string{"get"}),
	}
	for index, policyRule := range tests {
		state := clusterState(t, clusterGrant("custom", user("alice"), policyRule)...)
		if findings := evaluateRule(t, "KSCAN-K02-002", state); len(findings) != 1 {
			t.Errorf("wildcard case %d findings = %#v", index, findings)
		}
	}
}

func TestEffectiveWildcardPermissionsTriggerSpecificRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id        string
		apiGroups []string
		resources []string
		verbs     []string
	}{
		{"KSCAN-K02-003", []string{"*"}, []string{"secrets"}, []string{"*"}},
		{"KSCAN-K02-004", []string{""}, []string{"pods/*"}, []string{"create"}},
		{"KSCAN-K02-005", []string{""}, []string{"pods/*"}, []string{"create"}},
		{"KSCAN-K02-006", []string{""}, []string{"pods"}, []string{"*"}},
		{"KSCAN-K02-007", []string{""}, []string{"serviceaccounts/*"}, []string{"*"}},
		{"KSCAN-K02-008", []string{"*"}, []string{"roles"}, []string{"*"}},
		{"KSCAN-K02-009", []string{"*"}, []string{"clusterroles"}, []string{"*"}},
		{"KSCAN-K02-010", []string{"*"}, []string{"groups"}, []string{"*"}},
		{"KSCAN-K02-011", []string{"*"}, []string{"rolebindings"}, []string{"*"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.id, func(t *testing.T) {
			t.Parallel()
			state := clusterState(t, clusterGrant("custom", user("alice"), policy(test.apiGroups, test.resources, test.verbs))...)
			if findings := evaluateRule(t, test.id, state); len(findings) != 1 {
				t.Fatalf("findings = %#v, want one effective wildcard finding", findings)
			}
		})
	}
}

func TestSecretReadCoversGetListAndWatchWithoutDuplicateFindings(t *testing.T) {
	t.Parallel()

	for _, verbs := range [][]string{{"get"}, {"list"}, {"watch"}, {"get", "list", "watch"}} {
		state := clusterState(t, clusterGrant("secret-reader", user("alice"), policy([]string{""}, []string{"secrets"}, verbs))...)
		if findings := evaluateRule(t, "KSCAN-K02-003", state); len(findings) != 1 {
			t.Errorf("verbs %v produced findings %#v", verbs, findings)
		}
	}
}

func TestNamespaceBindingDoesNotInventClusterScopedPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id        string
		apiGroups []string
		resources []string
		verbs     []string
	}{
		{"KSCAN-K02-008", []string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}},
		{"KSCAN-K02-009", []string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"}},
		{"KSCAN-K02-010", []string{""}, []string{"users"}, []string{"impersonate"}},
		{"KSCAN-K02-011", []string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.id, func(t *testing.T) {
			t.Parallel()
			state := clusterState(t, namespacedClusterRoleGrant("team-a", "custom", user("alice"), policy(test.apiGroups, test.resources, test.verbs))...)
			if findings := evaluateRule(t, test.id, state); len(findings) != 0 {
				t.Fatalf("namespace binding produced cluster-scoped findings: %#v", findings)
			}
		})
	}
}

func TestImpersonationCoversUserExtras(t *testing.T) {
	t.Parallel()

	state := clusterState(t, clusterGrant("impersonator", user("alice"), policy([]string{"authentication.k8s.io"}, []string{"userextras/acme.com/project"}, []string{"impersonate"}))...)
	if findings := evaluateRule(t, "KSCAN-K02-010", state); len(findings) != 1 {
		t.Fatalf("userextras findings = %#v", findings)
	}
}

func TestSeverityAccountsForScopeSubjectAndPrivilegePotential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ruleID   string
		objects  []runtime.Object
		severity domain.Severity
	}{
		{
			name:     "cluster admin cluster scope is critical",
			ruleID:   "KSCAN-K02-001",
			objects:  clusterGrant("cluster-admin", user("alice"), policy([]string{"*"}, []string{"*"}, []string{"*"})),
			severity: domain.SeverityCritical,
		},
		{
			name:     "cluster admin through role binding is high",
			ruleID:   "KSCAN-K02-001",
			objects:  namespacedClusterRoleGrant("team-a", "cluster-admin", user("alice"), policy([]string{"*"}, []string{"*"}, []string{"*"})),
			severity: domain.SeverityHigh,
		},
		{
			name:     "single wildcard on ordinary namespaced resource is low",
			ruleID:   "KSCAN-K02-002",
			objects:  namespacedRoleGrant("team-a", "config-reader", user("alice"), policy([]string{""}, []string{"configmaps"}, []string{"*"})),
			severity: domain.SeverityLow,
		},
		{
			name:     "namespaced secret read is medium",
			ruleID:   "KSCAN-K02-003",
			objects:  namespacedRoleGrant("team-a", "secret-reader", user("alice"), policy([]string{""}, []string{"secrets"}, []string{"get"})),
			severity: domain.SeverityMedium,
		},
		{
			name:     "cluster secret read by broad group is high",
			ruleID:   "KSCAN-K02-003",
			objects:  clusterGrant("secret-reader", group("system:authenticated"), policy([]string{""}, []string{"secrets"}, []string{"list"})),
			severity: domain.SeverityHigh,
		},
		{
			name:     "namespaced pod creation is high",
			ruleID:   "KSCAN-K02-006",
			objects:  namespacedRoleGrant("team-a", "pod-creator", user("alice"), policy([]string{""}, []string{"pods"}, []string{"create"})),
			severity: domain.SeverityHigh,
		},
		{
			name:     "cluster escalation by broad group is critical",
			ruleID:   "KSCAN-K02-009",
			objects:  clusterGrant("escalator", group("system:authenticated"), policy([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"})),
			severity: domain.SeverityCritical,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := evaluateRule(t, test.ruleID, clusterState(t, test.objects...))
			if len(findings) != 1 || findings[0].Severity != test.severity {
				t.Fatalf("findings = %#v, want severity %s", findings, test.severity)
			}
		})
	}
}

func TestResourceNamesRestrictionIsPreserved(t *testing.T) {
	t.Parallel()

	secretRule := policy([]string{""}, []string{"secrets"}, []string{"get"})
	secretRule.ResourceNames = []string{"database-password"}
	findings := evaluateRule(t, "KSCAN-K02-003", clusterState(t, namespacedRoleGrant("team-a", "named-secret", user("alice"), secretRule)...))
	if len(findings) != 1 || findings[0].Severity != domain.SeverityMedium || findings[0].Evidence[2].Value == "" {
		t.Fatalf("named Secret findings = %#v", findings)
	}

	podCreate := policy([]string{""}, []string{"pods"}, []string{"create"})
	podCreate.ResourceNames = []string{"named-pod"}
	if findings := evaluateRule(t, "KSCAN-K02-006", clusterState(t, namespacedRoleGrant("team-a", "invalid-create", user("alice"), podCreate)...)); len(findings) != 0 {
		t.Fatalf("create with resourceNames cannot authorize an unnamed create request: %#v", findings)
	}

	tokenCreate := policy([]string{""}, []string{"serviceaccounts/token"}, []string{"create"})
	tokenCreate.ResourceNames = []string{"deployer"}
	if findings := evaluateRule(t, "KSCAN-K02-007", clusterState(t, namespacedRoleGrant("team-a", "named-token", user("alice"), tokenCreate)...)); len(findings) != 1 {
		t.Fatalf("named ServiceAccount token creation should remain effective: %#v", findings)
	}

	rbacCreate := policy([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"})
	rbacCreate.ResourceNames = []string{"named-binding"}
	if findings := evaluateRule(t, "KSCAN-K02-011", clusterState(t, namespacedRoleGrant("team-a", "invalid-rbac-create", user("alice"), rbacCreate)...)); len(findings) != 0 {
		t.Fatalf("RBAC create with resourceNames cannot authorize an unnamed create request: %#v", findings)
	}
}

func TestDanglingBindingDoesNotCreateEffectivePermissionFinding(t *testing.T) {
	t.Parallel()

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "team-a"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "missing"},
		Subjects:   []rbacv1.Subject{user("alice")},
	}
	state := clusterState(t, binding)
	for _, rule := range k02.Rules() {
		if findings := evaluateRule(t, rule.Metadata().ID, state); len(findings) != 0 {
			t.Errorf("%s produced dangling-role findings: %#v", rule.Metadata().ID, findings)
		}
	}
}

func TestClusterAdminAndFullyWildcardGrantsAreCondensed(t *testing.T) {
	t.Parallel()

	allRules, err := engine.New(k02.Rules()...)
	if err != nil {
		t.Fatalf("engine.New(): %v", err)
	}
	clusterAdminState := clusterState(t, clusterGrant("cluster-admin", user("alice"), policy([]string{"*"}, []string{"*"}, []string{"*"}))...)
	findings, err := allRules.Evaluate(context.Background(), clusterAdminState)
	if err != nil {
		t.Fatalf("Evaluate(): %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "KSCAN-K02-001" {
		t.Fatalf("cluster-admin findings = %#v", findings)
	}

	wildcardState := clusterState(t, clusterGrant("custom-admin", user("alice"), policy([]string{"*"}, []string{"*"}, []string{"*"}))...)
	findings, err = allRules.Evaluate(context.Background(), wildcardState)
	if err != nil {
		t.Fatalf("Evaluate(): %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "KSCAN-K02-002" {
		t.Fatalf("fully wildcard findings = %#v", findings)
	}
}

func TestFindingEvidenceContainsEffectiveRelationshipChain(t *testing.T) {
	t.Parallel()

	state := clusterState(t, namespacedRoleGrant("team-a", "secret-reader", serviceAccount("team-a", "api"), policy([]string{""}, []string{"secrets"}, []string{"get"}))...)
	findings := evaluateRule(t, "KSCAN-K02-003", state)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	finding := findings[0]
	if finding.Resource.Kind != "RoleBinding" || finding.Resource.Namespace != "team-a" || len(finding.Evidence) != 3 {
		t.Fatalf("finding relationship evidence = %#v", finding)
	}
	if finding.Evidence[0].Value != "/ServiceAccount/team-a/api" || finding.Evidence[1].Value != "Role/team-a/secret-reader" {
		t.Errorf("finding relationship values = %#v", finding.Evidence)
	}
}

func evaluateRule(t *testing.T, id string, state domain.ClusterState) []domain.Finding {
	t.Helper()
	for _, rule := range k02.Rules() {
		if rule.Metadata().ID != id {
			continue
		}
		ruleEngine, err := engine.New(rule)
		if err != nil {
			t.Fatalf("engine.New(): %v", err)
		}
		findings, err := ruleEngine.Evaluate(context.Background(), state)
		if err != nil {
			t.Fatalf("Evaluate(): %v", err)
		}
		return findings
	}
	t.Fatalf("rule %s was not registered", id)
	return nil
}

func clusterState(t *testing.T, objects ...runtime.Object) domain.ClusterState {
	t.Helper()
	state, err := collectors.NewClusterCollector().Collect(context.Background(), fake.NewSimpleClientset(objects...), domain.ClusterMetadata{Name: "test"}, collectors.Scope{})
	if err != nil {
		t.Fatalf("collect test state: %v", err)
	}
	return state
}

func clusterGrant(roleName string, subject rbacv1.Subject, policyRules ...rbacv1.PolicyRule) []runtime.Object {
	return []runtime.Object{
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: roleName}, Rules: policyRules},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleName + "-binding"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: roleName},
			Subjects:   []rbacv1.Subject{subject},
		},
	}
}

func namespacedClusterRoleGrant(namespace, roleName string, subject rbacv1.Subject, policyRules ...rbacv1.PolicyRule) []runtime.Object {
	return []runtime.Object{
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: roleName}, Rules: policyRules},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleName + "-binding", Namespace: namespace},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: roleName},
			Subjects:   []rbacv1.Subject{subject},
		},
	}
}

func namespacedRoleGrant(namespace, roleName string, subject rbacv1.Subject, policyRules ...rbacv1.PolicyRule) []runtime.Object {
	return []runtime.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace}, Rules: policyRules},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleName + "-binding", Namespace: namespace},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: roleName},
			Subjects:   []rbacv1.Subject{subject},
		},
	}
}

func policy(apiGroups, resources, verbs []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{APIGroups: apiGroups, Resources: resources, Verbs: verbs}
}

func user(name string) rbacv1.Subject {
	return rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: name}
}

func group(name string) rbacv1.Subject {
	return rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: name}
}

func serviceAccount(namespace, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: namespace, Name: name}
}
