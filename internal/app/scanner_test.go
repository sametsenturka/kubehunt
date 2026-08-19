package app

import (
	"context"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

func TestNewScannerRegistersK01AndK02Rules(t *testing.T) {
	t.Parallel()

	trueValue := true
	state := domain.ClusterState{
		Pods: []domain.Pod{{
			Metadata: domain.Metadata{Name: "privileged", Namespace: "team-a"},
			Spec: domain.PodSpec{Containers: []domain.Container{{
				Name: "app", SecurityContext: domain.ContainerSecurityContext{Privileged: &trueValue},
			}}},
		}},
		ClusterRoles: []domain.Role{{
			Metadata: domain.Metadata{Name: "secret-reader"},
			Rules:    []domain.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		}},
		ClusterRoleBindings: []domain.RoleBinding{{
			Metadata: domain.Metadata{Name: "secret-reader"},
			RoleRef:  domain.RoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "secret-reader"},
			Subjects: []domain.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}},
		}},
	}
	scanner := NewScanner()
	if scanner.InitializationError != nil {
		t.Fatalf("NewScanner() initialization error = %v", scanner.InitializationError)
	}
	findings, err := scanner.Rules.Evaluate(context.Background(), state)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	wanted := map[string]bool{"KSCAN-K01-001": false, "KSCAN-K02-003": false}
	for _, finding := range findings {
		if _, exists := wanted[finding.RuleID]; exists {
			wanted[finding.RuleID] = true
		}
	}
	for id, found := range wanted {
		if !found {
			t.Errorf("registered catalog did not produce %s", id)
		}
	}
}
