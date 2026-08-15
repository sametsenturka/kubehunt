package collectors

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

func TestClusterCollectorCollectsAndNormalizesInventory(t *testing.T) {
	t.Parallel()

	privileged := true
	client := fake.NewSimpleClientset(inventoryObjects(&privileged)...)
	collector := NewClusterCollector()
	state, err := collector.Collect(context.Background(), client, domain.ClusterMetadata{Name: "test-cluster"}, Scope{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	expectedCounts := map[domain.ResourceKind]int{
		domain.KindNamespaces:          2,
		domain.KindPods:                2,
		domain.KindDeployments:         1,
		domain.KindStatefulSets:        1,
		domain.KindDaemonSets:          1,
		domain.KindServices:            1,
		domain.KindIngresses:           1,
		domain.KindServiceAccounts:     1,
		domain.KindRoles:               1,
		domain.KindClusterRoles:        1,
		domain.KindRoleBindings:        1,
		domain.KindClusterRoleBindings: 1,
		domain.KindNetworkPolicies:     1,
	}
	for kind, expected := range expectedCounts {
		if actual := state.Count(kind); actual != expected {
			t.Errorf("Count(%s) = %d, want %d", kind, actual, expected)
		}
		metadata, ok := state.Collections[kind]
		if !ok {
			t.Errorf("collection metadata missing for %s", kind)
		} else if metadata.Count != expected {
			t.Errorf("collection metadata count for %s = %d, want %d", kind, metadata.Count, expected)
		}
	}

	if got := state.Pods[0].Metadata.Name; got != "pod-a" {
		t.Errorf("pods are not deterministically sorted, first = %q", got)
	}
	if got := state.Pods[0].Spec.Containers[0].SecurityContext.Privileged; got == nil || !*got {
		t.Errorf("privileged setting was not normalized: %#v", got)
	}
	if got := state.Deployments[0].Template.Spec.Containers[0].Image; got != "example/app:1" {
		t.Errorf("deployment container image = %q", got)
	}
	if got := state.NetworkPolicies[0].PodSelector.MatchLabels["app"]; got != "demo" {
		t.Errorf("network policy selector app = %q", got)
	}
}

func TestClusterCollectorFiltersNamespacedResources(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset(inventoryObjects(nil)...)
	state, err := NewClusterCollector().Collect(context.Background(), client, domain.ClusterMetadata{Name: "test-cluster"}, Scope{Namespaces: []string{"team-a"}})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if len(state.Namespaces) != 1 || state.Namespaces[0].Metadata.Name != "team-a" {
		t.Fatalf("namespaces = %#v, want only team-a", state.Namespaces)
	}
	if len(state.Pods) != 1 || state.Pods[0].Metadata.Namespace != "team-a" {
		t.Fatalf("pods = %#v, want only team-a pod", state.Pods)
	}
	if len(state.ClusterRoles) != 1 {
		t.Fatalf("cluster roles = %d, want cluster-scoped inventory to remain included", len(state.ClusterRoles))
	}
}

func TestClusterCollectorReturnsContextualCollectionErrors(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("access denied")
	})

	_, err := NewClusterCollector().Collect(context.Background(), client, domain.ClusterMetadata{}, Scope{})
	if err == nil {
		t.Fatal("Collect() error = nil, want collection error")
	}
	if !strings.Contains(err.Error(), "collect Pods") || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("Collect() error = %q, want resource and cause", err)
	}
}

func inventoryObjects(privileged *bool) []runtime.Object {
	selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}
	podSpec := corev1.PodSpec{Containers: []corev1.Container{{
		Name:  "app",
		Image: "example/app:1",
		SecurityContext: &corev1.SecurityContext{
			Privileged: privileged,
		},
	}}}
	return []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-b"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "team-b"}, Spec: podSpec},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "team-a"}, Spec: podSpec},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deploy", Namespace: "team-a"}, Spec: appsv1.DeploymentSpec{Selector: &selector, Template: corev1.PodTemplateSpec{Spec: podSpec}}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "stateful", Namespace: "team-a"}, Spec: appsv1.StatefulSetSpec{Selector: &selector, Template: corev1.PodTemplateSpec{Spec: podSpec}}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "team-a"}, Spec: appsv1.DaemonSetSpec{Selector: &selector, Template: corev1.PodTemplateSpec{Spec: podSpec}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "service", Namespace: "team-a"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "demo"}}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "team-a"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "scanner", Namespace: "team-a"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "team-a"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "cluster-reader"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "team-a"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "cluster-reader"}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "team-a"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: selector}},
	}
}
