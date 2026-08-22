package collectors

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
		domain.KindNamespaces:                        2,
		domain.KindPods:                              2,
		domain.KindDeployments:                       1,
		domain.KindStatefulSets:                      1,
		domain.KindDaemonSets:                        1,
		domain.KindServices:                          1,
		domain.KindIngresses:                         1,
		domain.KindServiceAccounts:                   1,
		domain.KindRoles:                             1,
		domain.KindClusterRoles:                      1,
		domain.KindRoleBindings:                      1,
		domain.KindClusterRoleBindings:               1,
		domain.KindNetworkPolicies:                   1,
		domain.KindValidatingAdmissionPolicies:       1,
		domain.KindValidatingAdmissionPolicyBindings: 1,
		domain.KindValidatingWebhookConfigurations:   1,
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
	if mounts := state.Pods[0].Spec.Containers[0].VolumeMounts; len(mounts) != 1 || mounts[0].Name != "host" || mounts[0].MountPath != "/host" || !mounts[0].ReadOnly {
		t.Errorf("volume mounts were not normalized: %#v", mounts)
	}
	if got := state.Deployments[0].Template.Spec.Containers[0].Image; got != "example/app:1" {
		t.Errorf("deployment container image = %q", got)
	}
	container := state.Pods[0].Spec.Containers[0]
	if len(container.SecretEnvironmentVariables) != 1 || container.SecretEnvironmentVariables[0].Index != 2 || container.SecretEnvironmentVariables[0].SecretName != "database" || container.SecretEnvironmentVariables[0].SecretKey != "password" {
		t.Errorf("secret environment variable references were not normalized: %#v", container.SecretEnvironmentVariables)
	}
	if len(container.SecretEnvironmentSources) != 1 || container.SecretEnvironmentSources[0].Index != 1 || container.SecretEnvironmentSources[0].SecretName != "application-secrets" {
		t.Errorf("secret envFrom references were not normalized: %#v", container.SecretEnvironmentSources)
	}
	if strings.Contains(fmt.Sprintf("%#v", state), "literal-secret-canary") {
		t.Fatal("normalized state retained a literal environment value")
	}
	if got := state.NetworkPolicies[0].PodSelector.MatchLabels["app"]; got != "demo" {
		t.Errorf("network policy selector app = %q", got)
	}
	if got := state.ValidatingAdmissionPolicies[0].FailurePolicy; got != "Ignore" {
		t.Errorf("validating admission policy failure policy = %q", got)
	}
	if got := state.ValidatingAdmissionPolicyBindings[0].ValidationActions; len(got) != 2 || got[0] != "Audit" || got[1] != "Warn" {
		t.Errorf("validating admission policy binding actions = %#v", got)
	}
	if got := state.ValidatingWebhookConfigurations[0].Webhooks; len(got) != 1 || got[0].Name != "security.example.com" || got[0].FailurePolicy != "Ignore" {
		t.Errorf("validating webhook configuration = %#v", got)
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
	if len(state.ValidatingAdmissionPolicies) != 1 || len(state.ValidatingAdmissionPolicyBindings) != 1 || len(state.ValidatingWebhookConfigurations) != 1 {
		t.Fatalf("cluster-scoped admission inventory was filtered: policies=%d bindings=%d webhooks=%d", len(state.ValidatingAdmissionPolicies), len(state.ValidatingAdmissionPolicyBindings), len(state.ValidatingWebhookConfigurations))
	}
}

func TestClusterCollectorTreatsUnavailableVAPAPIAsUnsupportedCapability(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"}, "")
	})

	state, err := NewClusterCollector().Collect(context.Background(), client, domain.ClusterMetadata{}, Scope{})
	if err != nil {
		t.Fatalf("Collect() error = %v, want unavailable optional API to be tolerated", err)
	}
	if _, found := state.Collections[domain.KindValidatingAdmissionPolicies]; found {
		t.Fatalf("collection metadata claims unavailable VAP API was collected: %#v", state.Collections)
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
		Env: []corev1.EnvVar{
			{Name: "INLINE_PASSWORD", Value: "literal-secret-canary"},
			{Name: "CONFIG", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "application-config"}, Key: "setting"}}},
			{Name: "DATABASE_PASSWORD", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "database"}, Key: "password"}}},
		},
		EnvFrom: []corev1.EnvFromSource{
			{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "application-config"}}},
			{Prefix: "APP_", SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "application-secrets"}}},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: "host", MountPath: "/host", ReadOnly: true}},
		SecurityContext: &corev1.SecurityContext{
			Privileged: privileged,
		},
	}}, Volumes: []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}}}}
	ignore := admissionv1.Ignore
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
		&admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: "required-labels"}, Spec: admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &ignore}},
		&admissionv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: "required-labels-audit"}, Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "required-labels", ValidationActions: []admissionv1.ValidationAction{admissionv1.Audit, admissionv1.Warn}}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "security-policy"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "security.example.com", FailurePolicy: &ignore}}},
	}
}
