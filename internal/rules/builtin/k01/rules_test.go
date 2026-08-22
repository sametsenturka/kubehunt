package k01_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
	"github.com/sametsenturka/kubehunt/internal/rules/builtin/k01"
	"github.com/sametsenturka/kubehunt/internal/rules/engine"
)

func TestEveryK01RuleHasCompleteMetadata(t *testing.T) {
	t.Parallel()

	registered := k01.Rules()
	if len(registered) != 10 {
		t.Fatalf("Rules() count = %d, want 10", len(registered))
	}
	for _, rule := range registered {
		metadata := rule.Metadata()
		if metadata.ID == "" || metadata.Title == "" || metadata.Description == "" || metadata.Remediation == "" || metadata.DefaultSeverity == "" {
			t.Errorf("rule has incomplete metadata: %#v", metadata)
		}
		if len(metadata.AffectedResourceTypes) != 4 || len(metadata.RequiredCapabilities) == 0 {
			t.Errorf("rule %s has incomplete applicability metadata", metadata.ID)
		}
		if len(metadata.OWASPMappings) == 0 || metadata.OWASPMappings[0].Type != rules.MappingPrimary || metadata.OWASPMappings[0].Category.ID != "K01" {
			t.Errorf("rule %s mappings = %#v", metadata.ID, metadata.OWASPMappings)
		}
		if metadata.ID == "KSCAN-K01-007" {
			if len(metadata.OWASPMappings) != 2 || metadata.OWASPMappings[1].Type != rules.MappingRelated || metadata.OWASPMappings[1].Category.ID != "K05" {
				t.Errorf("host-network rule mappings = %#v, want related K05 mapping", metadata.OWASPMappings)
			}
		} else if len(metadata.OWASPMappings) != 1 {
			t.Errorf("rule %s mappings = %#v, want only primary K01", metadata.ID, metadata.OWASPMappings)
		}
	}
	if _, err := engine.New(registered...); err != nil {
		t.Fatalf("rule catalog validation failed: %v", err)
	}
}

func TestK01RulesPositiveAndNegative(t *testing.T) {
	t.Parallel()

	trueValue, falseValue := true, false
	root, nonRoot := int64(0), int64(1000)
	tests := []struct {
		id       string
		positive domain.PodSpec
		negative domain.PodSpec
	}{
		{
			id:       "KSCAN-K01-001",
			positive: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{Privileged: &trueValue}}),
			negative: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{Privileged: &falseValue}}),
		},
		{
			id:       "KSCAN-K01-002",
			positive: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{RunAsUser: &root}}),
			negative: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{RunAsUser: &nonRoot}}),
		},
		{
			id:       "KSCAN-K01-003",
			positive: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{AllowPrivilegeEscalation: &trueValue}}),
			negative: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{AllowPrivilegeEscalation: &falseValue}}),
		},
		{
			id:       "KSCAN-K01-004",
			positive: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{AddedCapabilities: []string{"SYS_ADMIN"}}}),
			negative: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{AddedCapabilities: []string{"NET_BIND_SERVICE"}}}),
		},
		{
			id:       "KSCAN-K01-005",
			positive: withPodSpec(podSpec(secureContainer()), func(spec *domain.PodSpec) { spec.HostPID = true }),
			negative: podSpec(secureContainer()),
		},
		{
			id:       "KSCAN-K01-006",
			positive: withPodSpec(podSpec(secureContainer()), func(spec *domain.PodSpec) { spec.HostIPC = true }),
			negative: podSpec(secureContainer()),
		},
		{
			id:       "KSCAN-K01-007",
			positive: withPodSpec(podSpec(secureContainer()), func(spec *domain.PodSpec) { spec.HostNetwork = true }),
			negative: podSpec(secureContainer()),
		},
		{
			id: "KSCAN-K01-008",
			positive: domain.PodSpec{
				Containers: []domain.Container{{Name: "app", VolumeMounts: []domain.VolumeMount{{Name: "host", MountPath: "/host"}}}},
				Volumes:    []domain.Volume{{Name: "host", Type: "HostPath", HostPath: "/var/run/docker.sock"}},
			},
			negative: domain.PodSpec{
				Containers: []domain.Container{{Name: "app", VolumeMounts: []domain.VolumeMount{{Name: "host", MountPath: "/data"}}}},
				Volumes:    []domain.Volume{{Name: "host", Type: "HostPath", HostPath: "/srv/application-data"}},
			},
		},
		{
			id:       "KSCAN-K01-009",
			positive: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{SeccompProfile: "Unconfined"}}),
			negative: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{SeccompProfile: "RuntimeDefault"}}),
		},
		{
			id:       "KSCAN-K01-010",
			positive: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{ReadOnlyRootFilesystem: &falseValue}}),
			negative: podSpec(domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{ReadOnlyRootFilesystem: &trueValue}}),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.id, func(t *testing.T) {
			t.Parallel()
			if findings := evaluateRule(t, test.id, stateWithPod(test.positive)); len(findings) == 0 {
				t.Errorf("positive case produced no finding")
			}
			if findings := evaluateRule(t, test.id, stateWithPod(test.negative)); len(findings) != 0 {
				t.Errorf("negative case produced %d findings: %#v", len(findings), findings)
			}
		})
	}
}

func TestContainerRulesAnalyzeInitContainers(t *testing.T) {
	t.Parallel()

	trueValue, falseValue := true, false
	root := int64(0)
	tests := []struct {
		id        string
		container domain.Container
		configure func(*domain.PodSpec)
	}{
		{"KSCAN-K01-001", domain.Container{Name: "setup", SecurityContext: domain.ContainerSecurityContext{Privileged: &trueValue}}, nil},
		{"KSCAN-K01-002", domain.Container{Name: "setup", SecurityContext: domain.ContainerSecurityContext{RunAsUser: &root}}, nil},
		{"KSCAN-K01-003", domain.Container{Name: "setup", SecurityContext: domain.ContainerSecurityContext{AllowPrivilegeEscalation: &trueValue}}, nil},
		{"KSCAN-K01-004", domain.Container{Name: "setup", SecurityContext: domain.ContainerSecurityContext{AddedCapabilities: []string{"SYS_PTRACE"}}}, nil},
		{"KSCAN-K01-008", domain.Container{Name: "setup", VolumeMounts: []domain.VolumeMount{{Name: "host", MountPath: "/host"}}}, func(spec *domain.PodSpec) {
			spec.Volumes = []domain.Volume{{Name: "host", Type: "HostPath", HostPath: "/etc"}}
		}},
		{"KSCAN-K01-009", domain.Container{Name: "setup", SecurityContext: domain.ContainerSecurityContext{SeccompProfile: "Unconfined"}}, nil},
		{"KSCAN-K01-010", domain.Container{Name: "setup", SecurityContext: domain.ContainerSecurityContext{ReadOnlyRootFilesystem: &falseValue}}, nil},
	}
	for _, test := range tests {
		test := test
		t.Run(test.id, func(t *testing.T) {
			t.Parallel()
			spec := domain.PodSpec{InitContainers: []domain.Container{test.container}}
			if test.configure != nil {
				test.configure(&spec)
			}
			findings := evaluateRule(t, test.id, stateWithPod(spec))
			if len(findings) != 1 || !strings.HasPrefix(findings[0].Evidence[0].Message, "initContainer") {
				t.Fatalf("init container findings = %#v", findings)
			}
		})
	}
}

func TestMissingValueSemantics(t *testing.T) {
	t.Parallel()

	spec := podSpec(domain.Container{Name: "app"})
	if findings := evaluateRule(t, "KSCAN-K01-001", stateWithPod(spec)); len(findings) != 0 {
		t.Errorf("unset privileged produced findings: %#v", findings)
	}
	if findings := evaluateRule(t, "KSCAN-K01-002", stateWithPod(spec)); len(findings) != 0 {
		t.Errorf("unset runAsUser produced findings: %#v", findings)
	}
	if findings := evaluateRule(t, "KSCAN-K01-009", stateWithPod(spec)); len(findings) != 0 {
		t.Errorf("unset seccomp produced findings: %#v", findings)
	}
	if findings := evaluateRule(t, "KSCAN-K01-003", stateWithPod(spec)); len(findings) != 1 || findings[0].Evidence[0].Value != "<unset>" {
		t.Errorf("unset allowPrivilegeEscalation findings = %#v", findings)
	}
	if findings := evaluateRule(t, "KSCAN-K01-010", stateWithPod(spec)); len(findings) != 1 || findings[0].Evidence[0].Value != "<unset>" {
		t.Errorf("unset readOnlyRootFilesystem findings = %#v", findings)
	}
}

func TestPodSecurityContextIsInherited(t *testing.T) {
	t.Parallel()

	root := int64(0)
	spec := podSpec(domain.Container{Name: "app"}, domain.Container{Name: "setup"})
	spec.InitContainers = spec.Containers[1:]
	spec.Containers = spec.Containers[:1]
	spec.SecurityContext.RunAsUser = &root
	if findings := evaluateRule(t, "KSCAN-K01-002", stateWithPod(spec)); len(findings) != 2 {
		t.Fatalf("inherited root UID findings = %d, want 2", len(findings))
	}
	spec.SecurityContext.SeccompProfile = "Unconfined"
	if findings := evaluateRule(t, "KSCAN-K01-009", stateWithPod(spec)); len(findings) != 2 {
		t.Fatalf("inherited seccomp findings = %d, want 2", len(findings))
	}
}

func TestControllerOwnedPodIsNotReportedTwice(t *testing.T) {
	t.Parallel()

	trueValue := true
	container := domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{Privileged: &trueValue}}
	state := domain.ClusterState{
		Deployments: []domain.Workload{{
			Metadata: domain.Metadata{Name: "api", Namespace: "production"},
			Selector: domain.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: domain.PodTemplate{Spec: podSpec(container)},
		}},
		Pods: []domain.Pod{{
			Metadata: domain.Metadata{
				Name: "api-abc", Namespace: "production", Labels: map[string]string{"app": "api"},
				Owners: []domain.OwnerReference{{Kind: "ReplicaSet", Name: "api-123", Controller: true}},
			},
			Spec: podSpec(container),
		}},
	}
	findings := evaluateRule(t, "KSCAN-K01-001", state)
	if len(findings) != 1 || findings[0].Resource.Kind != "Deployment" {
		t.Fatalf("findings = %#v, want one Deployment finding", findings)
	}
}

func TestWindowsWorkloadSkipsLinuxOnlyContainerRules(t *testing.T) {
	t.Parallel()

	spec := podSpec(domain.Container{Name: "app"})
	spec.OSName = "windows"
	for _, id := range []string{"KSCAN-K01-001", "KSCAN-K01-002", "KSCAN-K01-003", "KSCAN-K01-004", "KSCAN-K01-008", "KSCAN-K01-009", "KSCAN-K01-010"} {
		if findings := evaluateRule(t, id, stateWithPod(spec)); len(findings) != 0 {
			t.Errorf("%s produced Windows findings: %#v", id, findings)
		}
	}
}

func evaluateRule(t *testing.T, id string, state domain.ClusterState) []domain.Finding {
	t.Helper()
	for _, rule := range k01.Rules() {
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

func stateWithPod(spec domain.PodSpec) domain.ClusterState {
	return domain.ClusterState{Pods: []domain.Pod{{Metadata: domain.Metadata{Name: "test-pod", Namespace: "test"}, Spec: spec}}}
}

func podSpec(containers ...domain.Container) domain.PodSpec {
	return domain.PodSpec{Containers: containers}
}

func secureContainer() domain.Container {
	falseValue, trueValue := false, true
	return domain.Container{Name: "app", SecurityContext: domain.ContainerSecurityContext{AllowPrivilegeEscalation: &falseValue, ReadOnlyRootFilesystem: &trueValue}}
}

func withPodSpec(spec domain.PodSpec, modify func(*domain.PodSpec)) domain.PodSpec {
	modify(&spec)
	return spec
}
