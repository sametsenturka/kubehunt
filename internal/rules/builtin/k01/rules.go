package k01

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
)

var category = domain.OWASPCategory{ID: "K01", Version: "2025", Title: "Insecure Workload Configurations"}

type workloadTarget struct {
	ref      domain.ResourceReference
	spec     domain.PodSpec
	specPath string
}

type workloadRule struct {
	metadata rules.Metadata
	evaluate func(context.Context, workloadTarget) []domain.Finding
}

func (rule workloadRule) Metadata() rules.Metadata { return rule.metadata }

func (rule workloadRule) Evaluate(ctx context.Context, state domain.ClusterState) ([]domain.Finding, error) {
	var findings []domain.Finding
	for _, target := range workloadTargets(state) {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		findings = append(findings, rule.evaluate(ctx, target)...)
	}
	return findings, nil
}

func Rules() []rules.Rule {
	return []rules.Rule{
		newRule("KSCAN-K01-001", "1.0.0", "Privileged container", "A container is explicitly configured to run in privileged mode.", domain.SeverityHigh, "Set securityContext.privileged to false and grant only the narrowly required permissions.", evaluatePrivileged),
		newRule("KSCAN-K01-002", "1.0.0", "Container running as UID 0", "A container is explicitly configured to run as the root user (UID 0).", domain.SeverityHigh, "Run the image as a non-root UID and set runAsNonRoot=true at container or pod level.", evaluateRootUID),
		newRule("KSCAN-K01-003", "1.0.0", "Privilege escalation allowed", "A container can gain more privileges than its parent process.", domain.SeverityHigh, "Set securityContext.allowPrivilegeEscalation=false for every container and init container.", evaluatePrivilegeEscalation),
		newRule("KSCAN-K01-004", "1.0.0", "Dangerous Linux capabilities", "A container explicitly adds one or more high-risk Linux capabilities.", domain.SeverityHigh, "Remove the added capabilities, drop ALL capabilities, and add back only capabilities that are strictly required.", evaluateCapabilities),
		newRule("KSCAN-K01-005", "1.0.0", "Host PID namespace enabled", "The workload shares the host process ID namespace.", domain.SeverityHigh, "Set spec.hostPID=false unless host process visibility is an explicitly reviewed requirement.", evaluateHostPID),
		newRule("KSCAN-K01-006", "1.0.0", "Host IPC namespace enabled", "The workload shares the host IPC namespace.", domain.SeverityHigh, "Set spec.hostIPC=false unless host IPC access is an explicitly reviewed requirement.", evaluateHostIPC),
		newRule("KSCAN-K01-007", "1.0.0", "Host network namespace enabled", "The workload shares the host network namespace.", domain.SeverityHigh, "Set spec.hostNetwork=false and use Kubernetes Services and NetworkPolicies for connectivity.", evaluateHostNetwork),
		newRule("KSCAN-K01-008", "1.0.0", "Sensitive hostPath mount", "A container mounts a sensitive host filesystem path.", domain.SeverityHigh, "Remove the hostPath volume. If host access is unavoidable, restrict it to a reviewed path and mount it read-only.", evaluateHostPath),
		newRule("KSCAN-K01-009", "1.0.0", "Seccomp explicitly unconfined", "A container explicitly disables seccomp confinement.", domain.SeverityMedium, "Use RuntimeDefault or an approved Localhost seccomp profile at pod or container level.", evaluateSeccomp),
		newRule("KSCAN-K01-010", "1.0.0", "Writable root filesystem", "A container root filesystem is writable.", domain.SeverityMedium, "Set securityContext.readOnlyRootFilesystem=true and use explicit writable volumes for required paths.", evaluateWritableRoot),
	}
}

func newRule(id, version, title, description string, severity domain.Severity, remediation string, evaluate func(context.Context, workloadTarget) []domain.Finding) rules.Rule {
	return workloadRule{
		metadata: rules.Metadata{
			ID:                    id,
			Version:               version,
			Title:                 title,
			Description:           description,
			DefaultSeverity:       severity,
			AffectedResourceTypes: []string{"Pod", "Deployment", "StatefulSet", "DaemonSet"},
			RequiredCapabilities:  []domain.CapabilityID{domain.CapabilityPodsList, domain.CapabilityWorkloadTemplatesList},
			Remediation:           remediation,
			OWASPMappings: []rules.OWASPMapping{{
				TaxonomyID: rules.OWASPTaxonomyID,
				Category:   category,
				Type:       rules.MappingPrimary,
				Rationale:  "The rule directly identifies an insecure workload security configuration.",
			}},
		},
		evaluate: evaluate,
	}
}

func workloadTargets(state domain.ClusterState) []workloadTarget {
	result := make([]workloadTarget, 0, len(state.Pods)+len(state.Deployments)+len(state.StatefulSets)+len(state.DaemonSets))
	for _, workload := range state.Deployments {
		result = append(result, targetForWorkload("apps/v1", "Deployment", workload))
	}
	for _, workload := range state.StatefulSets {
		result = append(result, targetForWorkload("apps/v1", "StatefulSet", workload))
	}
	for _, workload := range state.DaemonSets {
		result = append(result, targetForWorkload("apps/v1", "DaemonSet", workload))
	}
	for _, pod := range state.Pods {
		if podRepresentedByCollectedWorkload(pod, state) {
			continue
		}
		result = append(result, workloadTarget{
			ref:      reference("v1", "Pod", pod.Metadata),
			spec:     pod.Spec,
			specPath: "spec",
		})
	}
	return result
}

func targetForWorkload(apiVersion, kind string, workload domain.Workload) workloadTarget {
	return workloadTarget{ref: reference(apiVersion, kind, workload.Metadata), spec: workload.Template.Spec, specPath: "spec.template.spec"}
}

func reference(apiVersion, kind string, metadata domain.Metadata) domain.ResourceReference {
	return domain.ResourceReference{APIVersion: apiVersion, Kind: kind, Namespace: metadata.Namespace, Name: metadata.Name, UID: metadata.UID}
}

func podRepresentedByCollectedWorkload(pod domain.Pod, state domain.ClusterState) bool {
	for _, owner := range pod.Metadata.Owners {
		if !owner.Controller {
			continue
		}
		switch owner.Kind {
		case "StatefulSet":
			if workloadNamed(state.StatefulSets, pod.Metadata.Namespace, owner.Name) {
				return true
			}
		case "DaemonSet":
			if workloadNamed(state.DaemonSets, pod.Metadata.Namespace, owner.Name) {
				return true
			}
		case "ReplicaSet":
			for _, deployment := range state.Deployments {
				if deployment.Metadata.Namespace == pod.Metadata.Namespace && selectorMatches(deployment.Selector, pod.Metadata.Labels) {
					return true
				}
			}
		}
	}
	return false
}

func workloadNamed(workloads []domain.Workload, namespace, name string) bool {
	for _, workload := range workloads {
		if workload.Metadata.Namespace == namespace && workload.Metadata.Name == name {
			return true
		}
	}
	return false
}

func selectorMatches(selector domain.LabelSelector, labels map[string]string) bool {
	for key, expected := range selector.MatchLabels {
		if labels[key] != expected {
			return false
		}
	}
	for _, expression := range selector.MatchExpressions {
		value, exists := labels[expression.Key]
		switch expression.Operator {
		case "In":
			if !exists || !contains(expression.Values, value) {
				return false
			}
		case "NotIn":
			if !exists || contains(expression.Values, value) {
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

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

type namedContainer struct {
	container domain.Container
	field     string
	display   string
}

func containers(target workloadTarget) []namedContainer {
	result := make([]namedContainer, 0, len(target.spec.Containers)+len(target.spec.InitContainers))
	for _, container := range target.spec.Containers {
		result = append(result, namedContainer{container: container, field: target.specPath + ".containers", display: "container"})
	}
	for _, container := range target.spec.InitContainers {
		result = append(result, namedContainer{container: container, field: target.specPath + ".initContainers", display: "initContainer"})
	}
	return result
}

func containerField(container namedContainer, suffix string) string {
	return fmt.Sprintf("%s[name=%s].%s", container.field, container.container.Name, suffix)
}

func finding(target workloadTarget, evidence domain.Evidence) domain.Finding {
	return domain.Finding{Resource: target.ref, Evidence: []domain.Evidence{evidence}}
}

func linuxWorkload(target workloadTarget) bool {
	return !strings.EqualFold(target.spec.OSName, "windows")
}

func evaluatePrivileged(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		if value := item.container.SecurityContext.Privileged; value != nil && *value {
			field := containerField(item, "securityContext.privileged")
			result = append(result, finding(target, domain.Evidence{Field: field, Value: "true", Message: fmt.Sprintf("%s %q: securityContext.privileged=true", item.display, item.container.Name)}))
		}
	}
	return result
}

func evaluateRootUID(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		value := item.container.SecurityContext.RunAsUser
		field := containerField(item, "securityContext.runAsUser")
		inherited := false
		if value == nil {
			value = target.spec.SecurityContext.RunAsUser
			field = containerField(item, "effectiveSecurityContext.runAsUser")
			inherited = value != nil
		}
		if value != nil && *value == 0 {
			message := fmt.Sprintf("%s %q: effective runAsUser=0", item.display, item.container.Name)
			if inherited {
				message += " (inherited from pod securityContext)"
			}
			result = append(result, finding(target, domain.Evidence{Field: field, Value: "0", Message: message}))
		}
	}
	return result
}

func evaluatePrivilegeEscalation(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		value := item.container.SecurityContext.AllowPrivilegeEscalation
		if value != nil && !*value {
			continue
		}
		field := containerField(item, "securityContext.allowPrivilegeEscalation")
		evidenceValue := "true"
		message := fmt.Sprintf("%s %q: securityContext.allowPrivilegeEscalation=true", item.display, item.container.Name)
		if value == nil {
			evidenceValue = "<unset>"
			message = fmt.Sprintf("%s %q: securityContext.allowPrivilegeEscalation is unset (defaults to true)", item.display, item.container.Name)
		}
		result = append(result, finding(target, domain.Evidence{Field: field, Value: evidenceValue, Message: message}))
	}
	return result
}

var dangerousCapabilities = map[string]struct{}{
	"ALL": {}, "AUDIT_CONTROL": {}, "AUDIT_READ": {}, "BLOCK_SUSPEND": {}, "BPF": {},
	"DAC_READ_SEARCH": {}, "IPC_LOCK": {}, "IPC_OWNER": {}, "LEASE": {}, "LINUX_IMMUTABLE": {},
	"MAC_ADMIN": {}, "MAC_OVERRIDE": {}, "NET_ADMIN": {}, "NET_RAW": {}, "PERFMON": {},
	"SYS_ADMIN": {}, "SYS_BOOT": {}, "SYS_MODULE": {}, "SYS_NICE": {}, "SYS_PACCT": {},
	"SYS_PTRACE": {}, "SYS_RAWIO": {}, "SYS_RESOURCE": {}, "SYS_TIME": {}, "SYS_TTY_CONFIG": {},
	"SYSLOG": {}, "WAKE_ALARM": {},
}

func evaluateCapabilities(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		var dangerous []string
		seen := make(map[string]struct{})
		for _, capability := range item.container.SecurityContext.AddedCapabilities {
			capability = strings.ToUpper(capability)
			if _, risky := dangerousCapabilities[capability]; !risky {
				continue
			}
			if _, exists := seen[capability]; !exists {
				seen[capability] = struct{}{}
				dangerous = append(dangerous, capability)
			}
		}
		if len(dangerous) == 0 {
			continue
		}
		sort.Strings(dangerous)
		value := strings.Join(dangerous, ",")
		result = append(result, finding(target, domain.Evidence{Field: containerField(item, "securityContext.capabilities.add"), Value: value, Message: fmt.Sprintf("%s %q: adds dangerous Linux capabilities %s", item.display, item.container.Name, strings.Join(dangerous, ", "))}))
	}
	return result
}

func evaluateHostPID(_ context.Context, target workloadTarget) []domain.Finding {
	if target.spec.HostPID {
		return []domain.Finding{finding(target, domain.Evidence{Field: target.specPath + ".hostPID", Value: "true", Message: "spec.hostPID=true"})}
	}
	return nil
}

func evaluateHostIPC(_ context.Context, target workloadTarget) []domain.Finding {
	if target.spec.HostIPC {
		return []domain.Finding{finding(target, domain.Evidence{Field: target.specPath + ".hostIPC", Value: "true", Message: "spec.hostIPC=true"})}
	}
	return nil
}

func evaluateHostNetwork(_ context.Context, target workloadTarget) []domain.Finding {
	if target.spec.HostNetwork {
		return []domain.Finding{finding(target, domain.Evidence{Field: target.specPath + ".hostNetwork", Value: "true", Message: "spec.hostNetwork=true"})}
	}
	return nil
}

func evaluateHostPath(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	volumes := make(map[string]domain.Volume)
	for _, volume := range target.spec.Volumes {
		if volume.Type == "HostPath" && sensitiveHostPath(volume.HostPath) {
			volumes[volume.Name] = volume
		}
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		for _, mount := range item.container.VolumeMounts {
			volume, risky := volumes[mount.Name]
			if !risky {
				continue
			}
			field := fmt.Sprintf("%s[name=%s].volumeMounts[name=%s]", item.field, item.container.Name, mount.Name)
			message := fmt.Sprintf("%s %q: hostPath %q is mounted at %q", item.display, item.container.Name, volume.HostPath, mount.MountPath)
			result = append(result, finding(target, domain.Evidence{Field: field, Value: volume.HostPath, Message: message}))
		}
	}
	return result
}

var sensitivePathPrefixes = []string{
	"/boot", "/dev", "/etc", "/proc", "/root", "/sys", "/run", "/var/lib/docker", "/var/lib/kubelet", "/var/run",
}

func sensitiveHostPath(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") {
		return false
	}
	cleaned := path.Clean(value)
	if cleaned == "/" {
		return true
	}
	for _, prefix := range sensitivePathPrefixes {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") {
			return true
		}
	}
	return false
}

func evaluateSeccomp(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		profile := item.container.SecurityContext.SeccompProfile
		field := containerField(item, "securityContext.seccompProfile.type")
		inherited := false
		if profile == "" {
			profile = target.spec.SecurityContext.SeccompProfile
			field = containerField(item, "effectiveSecurityContext.seccompProfile.type")
			inherited = profile != ""
		}
		if strings.EqualFold(profile, "Unconfined") {
			message := fmt.Sprintf("%s %q: effective seccomp profile is explicitly Unconfined", item.display, item.container.Name)
			if inherited {
				message += " (inherited from pod securityContext)"
			}
			result = append(result, finding(target, domain.Evidence{Field: field, Value: "Unconfined", Message: message}))
		}
	}
	return result
}

func evaluateWritableRoot(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		value := item.container.SecurityContext.ReadOnlyRootFilesystem
		if value != nil && *value {
			continue
		}
		field := containerField(item, "securityContext.readOnlyRootFilesystem")
		evidenceValue := "false"
		message := fmt.Sprintf("%s %q: securityContext.readOnlyRootFilesystem=false", item.display, item.container.Name)
		if value == nil {
			evidenceValue = "<unset>"
			message = fmt.Sprintf("%s %q: securityContext.readOnlyRootFilesystem is unset (defaults to false)", item.display, item.container.Name)
		}
		result = append(result, finding(target, domain.Evidence{Field: field, Value: evidenceValue, Message: message}))
	}
	return result
}
