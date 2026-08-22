package k01

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/sametsenturka/kubehunt/internal/domain"
	"github.com/sametsenturka/kubehunt/internal/rules"
	workloadtarget "github.com/sametsenturka/kubehunt/internal/rules/workload"
)

var (
	category    = domain.OWASPCategory{ID: "K01", Version: "2025", Title: "Insecure Workload Configurations"}
	categoryK05 = domain.OWASPCategory{ID: "K05", Version: "2025", Title: "Missing Network Segmentation Controls"}
)

type workloadTarget = workloadtarget.Target
type namedContainer = workloadtarget.Container

type workloadRule struct {
	metadata rules.Metadata
	evaluate func(context.Context, workloadTarget) []domain.Finding
}

func (rule workloadRule) Metadata() rules.Metadata { return rule.metadata }

func (rule workloadRule) Evaluate(ctx context.Context, state domain.ClusterState) ([]domain.Finding, error) {
	var findings []domain.Finding
	for _, target := range workloadtarget.Targets(state) {
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
	metadata := rules.Metadata{
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
	}
	if id == "KSCAN-K01-007" {
		metadata.OWASPMappings = append(metadata.OWASPMappings, rules.OWASPMapping{
			TaxonomyID: rules.OWASPTaxonomyID,
			Category:   categoryK05,
			Type:       rules.MappingRelated,
			Rationale:  "Host-networked workloads may bypass or receive CNI-specific handling outside ordinary Pod NetworkPolicy enforcement.",
		})
	}
	return workloadRule{metadata: metadata, evaluate: evaluate}
}

func containers(target workloadTarget) []namedContainer {
	return workloadtarget.Containers(target, false)
}

func containerField(container namedContainer, suffix string) string {
	return workloadtarget.ContainerField(container, suffix)
}

func finding(target workloadTarget, evidence domain.Evidence) domain.Finding {
	return domain.Finding{Resource: target.Ref, Evidence: []domain.Evidence{evidence}}
}

func linuxWorkload(target workloadTarget) bool {
	return !strings.EqualFold(target.Spec.OSName, "windows")
}

func evaluatePrivileged(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		if value := item.Value.SecurityContext.Privileged; value != nil && *value {
			field := containerField(item, "securityContext.privileged")
			result = append(result, finding(target, domain.Evidence{Field: field, Value: "true", Message: fmt.Sprintf("%s %q: securityContext.privileged=true", item.Display, item.Value.Name)}))
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
		value := item.Value.SecurityContext.RunAsUser
		field := containerField(item, "securityContext.runAsUser")
		inherited := false
		if value == nil {
			value = target.Spec.SecurityContext.RunAsUser
			field = containerField(item, "effectiveSecurityContext.runAsUser")
			inherited = value != nil
		}
		if value != nil && *value == 0 {
			message := fmt.Sprintf("%s %q: effective runAsUser=0", item.Display, item.Value.Name)
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
		value := item.Value.SecurityContext.AllowPrivilegeEscalation
		if value != nil && !*value {
			continue
		}
		field := containerField(item, "securityContext.allowPrivilegeEscalation")
		evidenceValue := "true"
		message := fmt.Sprintf("%s %q: securityContext.allowPrivilegeEscalation=true", item.Display, item.Value.Name)
		if value == nil {
			evidenceValue = "<unset>"
			message = fmt.Sprintf("%s %q: securityContext.allowPrivilegeEscalation is unset (defaults to true)", item.Display, item.Value.Name)
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
		for _, capability := range item.Value.SecurityContext.AddedCapabilities {
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
		result = append(result, finding(target, domain.Evidence{Field: containerField(item, "securityContext.capabilities.add"), Value: value, Message: fmt.Sprintf("%s %q: adds dangerous Linux capabilities %s", item.Display, item.Value.Name, strings.Join(dangerous, ", "))}))
	}
	return result
}

func evaluateHostPID(_ context.Context, target workloadTarget) []domain.Finding {
	if target.Spec.HostPID {
		return []domain.Finding{finding(target, domain.Evidence{Field: target.SpecPath + ".hostPID", Value: "true", Message: "spec.hostPID=true"})}
	}
	return nil
}

func evaluateHostIPC(_ context.Context, target workloadTarget) []domain.Finding {
	if target.Spec.HostIPC {
		return []domain.Finding{finding(target, domain.Evidence{Field: target.SpecPath + ".hostIPC", Value: "true", Message: "spec.hostIPC=true"})}
	}
	return nil
}

func evaluateHostNetwork(_ context.Context, target workloadTarget) []domain.Finding {
	if target.Spec.HostNetwork {
		return []domain.Finding{finding(target, domain.Evidence{Field: target.SpecPath + ".hostNetwork", Value: "true", Message: "spec.hostNetwork=true"})}
	}
	return nil
}

func evaluateHostPath(_ context.Context, target workloadTarget) []domain.Finding {
	if !linuxWorkload(target) {
		return nil
	}
	volumes := make(map[string]domain.Volume)
	for _, volume := range target.Spec.Volumes {
		if volume.Type == "HostPath" && sensitiveHostPath(volume.HostPath) {
			volumes[volume.Name] = volume
		}
	}
	var result []domain.Finding
	for _, item := range containers(target) {
		for _, mount := range item.Value.VolumeMounts {
			volume, risky := volumes[mount.Name]
			if !risky {
				continue
			}
			field := fmt.Sprintf("%s[name=%s].volumeMounts[name=%s]", item.Field, item.Value.Name, mount.Name)
			message := fmt.Sprintf("%s %q: hostPath %q is mounted at %q", item.Display, item.Value.Name, volume.HostPath, mount.MountPath)
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
		profile := item.Value.SecurityContext.SeccompProfile
		field := containerField(item, "securityContext.seccompProfile.type")
		inherited := false
		if profile == "" {
			profile = target.Spec.SecurityContext.SeccompProfile
			field = containerField(item, "effectiveSecurityContext.seccompProfile.type")
			inherited = profile != ""
		}
		if strings.EqualFold(profile, "Unconfined") {
			message := fmt.Sprintf("%s %q: effective seccomp profile is explicitly Unconfined", item.Display, item.Value.Name)
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
		value := item.Value.SecurityContext.ReadOnlyRootFilesystem
		if value != nil && *value {
			continue
		}
		field := containerField(item, "securityContext.readOnlyRootFilesystem")
		evidenceValue := "false"
		message := fmt.Sprintf("%s %q: securityContext.readOnlyRootFilesystem=false", item.Display, item.Value.Name)
		if value == nil {
			evidenceValue = "<unset>"
			message = fmt.Sprintf("%s %q: securityContext.readOnlyRootFilesystem is unset (defaults to false)", item.Display, item.Value.Name)
		}
		result = append(result, finding(target, domain.Evidence{Field: field, Value: evidenceValue, Message: message}))
	}
	return result
}
