package collectors

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

func normalizeMetadata(object metav1.Object) domain.Metadata {
	owners := make([]domain.OwnerReference, 0, len(object.GetOwnerReferences()))
	for _, owner := range object.GetOwnerReferences() {
		controller := owner.Controller != nil && *owner.Controller
		owners = append(owners, domain.OwnerReference{
			APIVersion: owner.APIVersion,
			Kind:       owner.Kind,
			Name:       owner.Name,
			UID:        string(owner.UID),
			Controller: controller,
		})
	}
	return domain.Metadata{
		Name:            object.GetName(),
		Namespace:       object.GetNamespace(),
		UID:             string(object.GetUID()),
		ResourceVersion: object.GetResourceVersion(),
		Generation:      object.GetGeneration(),
		Labels:          copyMap(object.GetLabels()),
		Annotations:     copyMap(object.GetAnnotations()),
		Owners:          owners,
	}
}

func normalizeNamespace(namespace corev1.Namespace) domain.Namespace {
	return domain.Namespace{Metadata: normalizeMetadata(&namespace), Phase: string(namespace.Status.Phase)}
}

func normalizePod(pod corev1.Pod) domain.Pod {
	return domain.Pod{
		Metadata: normalizeMetadata(&pod),
		Spec:     normalizePodSpec(pod.Spec),
		Phase:    string(pod.Status.Phase),
	}
}

func normalizeDeployment(deployment appsv1.Deployment) domain.Workload {
	return domain.Workload{
		Metadata: normalizeMetadata(&deployment),
		Replicas: copyInt32(deployment.Spec.Replicas),
		Selector: normalizeLabelSelector(deployment.Spec.Selector),
		Template: normalizePodTemplate(deployment.Spec.Template),
	}
}

func normalizeStatefulSet(statefulSet appsv1.StatefulSet) domain.Workload {
	return domain.Workload{
		Metadata: normalizeMetadata(&statefulSet),
		Replicas: copyInt32(statefulSet.Spec.Replicas),
		Selector: normalizeLabelSelector(statefulSet.Spec.Selector),
		Template: normalizePodTemplate(statefulSet.Spec.Template),
	}
}

func normalizeDaemonSet(daemonSet appsv1.DaemonSet) domain.Workload {
	return domain.Workload{
		Metadata: normalizeMetadata(&daemonSet),
		Selector: normalizeLabelSelector(daemonSet.Spec.Selector),
		Template: normalizePodTemplate(daemonSet.Spec.Template),
	}
}

func normalizePodTemplate(template corev1.PodTemplateSpec) domain.PodTemplate {
	return domain.PodTemplate{
		Labels:      copyMap(template.Labels),
		Annotations: copyMap(template.Annotations),
		Spec:        normalizePodSpec(template.Spec),
	}
}

func normalizePodSpec(spec corev1.PodSpec) domain.PodSpec {
	containers := make([]domain.Container, 0, len(spec.Containers))
	for _, container := range spec.Containers {
		containers = append(containers, normalizeContainer(container))
	}
	initContainers := make([]domain.Container, 0, len(spec.InitContainers))
	for _, container := range spec.InitContainers {
		initContainers = append(initContainers, normalizeContainer(container))
	}
	ephemeralContainers := make([]domain.Container, 0, len(spec.EphemeralContainers))
	for _, container := range spec.EphemeralContainers {
		ephemeralContainers = append(ephemeralContainers, normalizeEphemeralContainer(container))
	}
	volumes := make([]domain.Volume, 0, len(spec.Volumes))
	for _, volume := range spec.Volumes {
		volumes = append(volumes, normalizeVolume(volume))
	}

	securityContext := domain.PodSecurityContext{}
	if spec.SecurityContext != nil {
		securityContext.RunAsNonRoot = copyBool(spec.SecurityContext.RunAsNonRoot)
		securityContext.RunAsUser = copyInt64(spec.SecurityContext.RunAsUser)
		if spec.SecurityContext.SeccompProfile != nil {
			securityContext.SeccompProfile = string(spec.SecurityContext.SeccompProfile.Type)
		}
	}

	osName := ""
	if spec.OS != nil {
		osName = string(spec.OS.Name)
	}
	return domain.PodSpec{
		OSName:                       osName,
		ServiceAccountName:           spec.ServiceAccountName,
		AutomountServiceAccountToken: copyBool(spec.AutomountServiceAccountToken),
		NodeName:                     spec.NodeName,
		HostNetwork:                  spec.HostNetwork,
		HostPID:                      spec.HostPID,
		HostIPC:                      spec.HostIPC,
		SecurityContext:              securityContext,
		Containers:                   containers,
		InitContainers:               initContainers,
		EphemeralContainers:          ephemeralContainers,
		Volumes:                      volumes,
	}
}

func normalizeContainer(container corev1.Container) domain.Container {
	return domain.Container{
		Name:            container.Name,
		Image:           container.Image,
		SecurityContext: normalizeContainerSecurityContext(container.SecurityContext),
		VolumeMounts:    normalizeVolumeMounts(container.VolumeMounts),
		Limits:          normalizeResourceList(container.Resources.Limits),
		Requests:        normalizeResourceList(container.Resources.Requests),
	}
}

func normalizeEphemeralContainer(container corev1.EphemeralContainer) domain.Container {
	return domain.Container{
		Name:            container.Name,
		Image:           container.Image,
		SecurityContext: normalizeContainerSecurityContext(container.SecurityContext),
		VolumeMounts:    normalizeVolumeMounts(container.VolumeMounts),
	}
}

func normalizeVolumeMounts(mounts []corev1.VolumeMount) []domain.VolumeMount {
	result := make([]domain.VolumeMount, 0, len(mounts))
	for _, mount := range mounts {
		result = append(result, domain.VolumeMount{Name: mount.Name, MountPath: mount.MountPath, ReadOnly: mount.ReadOnly})
	}
	return result
}

func normalizeContainerSecurityContext(context *corev1.SecurityContext) domain.ContainerSecurityContext {
	if context == nil {
		return domain.ContainerSecurityContext{}
	}
	result := domain.ContainerSecurityContext{
		Privileged:               copyBool(context.Privileged),
		AllowPrivilegeEscalation: copyBool(context.AllowPrivilegeEscalation),
		ReadOnlyRootFilesystem:   copyBool(context.ReadOnlyRootFilesystem),
		RunAsNonRoot:             copyBool(context.RunAsNonRoot),
		RunAsUser:                copyInt64(context.RunAsUser),
	}
	if context.Capabilities != nil {
		for _, capability := range context.Capabilities.Add {
			result.AddedCapabilities = append(result.AddedCapabilities, string(capability))
		}
		for _, capability := range context.Capabilities.Drop {
			result.DroppedCapabilities = append(result.DroppedCapabilities, string(capability))
		}
	}
	if context.SeccompProfile != nil {
		result.SeccompProfile = string(context.SeccompProfile.Type)
	}
	return result
}

func normalizeResourceList(resources corev1.ResourceList) map[string]string {
	if len(resources) == 0 {
		return nil
	}
	result := make(map[string]string, len(resources))
	for name, quantity := range resources {
		result[string(name)] = quantity.String()
	}
	return result
}

func normalizeVolume(volume corev1.Volume) domain.Volume {
	result := domain.Volume{Name: volume.Name}
	switch {
	case volume.HostPath != nil:
		result.Type = "HostPath"
		result.HostPath = volume.HostPath.Path
	case volume.Secret != nil:
		result.Type = "Secret"
		result.SecretName = volume.Secret.SecretName
	case volume.ConfigMap != nil:
		result.Type = "ConfigMap"
	case volume.EmptyDir != nil:
		result.Type = "EmptyDir"
	case volume.PersistentVolumeClaim != nil:
		result.Type = "PersistentVolumeClaim"
	case volume.Projected != nil:
		result.Type = "Projected"
	default:
		result.Type = "Other"
	}
	return result
}

func normalizeService(service corev1.Service) domain.Service {
	ports := make([]domain.ServicePort, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		ports = append(ports, domain.ServicePort{
			Name:       port.Name,
			Protocol:   string(port.Protocol),
			Port:       port.Port,
			TargetPort: port.TargetPort.String(),
			NodePort:   port.NodePort,
		})
	}
	return domain.Service{
		Metadata:     normalizeMetadata(&service),
		Type:         string(service.Spec.Type),
		Selector:     copyMap(service.Spec.Selector),
		ClusterIP:    service.Spec.ClusterIP,
		ExternalName: service.Spec.ExternalName,
		ExternalIPs:  copyStrings(service.Spec.ExternalIPs),
		Ports:        ports,
	}
}

func normalizeIngress(ingress networkingv1.Ingress) domain.Ingress {
	rules := make([]domain.IngressRule, 0, len(ingress.Spec.Rules))
	for _, rule := range ingress.Spec.Rules {
		normalizedRule := domain.IngressRule{Host: rule.Host}
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				pathType := ""
				if path.PathType != nil {
					pathType = string(*path.PathType)
				}
				normalizedRule.Paths = append(normalizedRule.Paths, domain.IngressPath{
					Path:     path.Path,
					PathType: pathType,
					Backend:  normalizeIngressBackend(path.Backend),
				})
			}
		}
		rules = append(rules, normalizedRule)
	}
	var defaultBackend *domain.IngressBackend
	if ingress.Spec.DefaultBackend != nil {
		backend := normalizeIngressBackend(*ingress.Spec.DefaultBackend)
		defaultBackend = &backend
	}
	return domain.Ingress{
		Metadata:         normalizeMetadata(&ingress),
		IngressClassName: copyString(ingress.Spec.IngressClassName),
		DefaultBackend:   defaultBackend,
		Rules:            rules,
	}
}

func normalizeIngressBackend(backend networkingv1.IngressBackend) domain.IngressBackend {
	result := domain.IngressBackend{}
	if backend.Service != nil {
		result.ServiceName = backend.Service.Name
		if backend.Service.Port.Name != "" {
			result.ServicePort = backend.Service.Port.Name
		} else {
			result.ServicePort = fmt.Sprint(backend.Service.Port.Number)
		}
	}
	if backend.Resource != nil {
		apiGroup := ""
		if backend.Resource.APIGroup != nil {
			apiGroup = *backend.Resource.APIGroup + "/"
		}
		result.Resource = apiGroup + backend.Resource.Kind + "/" + backend.Resource.Name
	}
	return result
}

func normalizeServiceAccount(account corev1.ServiceAccount) domain.ServiceAccount {
	secrets := make([]domain.LocalReference, 0, len(account.Secrets))
	for _, reference := range account.Secrets {
		secrets = append(secrets, domain.LocalReference{Name: reference.Name})
	}
	pullSecrets := make([]domain.LocalReference, 0, len(account.ImagePullSecrets))
	for _, reference := range account.ImagePullSecrets {
		pullSecrets = append(pullSecrets, domain.LocalReference{Name: reference.Name})
	}
	return domain.ServiceAccount{
		Metadata:                     normalizeMetadata(&account),
		AutomountServiceAccountToken: copyBool(account.AutomountServiceAccountToken),
		Secrets:                      secrets,
		ImagePullSecrets:             pullSecrets,
	}
}

func normalizeRole(role rbacv1.Role) domain.Role {
	return domain.Role{Metadata: normalizeMetadata(&role), Rules: normalizePolicyRules(role.Rules)}
}

func normalizeClusterRole(role rbacv1.ClusterRole) domain.Role {
	result := domain.Role{Metadata: normalizeMetadata(&role), Rules: normalizePolicyRules(role.Rules)}
	if role.AggregationRule != nil {
		for index := range role.AggregationRule.ClusterRoleSelectors {
			result.AggregationRule = append(result.AggregationRule, normalizeLabelSelector(&role.AggregationRule.ClusterRoleSelectors[index]))
		}
	}
	return result
}

func normalizePolicyRules(rules []rbacv1.PolicyRule) []domain.PolicyRule {
	result := make([]domain.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, domain.PolicyRule{
			Verbs:           copyStrings(rule.Verbs),
			APIGroups:       copyStrings(rule.APIGroups),
			Resources:       copyStrings(rule.Resources),
			ResourceNames:   copyStrings(rule.ResourceNames),
			NonResourceURLs: copyStrings(rule.NonResourceURLs),
		})
	}
	return result
}

func normalizeRoleBinding(binding rbacv1.RoleBinding) domain.RoleBinding {
	return domain.RoleBinding{
		Metadata: normalizeMetadata(&binding),
		RoleRef:  normalizeRoleReference(binding.RoleRef),
		Subjects: normalizeSubjects(binding.Subjects),
	}
}

func normalizeClusterRoleBinding(binding rbacv1.ClusterRoleBinding) domain.RoleBinding {
	return domain.RoleBinding{
		Metadata: normalizeMetadata(&binding),
		RoleRef:  normalizeRoleReference(binding.RoleRef),
		Subjects: normalizeSubjects(binding.Subjects),
	}
}

func normalizeRoleReference(reference rbacv1.RoleRef) domain.RoleReference {
	return domain.RoleReference{APIGroup: reference.APIGroup, Kind: reference.Kind, Name: reference.Name}
}

func normalizeSubjects(subjects []rbacv1.Subject) []domain.Subject {
	result := make([]domain.Subject, 0, len(subjects))
	for _, subject := range subjects {
		result = append(result, domain.Subject{
			APIGroup:  subject.APIGroup,
			Kind:      subject.Kind,
			Namespace: subject.Namespace,
			Name:      subject.Name,
		})
	}
	return result
}

func normalizeNetworkPolicy(policy networkingv1.NetworkPolicy) domain.NetworkPolicy {
	ingress := make([]domain.NetworkPolicyIngressRule, 0, len(policy.Spec.Ingress))
	for _, rule := range policy.Spec.Ingress {
		ingress = append(ingress, domain.NetworkPolicyIngressRule{
			From:  normalizeNetworkPolicyPeers(rule.From),
			Ports: normalizeNetworkPolicyPorts(rule.Ports),
		})
	}
	egress := make([]domain.NetworkPolicyEgressRule, 0, len(policy.Spec.Egress))
	for _, rule := range policy.Spec.Egress {
		egress = append(egress, domain.NetworkPolicyEgressRule{
			To:    normalizeNetworkPolicyPeers(rule.To),
			Ports: normalizeNetworkPolicyPorts(rule.Ports),
		})
	}
	policyTypes := make([]string, 0, len(policy.Spec.PolicyTypes))
	for _, policyType := range policy.Spec.PolicyTypes {
		policyTypes = append(policyTypes, string(policyType))
	}
	return domain.NetworkPolicy{
		Metadata:    normalizeMetadata(&policy),
		PodSelector: normalizeLabelSelector(&policy.Spec.PodSelector),
		PolicyTypes: policyTypes,
		Ingress:     ingress,
		Egress:      egress,
	}
}

func normalizeNetworkPolicyPeers(peers []networkingv1.NetworkPolicyPeer) []domain.NetworkPolicyPeer {
	result := make([]domain.NetworkPolicyPeer, 0, len(peers))
	for _, peer := range peers {
		normalized := domain.NetworkPolicyPeer{}
		if peer.PodSelector != nil {
			selector := normalizeLabelSelector(peer.PodSelector)
			normalized.PodSelector = &selector
		}
		if peer.NamespaceSelector != nil {
			selector := normalizeLabelSelector(peer.NamespaceSelector)
			normalized.NamespaceSelector = &selector
		}
		if peer.IPBlock != nil {
			normalized.IPBlock = &domain.IPBlock{CIDR: peer.IPBlock.CIDR, Except: copyStrings(peer.IPBlock.Except)}
		}
		result = append(result, normalized)
	}
	return result
}

func normalizeNetworkPolicyPorts(ports []networkingv1.NetworkPolicyPort) []domain.NetworkPolicyPort {
	result := make([]domain.NetworkPolicyPort, 0, len(ports))
	for _, port := range ports {
		normalized := domain.NetworkPolicyPort{EndPort: copyInt32(port.EndPort)}
		if port.Protocol != nil {
			normalized.Protocol = string(*port.Protocol)
		}
		if port.Port != nil {
			normalized.Port = port.Port.String()
		}
		result = append(result, normalized)
	}
	return result
}

func normalizeLabelSelector(selector *metav1.LabelSelector) domain.LabelSelector {
	if selector == nil {
		return domain.LabelSelector{}
	}
	result := domain.LabelSelector{MatchLabels: copyMap(selector.MatchLabels)}
	for _, expression := range selector.MatchExpressions {
		result.MatchExpressions = append(result.MatchExpressions, domain.LabelSelectorRequirement{
			Key:      expression.Key,
			Operator: string(expression.Operator),
			Values:   copyStrings(expression.Values),
		})
	}
	return result
}

func copyMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func copyStrings(source []string) []string {
	return append([]string(nil), source...)
}

func copyBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyInt32(value *int32) *int32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
