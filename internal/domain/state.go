package domain

import "time"

// ClusterState is the normalized, in-memory representation of one cluster
// inventory. It deliberately contains no client-go API objects.
type ClusterState struct {
	Cluster                           ClusterMetadata
	Namespaces                        []Namespace
	Pods                              []Pod
	Deployments                       []Workload
	StatefulSets                      []Workload
	DaemonSets                        []Workload
	Services                          []Service
	Ingresses                         []Ingress
	ServiceAccounts                   []ServiceAccount
	Roles                             []Role
	ClusterRoles                      []Role
	RoleBindings                      []RoleBinding
	ClusterRoleBindings               []RoleBinding
	NetworkPolicies                   []NetworkPolicy
	ValidatingAdmissionPolicies       []ValidatingAdmissionPolicy
	ValidatingAdmissionPolicyBindings []ValidatingAdmissionPolicyBinding
	ValidatingWebhookConfigurations   []ValidatingWebhookConfiguration
	Collections                       map[ResourceKind]CollectionMetadata
}

type ClusterMetadata struct {
	Context        string
	Name           string
	Server         string
	NamespaceScope []string
	StartedAt      time.Time
	EndedAt        time.Time
}

type ResourceKind string

const (
	KindNamespaces                        ResourceKind = "Namespaces"
	KindPods                              ResourceKind = "Pods"
	KindDeployments                       ResourceKind = "Deployments"
	KindStatefulSets                      ResourceKind = "StatefulSets"
	KindDaemonSets                        ResourceKind = "DaemonSets"
	KindServices                          ResourceKind = "Services"
	KindIngresses                         ResourceKind = "Ingresses"
	KindServiceAccounts                   ResourceKind = "ServiceAccounts"
	KindRoles                             ResourceKind = "Roles"
	KindClusterRoles                      ResourceKind = "ClusterRoles"
	KindRoleBindings                      ResourceKind = "RoleBindings"
	KindClusterRoleBindings               ResourceKind = "ClusterRoleBindings"
	KindNetworkPolicies                   ResourceKind = "NetworkPolicies"
	KindValidatingAdmissionPolicies       ResourceKind = "ValidatingAdmissionPolicies"
	KindValidatingAdmissionPolicyBindings ResourceKind = "ValidatingAdmissionPolicyBindings"
	KindValidatingWebhookConfigurations   ResourceKind = "ValidatingWebhookConfigurations"
)

var InventoryKinds = []ResourceKind{
	KindNamespaces,
	KindPods,
	KindDeployments,
	KindStatefulSets,
	KindDaemonSets,
	KindServices,
	KindIngresses,
	KindServiceAccounts,
	KindRoles,
	KindClusterRoles,
	KindRoleBindings,
	KindClusterRoleBindings,
	KindNetworkPolicies,
	KindValidatingAdmissionPolicies,
	KindValidatingAdmissionPolicyBindings,
	KindValidatingWebhookConfigurations,
}

type CollectionMetadata struct {
	ResourceVersion string
	StartedAt       time.Time
	EndedAt         time.Time
	Count           int
}

type Metadata struct {
	Name            string
	Namespace       string
	UID             string
	ResourceVersion string
	Generation      int64
	Labels          map[string]string
	Annotations     map[string]string
	Owners          []OwnerReference
}

type OwnerReference struct {
	APIVersion string
	Kind       string
	Name       string
	UID        string
	Controller bool
}

type Namespace struct {
	Metadata Metadata
	Phase    string
}

type Pod struct {
	Metadata Metadata
	Spec     PodSpec
	Phase    string
}

type Workload struct {
	Metadata Metadata
	Replicas *int32
	Selector LabelSelector
	Template PodTemplate
}

type PodTemplate struct {
	Labels      map[string]string
	Annotations map[string]string
	Spec        PodSpec
}

type PodSpec struct {
	OSName                       string
	ServiceAccountName           string
	AutomountServiceAccountToken *bool
	NodeName                     string
	HostNetwork                  bool
	HostPID                      bool
	HostIPC                      bool
	SecurityContext              PodSecurityContext
	Containers                   []Container
	InitContainers               []Container
	EphemeralContainers          []Container
	Volumes                      []Volume
}

type PodSecurityContext struct {
	RunAsNonRoot   *bool
	RunAsUser      *int64
	SeccompProfile string
}

type Container struct {
	Name                       string
	Image                      string
	SecurityContext            ContainerSecurityContext
	VolumeMounts               []VolumeMount
	Limits                     map[string]string
	Requests                   map[string]string
	SecretEnvironmentVariables []SecretEnvironmentVariable
	SecretEnvironmentSources   []SecretEnvironmentSource
}

// SecretEnvironmentVariable is a report-safe reference to one Secret key.
// It deliberately contains no environment or Secret value.
type SecretEnvironmentVariable struct {
	Index      int
	Name       string
	SecretName string
	SecretKey  string
	Optional   *bool
}

// SecretEnvironmentSource records envFrom.secretRef without Secret contents.
type SecretEnvironmentSource struct {
	Index      int
	Prefix     string
	SecretName string
	Optional   *bool
}

type VolumeMount struct {
	Name      string
	ReadOnly  bool
	MountPath string
}

type ContainerSecurityContext struct {
	Privileged               *bool
	AllowPrivilegeEscalation *bool
	ReadOnlyRootFilesystem   *bool
	RunAsNonRoot             *bool
	RunAsUser                *int64
	AddedCapabilities        []string
	DroppedCapabilities      []string
	SeccompProfile           string
}

type Volume struct {
	Name       string
	Type       string
	HostPath   string
	SecretName string
}

type Service struct {
	Metadata     Metadata
	Type         string
	Selector     map[string]string
	ClusterIP    string
	ExternalName string
	ExternalIPs  []string
	Ports        []ServicePort
}

type ServicePort struct {
	Name       string
	Protocol   string
	Port       int32
	TargetPort string
	NodePort   int32
}

type Ingress struct {
	Metadata         Metadata
	IngressClassName *string
	DefaultBackend   *IngressBackend
	Rules            []IngressRule
}

type IngressRule struct {
	Host  string
	Paths []IngressPath
}

type IngressPath struct {
	Path     string
	PathType string
	Backend  IngressBackend
}

type IngressBackend struct {
	ServiceName string
	ServicePort string
	Resource    string
}

type ServiceAccount struct {
	Metadata                     Metadata
	AutomountServiceAccountToken *bool
	Secrets                      []LocalReference
	ImagePullSecrets             []LocalReference
}

type LocalReference struct {
	Name string
}

type Role struct {
	Metadata        Metadata
	Rules           []PolicyRule
	AggregationRule []LabelSelector
}

type PolicyRule struct {
	Verbs           []string
	APIGroups       []string
	Resources       []string
	ResourceNames   []string
	NonResourceURLs []string
}

type RoleBinding struct {
	Metadata Metadata
	RoleRef  RoleReference
	Subjects []Subject
}

type RoleReference struct {
	APIGroup string
	Kind     string
	Name     string
}

type Subject struct {
	APIGroup  string
	Kind      string
	Namespace string
	Name      string
}

type NetworkPolicy struct {
	Metadata    Metadata
	PodSelector LabelSelector
	PolicyTypes []string
	Ingress     []NetworkPolicyIngressRule
	Egress      []NetworkPolicyEgressRule
}

type LabelSelector struct {
	MatchLabels      map[string]string
	MatchExpressions []LabelSelectorRequirement
}

type LabelSelectorRequirement struct {
	Key      string
	Operator string
	Values   []string
}

type NetworkPolicyIngressRule struct {
	From  []NetworkPolicyPeer
	Ports []NetworkPolicyPort
}

type NetworkPolicyEgressRule struct {
	To    []NetworkPolicyPeer
	Ports []NetworkPolicyPort
}

type NetworkPolicyPeer struct {
	PodSelector       *LabelSelector
	NamespaceSelector *LabelSelector
	IPBlock           *IPBlock
}

type IPBlock struct {
	CIDR   string
	Except []string
}

type NetworkPolicyPort struct {
	Protocol string
	Port     string
	EndPort  *int32
}

type ValidatingAdmissionPolicy struct {
	Metadata      Metadata
	FailurePolicy string
}

type ValidatingAdmissionPolicyBinding struct {
	Metadata          Metadata
	PolicyName        string
	ValidationActions []string
}

type ValidatingWebhookConfiguration struct {
	Metadata Metadata
	Webhooks []ValidatingWebhook
}

type ValidatingWebhook struct {
	Name          string
	FailurePolicy string
}

func (s ClusterState) Count(kind ResourceKind) int {
	switch kind {
	case KindNamespaces:
		return len(s.Namespaces)
	case KindPods:
		return len(s.Pods)
	case KindDeployments:
		return len(s.Deployments)
	case KindStatefulSets:
		return len(s.StatefulSets)
	case KindDaemonSets:
		return len(s.DaemonSets)
	case KindServices:
		return len(s.Services)
	case KindIngresses:
		return len(s.Ingresses)
	case KindServiceAccounts:
		return len(s.ServiceAccounts)
	case KindRoles:
		return len(s.Roles)
	case KindClusterRoles:
		return len(s.ClusterRoles)
	case KindRoleBindings:
		return len(s.RoleBindings)
	case KindClusterRoleBindings:
		return len(s.ClusterRoleBindings)
	case KindNetworkPolicies:
		return len(s.NetworkPolicies)
	case KindValidatingAdmissionPolicies:
		return len(s.ValidatingAdmissionPolicies)
	case KindValidatingAdmissionPolicyBindings:
		return len(s.ValidatingAdmissionPolicyBindings)
	case KindValidatingWebhookConfigurations:
		return len(s.ValidatingWebhookConfigurations)
	default:
		return 0
	}
}
