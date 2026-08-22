package domain

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (severity Severity) Rank() int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

type CapabilityID string

const (
	CapabilityPodsList                            CapabilityID = "kubernetes.core.pods.list"
	CapabilityWorkloadTemplatesList               CapabilityID = "kubernetes.apps.workload_templates.list"
	CapabilityRolesList                           CapabilityID = "kubernetes.rbac.roles.list"
	CapabilityClusterRolesList                    CapabilityID = "kubernetes.rbac.clusterroles.list"
	CapabilityRoleBindingsList                    CapabilityID = "kubernetes.rbac.rolebindings.list"
	CapabilityClusterRoleBindingsList             CapabilityID = "kubernetes.rbac.clusterrolebindings.list"
	CapabilityNamespacesList                      CapabilityID = "kubernetes.core.namespaces.list"
	CapabilityValidatingAdmissionPoliciesList     CapabilityID = "kubernetes.admission.validatingadmissionpolicies.list"
	CapabilityValidatingAdmissionBindingsList     CapabilityID = "kubernetes.admission.validatingadmissionpolicybindings.list"
	CapabilityValidatingWebhookConfigurationsList CapabilityID = "kubernetes.admission.validatingwebhookconfigurations.list"
)

type ResourceReference struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	UID        string
}

type Evidence struct {
	Field   string
	Value   string
	Message string
}

type OWASPCategory struct {
	ID      string
	Version string
	Title   string
}

type RiskScore struct {
	Score   int
	Model   string
	Factors map[string]int
}

// AttackPathNode is a report-safe projection of a graph node. Resource is nil
// for abstract authorization targets such as API resources.
type AttackPathNode struct {
	ID         string
	Type       string
	Kind       string
	Resource   *ResourceReference
	Attributes map[string]string
}

type AttackPathStep struct {
	EdgeID       string
	From         AttackPathNode
	Relationship string
	To           AttackPathNode
	Confidence   string
	Evidence     []Evidence
}

// SupportingFinding is deliberately non-recursive: it carries the facts used
// by a correlation without embedding another complete Finding.
type SupportingFinding struct {
	Fingerprint  string
	RuleID       string
	Title        string
	Severity     Severity
	Resource     ResourceReference
	Evidence     []Evidence
	PrimaryOWASP OWASPCategory
}

type Finding struct {
	Fingerprint        string
	RuleID             string
	Title              string
	Severity           Severity
	Resource           ResourceReference
	Namespace          string
	Evidence           []Evidence
	Description        string
	Remediation        string
	PrimaryOWASP       OWASPCategory
	RelatedOWASP       []OWASPCategory
	RiskScore          *RiskScore
	AttackPath         []AttackPathStep
	AffectedResources  []ResourceReference
	SupportingFindings []SupportingFinding
}

type ScanResult struct {
	State    ClusterState
	Findings []Finding
}
