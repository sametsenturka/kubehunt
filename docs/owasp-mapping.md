# OWASP Kubernetes Top 10:2025 mapping

Status: proposed mapping and coverage contract
Taxonomy ID: `owasp-kubernetes-top-10:2025`
Primary source: [OWASP Kubernetes Top Ten](https://owasp.org/www-project-kubernetes-top-ten/)

## 1. Mapping policy

OWASP categories describe broad risks; they are not executable tests. KubeHunt rules are narrower claims derived from concrete evidence. Each rule has one `primary` category and may have `related` categories only when its evidence directly supports both. A mapping includes a written rationale and is reviewed/versioned with the rule.

Mapping does not imply OWASP endorsement or certification. Category order is not severity. Multiple findings in one category do not measure how completely the category was assessed.

Coverage statuses mean:

- `assessed`: all capabilities in KubeHunt's declared category profile were available and evaluated. This is still not a proof that the entire real-world OWASP risk is absent.
- `partial`: some useful category evidence was evaluated, while named material capabilities/evidence sources were unavailable or unimplemented.
- `not_assessed`: no meaningful rule in the declared profile could be evaluated.
- `error`: evaluation should have been possible, but collection or analysis failed.
- `not_applicable`: the target/scope cannot contain the relevant resource or feature.

KubeHunt should initially use the stricter label `partial` for K01-K06 at category level unless the category profile explicitly defines a supportable bounded claim. K07-K10 must remain partial/not assessed under the stated resource-only scanner scope.

## 2. 2025 categories and initial posture

| ID | OWASP Kubernetes Top 10:2025 category | Initial KubeHunt visibility | Important missing evidence |
|---|---|---|---|
| K01 | Insecure Workload Configurations | Partial, strong for supported workload/Pod fields | Jobs/CronJobs, admission/default mutation provenance, image contents, runtime state, node/runtime controls |
| K02 | Overly Permissive Authorization Configurations | Partial, strong for native RBAC objects | Identity-provider membership, cloud IAM mappings, non-RBAC authorizers, JIT expiry/workflow, admission effects |
| K03 | Secrets Management Failures | Partial | Values/content quality by design, encryption at rest, external secret stores, rotation/usage history, KMS configuration |
| K04 | Lack Of Cluster Level Policy Enforcement | Partial to not assessed | Admission controller configuration, ValidatingAdmissionPolicy/webhooks, policy-engine CRDs, enforcement/audit mode and coverage |
| K05 | Missing Network Segmentation Controls | Partial, native NetworkPolicy intent | CNI implementation/enforcement, vendor policies, observed flows, node/firewall/service-mesh/cloud controls |
| K06 | Overly Exposed Kubernetes Components | Partial, configuration indicators only | Cloud load balancers/firewalls/DNS, API server and component endpoints, Internet reachability, kubelet/etcd configuration |
| K07 | Misconfigured And Vulnerable Cluster Components | Partial or not assessed | Nodes, component flags/config, versions beyond server discovery, host OS/runtime, CVE intelligence |
| K08 | Cluster To Cloud Lateral Movement | Partial or not assessed | Cloud metadata reachability, workload identity, cloud IAM policies, provider configuration, runtime credentials |
| K09 | Broken Authentication Mechanisms | Not assessed by default | API server authentication flags, OIDC/webhook configuration, certificates/tokens and lifecycle, IdP policy |
| K10 | Inadequate Logging And Monitoring | Not assessed by default | Audit policy/logs, node/workload logs, SIEM pipeline, alert rules, retention and response evidence |

## 3. Candidate initial rule families

Rule IDs below are architectural examples, not an implemented or frozen rule catalog. Exact severities and predicates require review against supported Kubernetes versions before release.

### K01 — Insecure Workload Configurations

Potential deterministic rules for Pods and Pod templates:

- privileged container enabled;
- host PID, IPC, or network namespace enabled;
- dangerous hostPath mount;
- container allows privilege escalation;
- container does not require non-root execution, accounting for pod/container overrides and known version semantics;
- explicit root UID;
- capabilities are added or not dropped according to a declared profile;
- seccomp is unconfined or not explicitly set according to the selected profile/version;
- writable root filesystem;
- service account token automount effectively enabled when not required by an allowlist/policy;
- missing CPU/memory limits as an availability hardening signal;
- risky proc mount or host ports.

Possible evidence: canonical PodSpec and container security contexts, volumes, resources, service account selection, controller ownership, Kubernetes version. Results must cover regular, init, and ephemeral containers where applicable. “Field absent” needs version-aware effective semantics.

### K02 — Overly Permissive Authorization Configurations

Potential deterministic rules:

- binding to `cluster-admin` or an equivalent wildcard grant;
- wildcard API groups/resources/verbs;
- grants to read or mutate Secrets;
- grants to create Pods/workloads, bind/impersonate/escalate, create service-account tokens, or access dangerous subresources such as nodes/proxy or pods/exec;
- cluster-scoped grant where a namespace-scoped grant could satisfy a narrowly defined policy;
- high-privilege grant to broad subjects such as `system:authenticated` or ServiceAccounts group;
- dangling binding or referenced role unavailable;
- aggregated ClusterRole expands into privileged permissions.

The analyzer needs native RBAC semantics, discovery-aware resources/subresources, namespace scoping, `resourceNames` limitations, non-resource URLs, role aggregation, and opaque external subjects. It can calculate effective native RBAC grants, not actual identity-provider group membership or non-RBAC authorization.

### K03 — Secrets Management Failures

Safe default candidates using metadata and references only:

- long-lived legacy service-account-token Secret metadata where reliably identifiable;
- workload references a Secret broadly or injects all keys via `envFrom` (a contextual exposure indicator, not proof of leakage);
- Secret is referenced by workloads with a potentially exposed or highly privileged path;
- high-privilege ServiceAccount plus Secret access correlation;
- Secret metadata appears orphaned only when reference coverage is sufficient and the rule is carefully scoped.

KubeHunt cannot determine weak Secret contents, plaintext credentials, rotation age from creation time alone, encryption at rest, external-store policy, or whether an application logs a secret. Creation timestamp is not a reliable rotation timestamp. Rules must not infer these facts.

### K04 — Lack Of Cluster Level Policy Enforcement

With only the required resource list, useful evidence is limited:

- Namespace Pod Security Admission labels are absent, inconsistent, or below a configured baseline;
- supported workload configurations violate the selected Pod Security profile, showing posture drift but not necessarily absence of enforcement.

Namespace labels alone do not reveal all admission behavior. Full category work needs collectors for ValidatingAdmissionPolicies, bindings, admission webhook configurations, and known policy-engine CRDs, plus semantics for enforce/warn/audit and exclusions. Until then K04 category coverage is partial or not assessed.

### K05 — Missing Network Segmentation Controls

Potential deterministic rules:

- namespace with eligible Pods but no native NetworkPolicy;
- Pod is not selected by any ingress and/or egress isolating policy;
- policy admits traffic from overly broad pod/namespace/IP selectors under a declared policy profile;
- unrestricted egress or ingress rule;
- host-networked workload bypasses normal Pod network isolation assumptions;
- sensitive/exposed workload lacks intended segmentation;
- graph reachability between trust zones based on native policy intent.

NetworkPolicy evaluation must model additive policy semantics, ingress and egress independently, empty selectors, namespace selectors, pod selectors, `ipBlock` exceptions, ports/protocols, and namespace boundaries. It must say “native policy intent” unless the CNI and enforcement are independently verified.

### K06 — Overly Exposed Kubernetes Components

Configuration-indicator candidates:

- Service type LoadBalancer or NodePort routes to a sensitive workload;
- Ingress routes to a workload with privileged ServiceAccount or sensitive Secret references;
- external IPs or permissive source ranges are configured;
- service/ingress exposure plus absent native network segmentation;
- potentially exposed dashboard, control-plane-like, or administrative service based on an explicit reviewed signature catalog.

Names and ports are weak signals; signature-based administrative component findings need clear evidence and confidence. The scanner must say “potentially exposed” unless it observes cloud/network reachability. The Kubernetes API endpoint in kubeconfig being reachable by the scanner does not prove public exposure.

## 4. K07-K10 representation

### K07 — Misconfigured And Vulnerable Cluster Components

The server version, if discoverable, may support an informational age/support signal, but a server version alone does not inventory all components or prove vulnerability. No CVE claim should be emitted without a version-aware, maintained vulnerability source and component identity. Default category state: `not_assessed`; `partial` only when a concrete component capability is added.

### K08 — Cluster To Cloud Lateral Movement

Pod specs may expose hints such as host networking, ServiceAccount annotations, or environment variables, but provider-specific annotations are not sufficient to resolve effective cloud identity or IAM permissions. A meaningful assessment needs provider adapters, metadata-service reachability semantics, workload-identity bindings, and cloud APIs. Default: `not_assessed`; a hint rule may produce `partial` only with an explicit provider profile and low/medium confidence.

### K09 — Broken Authentication Mechanisms

Kubeconfig describes the scanner's client authentication, not the cluster's complete authentication posture. Native RBAC assesses authorization, not authentication. API server flags, OIDC/webhook configuration, credential issuance/rotation, anonymous auth, and IdP policy are outside current evidence. Default: `not_assessed`.

### K10 — Inadequate Logging And Monitoring

Resource inventory does not prove audit logging, collection, retention, alerting, or operational response. Absence of a visible logging DaemonSet is not proof of absent logging because managed and external systems may be used. Default: `not_assessed`.

## 5. Capability profiles

Each category catalog entry should list granular capabilities. Example IDs:

```text
kubernetes.discovery.read
kubernetes.version.read
kubernetes.core.pods.list
kubernetes.apps.workload_templates.list
kubernetes.core.namespaces.list
kubernetes.core.serviceaccounts.list
kubernetes.rbac.roles.list
kubernetes.rbac.clusterroles.list
kubernetes.rbac.rolebindings.list
kubernetes.rbac.clusterrolebindings.list
kubernetes.networking.networkpolicies.list
kubernetes.networking.services.list
kubernetes.networking.ingresses.list
kubernetes.secrets.metadata.list
kubernetes.admission.pod_security_labels.observe
cloud.network_reachability.observe
cloud.iam.effective_permissions.observe
cluster.components.configuration.observe
cluster.audit.configuration.observe
runtime.network_flows.observe
```

A category profile is an OR/AND expression over capabilities, not simply a list of resource types. Example:

```yaml
taxonomy: owasp-kubernetes-top-10:2025
category: K05
profiles:
  native-intent:
    required:
      allOf:
        - kubernetes.core.pods.list
        - kubernetes.networking.networkpolicies.list
        - kubernetes.core.namespaces.list
    knownGaps:
      - runtime.network_flows.observe
      - cni.policy_enforcement.observe
```

If Pods are available but NetworkPolicies are forbidden, native-intent coverage is `partial` or `not_assessed` per individual rule requirements; it is never a pass. If all three are available, KubeHunt may claim the bounded `native-intent` profile was assessed while the broad OWASP K05 category remains `partial` due to its declared gaps.

## 6. Finding-to-category examples

| Finding | Primary | Related | Why |
|---|---|---|---|
| Privileged container | K01 | K07 (only if component context exists) | Direct workload hardening failure; do not add K07 merely because breakout is possible |
| ServiceAccount bound to wildcard ClusterRole | K02 | K03 when Secret access is included | Authorization is the defect; Secret exposure is a direct related consequence |
| Workload injects every key from a Secret | K03 | K01 | Broad Secret consumption is primary; workload configuration is related |
| Namespace lacks a configured Pod Security baseline | K04 | K01 | Missing policy control is primary; resulting workload posture is related |
| Pod not selected by ingress isolation policy | K05 | none by default | Direct native segmentation gap |
| LoadBalancer routes to privileged workload | K06 | K01/K02 as separate evidence supports | Exposure is primary; do not manufacture related mappings without actual workload/RBAC findings |

Avoid category fan-out. An attack chain may reference findings from several categories, but that does not mean every underlying finding maps to every category in the chain.

## 7. Governance and validation

- Pin the OWASP 2025 category list and source URL in a catalog file; changes require review.
- Store rule mappings beside rule metadata and generate mapping documentation from the catalog once implementation begins.
- CI validation must reject missing/unknown category IDs, absent primary mappings, empty rationales, duplicate rule IDs, and references to a different taxonomy edition.
- Mapping changes that alter machine output require release notes and, where fingerprints include mapping metadata, an explicit fingerprint-version decision.
- Review rules against OWASP source material and Kubernetes primary documentation. OWASP prose informs the rationale; Kubernetes behavior defines the predicate.
- Publish coverage changes as prominently as new findings. Adding a collector can turn prior `not_assessed` areas into failures without any cluster configuration change.

## 8. Explicit claims KubeHunt must avoid

- “OWASP compliant” or “OWASP certified.”
- “No K0x risk” when only a bounded profile was assessed.
- “Internet exposed” based only on Service/Ingress configuration.
- “NetworkPolicy enforced” based only on an object being present.
- “Secret is stale” based only on creation time.
- “User has permission” when a group binding exists but membership is unknown; say the bound subject is granted permission.
- “Cluster is vulnerable to CVE-X” from the API server version alone.
- “Attack path is exploitable” without validating every prerequisite; report it as a modeled path with assumptions.
