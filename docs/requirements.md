# KubeHunt requirements

Status: architecture baseline; Milestone 1 implementation is in progress
Scope: full product requirements, delivered incrementally by documented milestones

## 1. Product definition

KubeHunt is an open-source, deterministic, CLI-based Kubernetes security posture scanner written in Go. It inspects the Kubernetes API using a kubeconfig, builds a normalized inventory and relationship graph, evaluates versioned rules, and reports findings mapped to the OWASP Kubernetes Top 10:2025.

KubeHunt is a posture assessment tool, not a penetration-testing tool, policy enforcer, admission controller, vulnerability scanner, runtime detector, or proof that a cluster is secure. Its reports must state what was observed, what could not be observed, and when the observation occurred.

## 2. Goals

- Produce reproducible findings from Kubernetes API evidence without an LLM in the decision path.
- Keep cluster access read-only and least-privileged by default.
- Assess Kubernetes-native resources, initially emphasizing OWASP K01-K06.
- Represent K07-K10 honestly as partial or not assessed when API visibility is insufficient.
- Preserve evidence and coverage information so findings are explainable and auditable.
- Support local use and CI through terminal, JSON, and SARIF reports and severity-based exit policy.
- Establish a resource graph that can later support deterministic attack-path correlation.
- Permit a future, optional AI explanation layer that cannot create, suppress, reprioritize, or alter findings.

## 3. Non-goals for the initial release

- Mutating, remediating, exploiting, or probing workloads or cluster endpoints.
- Reading Secret values by default.
- Container image package/CVE or software-bill-of-materials analysis.
- Node, container runtime, kubelet, etcd, control-plane flag, host filesystem, or cloud IAM inspection.
- Runtime behavior, traffic-flow, audit-log, or monitoring-system analysis.
- Proving that an Ingress, LoadBalancer, API server, or component is Internet reachable.
- Evaluating arbitrary CRDs or vendor-specific policy objects.
- Replacing admission policy, cloud security posture management, or human threat modeling.

## 4. Functional requirements

Requirements use RFC 2119 terms MUST, SHOULD, and MAY.

### 4.1 Connectivity and scope

- The CLI MUST use `client-go` and standard kubeconfig loading semantics.
- It MUST accept an explicit kubeconfig path and context. Ambient defaults MAY be supported, but the selected path, context, cluster server hostname, and namespace scope MUST be shown before or in the report without leaking credentials.
- It MUST support all namespaces, one namespace, and an explicit namespace set.
- API operations in the default scan path MUST be limited to discovery, `get`, and `list`. No create, update, patch, delete, exec, attach, port-forward, proxy, token creation, SubjectAccessReview, or SelfSubjectRulesReview call may be silently introduced.
- Collection MUST use bounded concurrency, request timeouts, pagination where supported, client-side rate limits, and cancellation.
- A scan MUST record its start/end time, Kubernetes server version when visible, requested scope, discovered API groups, per-resource collection result, and resource versions where returned.
- Authorization failures, absent APIs, timeouts, and unsupported metadata negotiation MUST be coverage results, not silently treated as an empty or secure cluster.

### 4.2 Resource inventory

The initial native collectors MUST support:

- Pods
- Deployments
- StatefulSets
- DaemonSets
- Services
- Ingresses
- Namespaces
- ServiceAccounts
- Roles and ClusterRoles
- RoleBindings and ClusterRoleBindings
- NetworkPolicies
- Secret metadata

The inventory SHOULD also record Kubernetes API discovery and server version because rule applicability depends on API and version. Additional native resources such as Nodes, Jobs, CronJobs, LimitRanges, ResourceQuotas, PodDisruptionBudgets, EndpointSlices, ValidatingAdmissionPolicies, and admission webhooks are explicitly future scope; their absence limits OWASP coverage.

Milestone 1 implements every resource above except Secret metadata, which is explicitly deferred because that milestone's requested inventory excludes Secrets. The default metadata-only Secret contract remains mandatory when Secret collection is introduced.

### 4.3 Secret handling

- Default Secret collection MUST request `PartialObjectMetadataList` through Kubernetes metadata content negotiation so Secret values never enter process memory.
- The scanner MUST NOT silently fall back to a normal Secret `list` or `get`, because a normal Secret response includes the `data` field.
- If metadata-only collection is unsupported, Secret coverage MUST be `not_assessed` or `error` with a reason.
- A separately named, explicit opt-in MAY allow Secret object collection. It MUST display a warning, keep values out of findings/logs/cache/reports, and zero or release value-bearing buffers as practical. This opt-in is not required for the initial release.
- Secret names, labels, annotations, and types can themselves be sensitive. Reports MUST support redaction or stable hashing of object names.

### 4.4 Analysis

- Every rule MUST have a stable ID, version, title, description, default severity, applicable resource kinds/API versions, deterministic predicate, evidence schema, remediation text, references, and one or more OWASP mappings.
- The same normalized input, rule set/version, configuration, and scanner version MUST produce semantically identical findings. Timestamps and ordering are excluded from semantic identity.
- Rule results MUST distinguish `pass`, `fail`, `not_applicable`, `not_assessed`, and `error`.
- Missing fields MUST be interpreted according to Kubernetes defaulting semantics for the applicable server/API version, not automatically as insecure or secure.
- Rules SHOULD evaluate desired-state workload templates separately from observed Pods. Deduplication MUST prevent a controller template and its child Pods from inflating the same issue without explanation.
- Policy exceptions MUST be explicit, scoped, expiring where possible, and reported. Configuration can tune thresholds or applicability, but MUST NOT make predicates nondeterministic.
- Analyzer failures MUST not abort unrelated rules unless input integrity is compromised.

### 4.5 OWASP mapping and coverage

- The taxonomy identifier MUST be versioned as `owasp-kubernetes-top-10:2025`.
- Findings MUST map to one or more category IDs, with mapping type `primary` or `related` and a rationale.
- K01-K06 are the initial focus, but category coverage MUST be computed from completed capabilities and rules rather than asserted from category name alone.
- K07-K10 MUST exist in every coverage report. They MUST be `partial` or `not_assessed` unless required evidence sources are present and implemented.
- Reports MUST separate category risk (findings) from category coverage (visibility). “No findings” MUST not mean “assessed” when relevant capabilities were unavailable.
- Taxonomy text and mappings MUST be data-driven and versioned so future OWASP editions do not require rewriting the engine.

### 4.6 Graph and correlation

- The scanner MUST build a typed directed multigraph from normalized resources and derived relationships.
- Nodes and edges MUST retain provenance, confidence, scope, and source evidence.
- Initial edges SHOULD cover ownership, workload-to-service-account use, RBAC binding, role aggregation, workload selection by Service/NetworkPolicy, Ingress routing, Secret reference, namespace membership, and relevant exposure relationships.
- Graph construction MUST distinguish a missing relation from a relation that could not be evaluated.
- Attack-path findings MUST eventually be emitted only by versioned deterministic correlation rules. A path is a plausible route under modeled assumptions, not proof of exploitability.
- Cycles, Kubernetes RBAC wildcard semantics, non-resource URLs, subresources, namespace scope, default service accounts, and selector semantics MUST be handled explicitly.

### 4.7 Risk and reporting

- Severity levels MUST have an explicit stable ordering; recommended levels are `info`, `low`, `medium`, `high`, and `critical`.
- Base rule severity, contextual risk score, confidence, and coverage MUST remain separate fields. OWASP category rank MUST NOT be treated as severity.
- Any contextual score MUST expose its formula, factor values, caps, and scoring-model version.
- Terminal output MUST be human-oriented; JSON MUST use a versioned schema; SARIF MUST target SARIF 2.1.0.
- Findings MUST have stable fingerprints that exclude volatile fields and sensitive values.
- Kubernetes objects in SARIF SHOULD use logical `k8s://` artifact locations and properties containing kind, namespace, name/hash, UID when allowed, and evidence fields. The report MUST not pretend a live resource is a source file.
- `--fail-on <severity>` MUST control exit policy independently from scan execution. A recommended exit contract is: `0` completed below threshold, `1` threshold met, `2` usage/configuration error, `3` incomplete scan or internal failure. CI behavior for incomplete coverage MUST be separately configurable and fail closed by default.
- Report ordering MUST be deterministic.

### 4.8 Optional AI boundary

- AI integration MUST be disabled by default and implemented behind a separate explainer interface after deterministic analysis.
- The AI layer MAY explain existing findings, suggest remediation, or narrate an already-computed path.
- It MUST NOT decide pass/fail, change evidence, severity, score, coverage, suppressions, exit status, or OWASP mapping.
- Data sent to an AI provider MUST be explicitly previewable and minimized; credentials, Secret values, tokens, kubeconfig data, and unredacted sensitive metadata MUST never be included.
- AI output MUST be labeled non-authoritative and must cite finding/rule IDs it explains.

## 5. Quality attributes

- **Safety:** passive read-only API access, no endpoint probing, strict output redaction.
- **Correctness:** version-aware defaulting, deterministic ordering, golden schemas, fixture-based Kubernetes behavior tests.
- **Resilience:** partial results with explicit coverage; cancellation and bounded resource usage.
- **Performance:** stream or paginate large inventories where possible; avoid an unbounded complete cluster object cache.
- **Compatibility:** publish a Kubernetes support matrix and test at the oldest and newest supported minor versions.
- **Extensibility:** stable domain interfaces, versioned rule/catalog formats, no reporter dependency in collectors or analyzers.
- **Observability:** structured diagnostics to stderr, never mixed into JSON/SARIF stdout.
- **Reproducibility:** include scanner, ruleset, taxonomy, configuration digest, and scoring-model versions.

## 6. Acceptance criteria for the architecture phase

- Package boundaries and dependency direction are documented.
- Domain models cover inventory, evidence, findings, mappings, coverage, graph facts, scoring, and reports.
- Collector, normalizer, rule, graph, scoring, reporting, and optional explanation interfaces are specified.
- CLI command and exit-code contracts are specified.
- Each OWASP 2025 category has a declared visibility and limitation model.
- The test strategy covers unit, contract, integration, end-to-end, security, compatibility, performance, and golden-output tests.
- Threat boundaries include kubeconfig credential plugins, API transport, malicious resource text, Secret handling, reports, plugins/rules, and future AI egress.

## 7. Architectural corrections and unresolved assumptions

These are constraints the product should acknowledge rather than hide:

1. **“Read-only client” is not a Kubernetes permission.** The credentials determine authorization. KubeHunt can restrict its own verbs, but it cannot make an overprivileged kubeconfig read-only. A documented least-privilege RBAC example and a client-side verb guard are both needed.
2. **Secret metadata is not available safely through an ordinary typed Secret list.** Normal responses contain values. Metadata content negotiation is mandatory for the default promise.
3. **K01-K06 cannot all be fully assessed from the listed objects.** For example, K04 requires visibility into enforcement/admission configuration; K06 Internet reachability depends on cloud networking and control-plane configuration. These categories will start partial.
4. **K07-K10 are broader than declarative Kubernetes objects.** Node/component configuration, cloud identity, authentication systems, audit pipelines, and runtime signals require separate collectors and trust boundaries.
5. **RBAC objects do not reveal all authorization.** External identity, webhook/ABAC modes, IAM mappings, impersonation, admission, and time-bound access may be invisible. A binding to a group does not enumerate its members.
6. **NetworkPolicy presence does not prove enforcement.** It depends on the CNI, and vendor-specific policies are not in the initial resource list. Selector analysis can assess intent, not observed packet filtering.
7. **Service/Ingress type does not prove Internet exposure.** Provider annotations, external load balancers, DNS, firewall rules, tunnels, and proxies can change reachability. Use terms such as “potentially externally exposed.”
8. **An API scan is not an atomic snapshot.** Per-kind list calls occur at different times. Reports must expose timestamps/resource versions and correlation must tolerate object churn.
9. **Attack paths are model-dependent hypotheses.** They combine capability and reachability assumptions and should carry confidence and missing prerequisites, not be marketed as exploit proof.
10. **A universal numeric risk score is not objective truth.** Default severity should be stable and contextual factors transparent. Consumers need raw factors, not only a number.
11. **Kubeconfig loading can execute credential plugins.** This is local code execution under the user account. The CLI should inspect and reject exec/auth-provider configurations by default or require an explicit trust opt-in/allowlist; this creates a usability tradeoff for managed clusters that must be documented.
12. **The workload list is incomplete.** Jobs and CronJobs can create Pods, and static/mirror Pods have no controller template. Initial reports must state this gap.
13. **Names and annotations can be secrets.** Avoiding Secret values is insufficient; inventory and report redaction are still required.
14. **OWASP is a risk taxonomy, not a complete test specification.** KubeHunt owns and versions each rule-to-category rationale; it must not imply OWASP certification or endorsement.

## 8. Source baseline

- [OWASP Kubernetes Top Ten 2025](https://owasp.org/www-project-kubernetes-top-ten/)
- [Kubernetes API concepts: metadata-only fetching](https://kubernetes.io/docs/reference/using-api/api-concepts/#metadata-only-fetches)
- [Kubernetes RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
