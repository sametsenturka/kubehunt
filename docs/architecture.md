# KubeHunt architecture

Status: proposed
Companion documents: [requirements.md](requirements.md), [owasp-mapping.md](owasp-mapping.md)

## 1. Architecture principles

1. **Evidence before conclusions.** Collect immutable facts, normalize them, then evaluate deterministic rules.
2. **Coverage is first-class.** Missing permissions or evidence produce explicit coverage records, never implicit passes.
3. **Read-only is enforced twice.** Recommend least-privilege RBAC and wrap the client transport/API surface with a scanner-side verb policy.
4. **Secret values do not enter memory by default.** Metadata-only content negotiation has no full-object fallback.
5. **Pure core, impure edges.** Kubernetes I/O and rendering live at the edges; rule, graph, and scoring logic operate on domain values.
6. **Version everything that changes meaning.** Rules, taxonomy, JSON schema, normalization semantics, fingerprints, scoring, and suppressions have versions.
7. **No AI in adjudication.** Optional AI is a downstream presentation aid only.

## 2. Processing model

```text
CLI/config
   |
   v
preflight -> discovery/capabilities -> collectors -> normalization -> snapshot
                                                       |             |
                                                       v             v
                                                  resource graph   rules
                                                       |             |
                                                       +--> correlations
                                                                 |
                                                                 v
                                                   findings + coverage
                                                                 |
                                                        risk enrichment
                                                                 |
                                           terminal / JSON / SARIF / AI explainer
```

The orchestrator owns phase order and cancellation. Stages communicate with immutable domain objects rather than Kubernetes client types. Reporters never query the cluster. The AI explainer, if installed later, receives only a redacted report view after all authoritative results and exit decisions have been computed.

## 3. Proposed repository and package layout

```text
cmd/kubehunt/                     executable entry point; dependency assembly only
internal/app/                     scan orchestration and use cases
internal/cli/                     commands, flags, config precedence, exit policy
internal/config/                  typed config, validation, digest, suppressions
internal/domain/                  resource, evidence, finding, coverage, score types
internal/kube/
  client/                         kubeconfig loading, transport guards, discovery
  collectors/                     one collector family per API/resource concern
  metadata/                       metadata-only Secret client
  normalize/                      client-go objects -> canonical domain resources
internal/rules/
  engine/                         scheduling, applicability, result validation
  builtin/k01/ ... builtin/k06/   built-in deterministic rules
  catalog/                        metadata, versioning, OWASP links, docs
internal/graph/
  model/                          typed directed multigraph
  build/                          fact/edge derivation from snapshot
  query/                          bounded traversal and indexes
  correlate/                      deterministic attack-path rules
internal/coverage/                capabilities, requirements, aggregation
internal/risk/                    severity and transparent contextual scoring
internal/report/
  terminal/                       human rendering
  json/                           versioned machine schema
  sarif/                          SARIF 2.1.0 adapter
internal/redact/                  field policy, name hashing, safe diagnostics
internal/explain/                 future optional explainer boundary
pkg/api/v1/                       public report/config schema only if stability needed
rules/                            built-in rule documentation/test fixtures
docs/                             architecture, requirements, mappings, security
testdata/                         sanitized manifests and golden outputs
```

`internal/domain` imports no Kubernetes or output packages. Collectors do not import rules, graph, risk, or reporters. Rules may depend on domain query interfaces, never collectors. Graph correlation consumes the graph/query API and emits ordinary findings. Risk consumes findings plus context; reporters consume the final report. This dependency direction prevents API mechanics, output formatting, or future AI code from influencing vulnerability decisions.

Avoid a public Go plugin ABI initially: Go's native plugin mechanism is platform-sensitive and arbitrary rule code undermines the security model. New compiled rules should be normal source packages. A future declarative rule format needs its own schema, sandbox, limits, signing story, and deterministic semantics.

## 4. Domain model

Illustrative Go-shaped contracts follow; they define boundaries, not implementation.

```go
type ResourceRef struct {
    ClusterID, Group, Version, Kind string
    Namespace, Name, UID           string
}

type Resource struct {
    Ref            ResourceRef
    ResourceVersion string
    Labels          map[string]string
    Annotations     map[string]string // subject to redaction policy
    OwnerRefs       []OwnerRef
    Spec            any               // canonical typed domain projection
    ObservedAt      time.Time
    Provenance      EvidenceSource
}

type Snapshot struct {
    Metadata       ScanMetadata
    Resources      ResourceStore
    CollectionRuns []CollectionResult
    Capabilities   CapabilitySet
}
```

Canonical projections store only fields needed by rules/edges. They must preserve three states where Kubernetes semantics require it: absent, explicitly false/zero, and a concrete value. Normalization resolves documented server defaults only when the default is known for the observed version; otherwise it retains `unknown`.

```go
type Evidence struct {
    Resource ResourceRef
    Field    string       // canonical JSONPath-like domain path
    Value    SafeValue    // already classified/redacted
    Source   EvidenceSource
}

type Finding struct {
    ID, RuleID, RuleVersion, Fingerprint string
    Title, Description                   string
    Subject                              ResourceRef
    Related                              []ResourceRef
    Outcome                              Outcome // fail for emitted findings
    Severity                             Severity
    Confidence                           Confidence
    Evidence                             []Evidence
    Mappings                             []TaxonomyMapping
    Remediation, References              []string
    ContextScore                         *RiskScore
}

type RuleEvaluation struct {
    RuleID, RuleVersion string
    Subject             *ResourceRef
    Outcome             Outcome // pass/fail/not_applicable/not_assessed/error
    Findings            []Finding
    ReasonCode          string
    Diagnostics         []Diagnostic
}
```

Finding fingerprints should hash: fingerprint-scheme version, cluster identity policy, rule ID and major rule version, canonical subject identity, stable discriminator, and relevant evidence identity. Do not hash timestamps, display messages, scores, Secret values, or map iteration order. UIDs are useful within one cluster lifetime but names may be preferable for baseline continuity; preserve both and document the selected scheme.

### 4.1 Capability and coverage model

```go
type CapabilityID string // e.g. kubernetes.rbac.clusterroles.list

type Capability struct {
    ID        CapabilityID
    State     CapabilityState // available/unavailable/unknown/error
    Reason    ReasonCode      // forbidden/api_absent/timeout/disabled/unsupported...
    Evidence  []EvidenceSource
}

type CoverageRequirement struct {
    AnyOf [][]CapabilityID // OR of AND-groups
}

type Coverage struct {
    TargetType string // rule/category/scan
    TargetID   string
    Status     CoverageStatus // assessed/partial/not_assessed/error/not_applicable
    Required, Available, Missing []CapabilityID
    Reasons    []ReasonCode
}
```

Capabilities are inferred from actual discovery/collection outcomes, not from active permission probes that might create objects or broaden access. A successful empty list is available; a forbidden list is unavailable. API absence is distinct from authorization denial. Rule metadata declares capability requirements. Category coverage aggregates applicable rule coverage plus known out-of-band evidence gaps defined in the OWASP catalog.

The system must not calculate category coverage as a misleading percentage unless the catalog has explicit, reviewed weights. Prefer status plus a list of assessed and missing capabilities.

### 4.2 Taxonomy model

```go
type TaxonomyRef struct { ID, Version, Name, URL string }
type TaxonomyMapping struct {
    TaxonomyID, CategoryID string
    Type MappingType // primary/related
    Rationale string
}
```

Taxonomy catalog data is immutable for a release and validated at build/test time: category IDs exist, every built-in rule has a primary mapping, rationales are non-empty, and URLs use the selected taxonomy edition.

## 5. Interfaces

```go
type Collector interface {
    ID() string
    Requirements() []APIRequirement
    Collect(context.Context, ClusterReader, Scope) CollectionResult
}

type ClusterReader interface {
    Discover(context.Context) DiscoverySnapshot
    List(context.Context, ListRequest) Page[RawObject]
    ListMetadata(context.Context, MetadataListRequest) Page[ObjectMetadata]
}

type Normalizer interface {
    Normalize(RawObject, ServerContext) (Resource, error)
}

type Rule interface {
    Metadata() RuleMetadata
    Evaluate(context.Context, EvaluationContext) []RuleEvaluation
}

type GraphBuilder interface {
    Build(context.Context, Snapshot) (Graph, []Diagnostic)
}

type Correlator interface {
    Metadata() CorrelationMetadata
    Evaluate(context.Context, GraphQuery, Snapshot) []RuleEvaluation
}

type Scorer interface {
    Version() string
    Score(Finding, RiskContext) RiskScore
}

type Reporter interface {
    Render(context.Context, Report, io.Writer) error
}

type Explainer interface {
    Explain(context.Context, RedactedFindingView) (NonAuthoritativeExplanation, error)
}
```

`ClusterReader` is deliberately narrower than `kubernetes.Interface`. The concrete adapter must reject non-GET HTTP methods and dangerous read-shaped subresources such as proxy, exec, attach, port-forward, and token requests. Tests should prove that collectors cannot reach a mutating client.

## 6. Kubernetes collection architecture

### 6.1 Preflight

1. Resolve configuration precedence: flags, environment, config file, safe defaults.
2. Load and validate kubeconfig without printing embedded data.
3. Detect exec/auth-provider credential configuration before client creation. Secure default: reject it unless explicitly allowed; when allowed, show the exact executable and use client-go's direct exec mechanism without invoking a shell.
4. Create a guarded transport with TLS verification on by default, request timeout, user agent, rate limit, and allowed verb/path policy.
5. Discover server version and API resources. Discovery failure degrades applicable coverage or stops when cluster identity cannot be established.

### 6.2 Collectors

Collectors are grouped by API (`core/v1`, `apps/v1`, `networking.k8s.io/v1`, `rbac.authorization.k8s.io/v1`) to reuse pagination and error classification, but each emits independent `CollectionResult` records. Namespaced collection honors scope. Cluster-scoped RBAC is collected only when relevant and permitted.

Each collection result contains status, pages, count, start/end time, returned resource version, warnings, and a sanitized error classification. Continue after a resource-level failure. Never interpret `Forbidden` as zero resources.

Secret metadata uses an `Accept` header for `PartialObjectMetadataList` and verifies the response kind/content type. If the API server cannot return metadata, the collector stops for Secrets; it does not deserialize full Secret objects. Even metadata collection requires `list secrets`, which is sensitive and may be denied by a well-designed scanner role.

### 6.3 Consistency and identity

Kubernetes cannot provide an atomic snapshot across resource kinds. Each list is internally associated with its own resource version and observation window. The graph marks dangling references and changes detected during pagination. `ClusterID` should be a locally derived, non-secret stable identifier (for example a hash of normalized server URL plus selected kubeconfig cluster name), not a claim of globally unique cluster identity.

Controller templates and Pods are distinct nodes. Template findings are preferred for Deployments, StatefulSets, and DaemonSets because remediation belongs in desired state. Direct/mirror Pods remain assessable. Child Pod findings may be suppressed as duplicates while retaining runtime divergence evidence.

## 7. Rule engine

### 7.1 Lifecycle

1. Validate the rule catalog and configuration.
2. Select enabled rules by ID/tags/category without changing their semantics.
3. Check server/API applicability and declared capabilities.
4. Obtain typed resources through indexed read-only queries.
5. Evaluate pure predicates with a deadline and cancellation.
6. Validate outcomes and evidence; a `fail` without evidence is an engine error.
7. Deduplicate using stable fingerprints.
8. Apply reviewed suppressions after evaluation, retaining suppressed results in machine reports when configured.
9. Sort by stable keys.

Rules may be resource rules (one subject), aggregate rules (namespace/cluster set), or correlation rules (graph path). Rule metadata must state which. Panic recovery converts a faulty rule to `error` coverage without masking other rules. Rule concurrency may improve performance, but output ordering cannot depend on scheduling.

### 7.2 Configuration and exceptions

Configuration is schema-validated. Suppressions require rule ID, constrained resource selector, justification, owner (recommended), and optional expiry. Expired suppressions do not apply and generate a diagnostic. Baselines compare fingerprints but must not silently convert new findings to pass.

Initial rules should be code-based. This preserves type safety and makes Kubernetes defaulting/test coverage reviewable. A generic expression language is premature until its determinism, resource limits, versioning, and security model are defined.

## 8. Attack graph

### 8.1 Model

The graph is a typed directed multigraph:

```go
type Node struct {
    ID NodeID
    Type NodeType // workload, pod, SA, role, subject, service, ingress, secret, namespace...
    Ref *ResourceRef
    Attributes map[string]SafeValue
}

type Edge struct {
    ID EdgeID
    From, To NodeID
    Type EdgeType
    Scope EdgeScope
    Confidence Confidence // confirmed/inferred/unknown
    Preconditions []PredicateRef
    Evidence []Evidence
}
```

It is a multigraph because the same nodes may be related through several bindings or selectors. Index nodes by type, resource reference, labels, and namespace. Index edges by direction and type. Stable IDs are hashes of canonical identities and derivation versions.

### 8.2 Edge derivation

- `OWNS`: controller to Pod via owner references.
- `RUNS_AS`: Pod/workload to effective ServiceAccount, including the default ServiceAccount.
- `BINDS`: RoleBinding/ClusterRoleBinding subject to Role/ClusterRole, preserving namespace semantics.
- `GRANTS`: effective role rule to resource/action capability; wildcard and subresource expansion is discovery-aware.
- `AGGREGATES`: ClusterRole label aggregation relationship.
- `SELECTS`: Service or NetworkPolicy to matching Pods/workload templates, with observed and potential matches distinguished.
- `ROUTES_TO`: Ingress to Service backend.
- `REFERENCES_SECRET`: workload/service account/ingress to Secret metadata when derivable without values.
- `MEMBER_OF_NAMESPACE`: namespaced resource to Namespace.
- `POTENTIALLY_EXPOSES`: Ingress/Service to backend, labeled as configuration inference rather than verified reachability.

Subjects representing external users/groups remain opaque; the graph cannot enumerate identity-provider membership. Non-RBAC authorizers are recorded as an authorization coverage gap.

### 8.3 Path correlation

Correlation rules define bounded path patterns with allowed edge types, direction, maximum depth, prerequisites, terminal asset types, and scoring factors. Traversal must have cycle detection, deterministic tie-breaking, query budgets, and maximum result counts. Equivalent paths should collapse to the most explanatory minimal path while retaining alternate evidence.

Example future hypothesis: potentially exposed Ingress -> selected workload -> mounted ServiceAccount -> RBAC grant to read Secrets. Every edge must exist in the scan evidence; the result must state assumptions such as external reachability and application compromise. It must not claim that the path was exploited or that credentials are usable.

## 9. Risk scoring

Risk uses two layers:

1. **Rule severity** is a reviewed categorical default tied to the configuration defect.
2. **Context score** prioritizes the finding without rewriting its severity.

A recommended transparent 0-100 model is:

```text
score = clamp(0, 100,
  base(severity)
  + exposure_factor
  + privilege_factor
  + blast_radius_factor
  + sensitive_asset_factor
  - mitigating_control_factor)
```

Suggested base anchors are info 0, low 20, medium 40, high 65, critical 85. Factor tables, caps, and missing-data behavior belong to a versioned scoring catalog. Unknown context contributes zero and lowers confidence; it must not be interpreted as a mitigating control. Display every applied factor. Attack-path length alone should not increase severity; edge confidence and terminal capability matter more.

Exit policy uses the rule severity by default for predictability. A future `--fail-on-score` would be a separate explicit feature. OWASP category numbers never enter the formula.

## 10. CLI design

```text
kubehunt scan cluster [flags]         collect selected cluster inventory
kubehunt rules list|show              inspect rule catalog and mappings
kubehunt coverage                     preflight visibility without claiming posture
kubehunt version                      version/build/schema information
kubehunt completion <shell>           shell completion
```

Representative `scan` flags:

```text
--kubeconfig <path>        explicit kubeconfig
--context <name>           kubeconfig context
--namespace <name>         repeatable; mutually exclusive with --all-namespaces
--all-namespaces           explicit cluster-wide namespace scope
--format terminal|json|sarif
--output <path|- >         stdout by default
--fail-on info|low|medium|high|critical|none
--incomplete-policy fail|warn|ignore
--rules <selector>         include rules/categories/tags
--exclude-rules <ids>      explicit exclusions, reported as coverage
--config <path>
--redact-names             stable name hashing
--allow-exec-credential    explicit kubeconfig plugin trust opt-in
--timeout <duration>
--qps <n> --burst <n>
```

Do not overload `scan` with remediation or active tests. `coverage` may perform the same discovery/list authorization attempts as a scan but reports only availability and does not evaluate findings. A future offline `scan manifest` mode should be a separate input adapter and must label which live-cluster semantics are unavailable.

Configuration precedence must be documented and printed as a sanitized digest. Diagnostics go to stderr; JSON/SARIF data goes to stdout or the output file. Broken pipes should be handled without corrupting saved output.

## 11. Report schema

The logical report contains:

- schema/scanner/ruleset/taxonomy/scoring/fingerprint versions;
- scan identity, sanitized target, scope, timestamps, and configuration digest;
- collection summary and diagnostics;
- per-rule and per-category coverage;
- findings and suppressed findings (policy-dependent);
- optional attack paths;
- summary counts and exit-policy decision.

The JSON schema should be published and follow compatibility rules: additive optional fields in a minor version, breaking changes only in a major version. Terminal output may evolve but cannot omit incomplete coverage warnings. SARIF maps rule metadata to `tool.driver.rules`, findings to `results`, stable fingerprints to `partialFingerprints`, severity to levels/properties, and coverage failures to invocation notifications/properties. Logical Kubernetes URIs must percent-encode components.

## 12. Testing strategy

### Unit tests

- Table-driven tests for every rule: vulnerable, secure, absent/defaulted, explicit zero/false, version boundary, init/ephemeral containers, and malformed input.
- Normalization/defaulting tests independent of API collection.
- RBAC wildcard, subresource, non-resource URL, aggregation, namespace, and binding semantics.
- Label selector and NetworkPolicy ingress/egress isolation semantics.
- Graph edge derivation, cycles, path bounds, deduplication, stable IDs, and deterministic ordering.
- Scoring factor/cap tests and coverage lattice tests.
- Redaction, fingerprint, config precedence, suppression expiry, and exit-code tests.

### Contract and integration tests

- Fake-client tests only for simple collector error paths; client-go fakes do not reproduce API authorization, defaulting, conversion, discovery, or content negotiation.
- `httptest` API server fixtures for pagination, timeouts, 403/404/429/5xx, malformed data, metadata `Accept` negotiation, and guard rejection of unsafe verbs/paths.
- Envtest or equivalent API-server tests for real discovery, versioned objects, selectors, and RBAC storage behavior where feasible.
- Disposable kind clusters across the declared Kubernetes support matrix for end-to-end collection and output.
- A restrictive scanner ServiceAccount test proving scans complete partially and label forbidden capabilities correctly.

### Golden, compatibility, and property tests

- Golden terminal, JSON, and SARIF reports with normalized timestamps/IDs.
- JSON Schema and SARIF validation in CI.
- Golden mapping/catalog validation and documentation parity.
- Fuzz untrusted names, labels, annotations, manifest fields, kubeconfig parsing boundaries, normalization, URI generation, and report escaping.
- Property tests for identical output under randomized resource/rule iteration order, no graph traversal beyond budgets, and no `data`/`stringData` Secret fields in default memory/report fixtures.
- Upgrade tests that compare fingerprints and explicitly approve intended churn.

### Security and performance tests

- Capture all HTTP requests and assert the default allowlist contains only approved discovery/get/list paths and methods.
- Canary Secret values must never occur in logs, diagnostics, findings, JSON, SARIF, heap/profile artifacts used by tests, or panic output.
- Kubeconfig exec credential rejection/opt-in tests; TLS verification and redirect policy tests.
- Terminal escape/control-character sanitization and spreadsheet-formula-safe exports if CSV is ever added.
- Benchmarks on large synthetic clusters; memory ceilings, rate limits, cancellation, traversal explosion, and reporter streaming.
- Race detector, static analysis, dependency/license review, vulnerability scanning, reproducible release provenance, and signed release artifacts.

## 13. Security model

### Assets and trust boundaries

Assets include kubeconfig credentials, API responses, object metadata, findings, cluster topology, local config/suppressions, and future AI prompts. Trust boundaries exist at kubeconfig loading, credential plugin execution, TLS/API transport, Kubernetes object parsing, rule code, local filesystem output, terminal rendering, CI logs, and future network egress.

### Controls

- Recommend a dedicated least-privilege ServiceAccount and short-lived credentials. Never claim client-side read-only guards replace RBAC.
- Reject insecure TLS by default and never log auth headers, certificates, tokens, raw kubeconfig, or raw API bodies.
- Inspect kubeconfig exec plugins before use; reject by default or require explicit opt-in and executable allowlisting. Do not invoke through a shell.
- Allow only necessary HTTP methods and safe API paths; disable redirects that could forward credentials to another origin.
- Apply response-size limits, pagination limits, timeouts, rate limits, graph budgets, and bounded concurrency.
- Treat all resource text as hostile: sanitize ANSI/control sequences, escape JSON/SARIF correctly, bound displayed lengths, and avoid rendering raw annotation bodies by default.
- Create output files with restrictive permissions where the OS permits; avoid caches by default. Document that reports contain sensitive cluster topology.
- Compile built-in rules into trusted releases. No arbitrary downloaded executable plugins.
- Make telemetry absent by default. Any future update check or analytics must be explicit and must not include cluster data.
- Future AI egress requires explicit enablement, preview, minimization, redaction, provider configuration, and a clear non-authoritative label.

### Read-only RBAC guidance

The eventual install documentation should provide an audited example role containing only `get`, `list` (and optionally `watch` only if a future mode truly needs it) on explicitly supported resources. Secret metadata remains awkward because Kubernetes RBAC cannot grant “metadata fields only”; `list secrets` also authorizes full Secret list responses to that identity. Therefore the strongest deployment separates Secret metadata permission as an optional role and reports K03 coverage limitations when absent.

## 14. Delivery sequence

1. Freeze domain/report schemas, capability semantics, and a small K01 rule catalog.
2. Build guarded collection and metadata-only Secret contract tests.
3. Add normalization and inventory for the listed native resources.
4. Add K01-K06 resource rules and coverage reporting before graph correlations.
5. Add graph facts with query tests; initially expose graph diagnostics, not attack-path claims.
6. Add transparent contextual scoring and all three reporters.
7. Add bounded, evidence-backed attack-path correlations.
8. Consider an optional AI explainer only after redaction and data-egress threat modeling are complete.

## 15. Milestone 1 implementation status

Milestone 1 implements the CLI, Kubernetes client, collectors, normalized `ClusterState`, and terminal inventory reporter layers. The implemented commands are:

```text
kubehunt scan cluster
kubehunt version
```

Cobra is used only for command/flag parsing, nested help, argument validation, and testable command execution. Kubernetes access uses `client-go` typed interfaces. Collectors accept `kubernetes.Interface`, which allows client-go fake clients in unit tests without coupling normalized domain types to Kubernetes API objects.

The initial dependency baseline is Go 1.25, Cobra 1.10, and the Kubernetes 1.35 client libraries (`client-go`, `api`, and `apimachinery` 0.35). Kubernetes dependencies are kept at the same minor/patch version. This is the newest maintained client-go line supported by the project toolchain at Milestone 1; the declared cluster compatibility matrix still needs dedicated integration testing before the first release.

The current collector supports the milestone resource list, pagination, bounded concurrency, namespace filtering, deterministic resource ordering, and per-resource observation metadata. It deliberately does not collect Secrets because Milestone 1 excludes them. Secret metadata collection remains a later, separately tested capability using metadata-only content negotiation.

Until the capability/coverage system is implemented, any failed resource collection makes `scan cluster` return a contextual error instead of printing a potentially misleading complete inventory. Successfully collected partial state remains available at the application boundary for the later coverage model, but the CLI does not present it as a completed scan.

The Kubernetes transport rejects non-GET/HEAD methods and dangerous read-shaped subresources. Kubeconfig exec and legacy auth-provider credentials are rejected by default because loading them can execute trusted local credential code; users of managed-cluster kubeconfigs must opt in with `--allow-exec-credential`.
